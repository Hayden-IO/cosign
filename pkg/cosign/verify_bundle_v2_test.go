// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/internal/test"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	sumdbNote "golang.org/x/mod/sumdb/note"
)

func mustVal[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type testPQCTrustedMaterial struct {
	root.TrustedMaterial
	extraRekor map[string]*root.TransparencyLog
}

func (m *testPQCTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	out := make(map[string]*root.TransparencyLog, len(m.extraRekor))
	if m.TrustedMaterial != nil {
		maps.Copy(out, m.TrustedMaterial.RekorLogs())
	}
	maps.Copy(out, m.extraRekor)
	return out
}

type testV2BundleOpts struct {
	artifact, dssePayload []byte
	identity, issuer      string
	signerKey             *mldsa.PrivateKey
	logKey                crypto.Signer
}

func buildTestBundleV2(t *testing.T, opts testV2BundleOpts) (*sgbundle.BundleV2, *root.TransparencyLog) {
	t.Helper()
	const origin = "rekor-v3.example.test"
	logSigner := opts.logKey
	if logSigner == nil {
		logSigner = mustVal(mldsa.GenerateKey(mldsa.MLDSA44()))
	}
	var artifactDigest [32]byte
	var payloadPB *bundleV2.Payload
	if len(opts.dssePayload) > 0 {
		const pt = "application/vnd.in-toto+json"
		artifactDigest = sha256.Sum256(dsse.PAE(pt, opts.dssePayload))
		payloadPB = &bundleV2.Payload{PayloadType: pt, Payload: opts.dssePayload}
	} else {
		artifactDigest = sha256.Sum256(opts.artifact)
	}
	msgHash := sha256.Sum256(artifactDigest[:])
	dbl := func(b []byte) [32]byte { h := sha256.Sum256(b); return sha256.Sum256(h[:]) }

	var rotHash, receiptDigest [32]byte
	var contextHashes, extraData []byte
	var sigPB *bundleV2.Signature
	if opts.signerKey != nil {
		pubDER := mustVal(x509.MarshalPKIXPublicKey(opts.signerKey.Public()))
		sig := mustVal(opts.signerKey.Sign(rand.Reader, append([]byte("c2sp.org/identity-transparency/v1\x00"), msgHash[:]...), crypto.Hash(0)))
		rotHash, receiptDigest = sha256.Sum256(append([]byte("ML-DSA-44"), pubDER...)), sha256.Sum256(sig)
		sigPB = &bundleV2.Signature{Signature: sig}
	} else {
		extraData = []byte("identity:" + opts.identity + "\nissuer:" + opts.issuer)
		rotHash = sha256.Sum256([]byte(opts.issuer))
		ik2, iv2 := dbl([]byte("identity")), dbl([]byte(opts.identity))
		issk2, issv2 := dbl([]byte("issuer")), dbl([]byte(opts.issuer))
		if bytes.Compare(ik2[:], issk2[:]) < 0 {
			contextHashes = slices.Concat(ik2[:], iv2[:], issk2[:], issv2[:])
		} else {
			contextHashes = slices.Concat(issk2[:], issv2[:], ik2[:], iv2[:])
		}
	}
	leaf := slices.Concat([]byte{0x01}, rotHash[:], msgHash[:], contextHashes, receiptDigest[:])
	cp := formatsLog.Checkpoint{Origin: origin, Size: 1, Hash: rfc6962.DefaultHasher.HashLeaf(leaf)}
	ns := mustVal(note.NewNoteSigner(context.Background(), origin, mustVal(signature.LoadDefaultSigner(logSigner))))
	signedNote := mustVal(sumdbNote.Sign(&sumdbNote.Note{Text: string(cp.Marshal())}, ns))
	b2 := mustVal(sgbundle.NewBundleV2(&bundleV2.Bundle{
		MediaType: cbundle.BundleV20MediaType, Payload: payloadPB,
		VerificationMaterial: &bundleV2.VerificationMaterial{Content: &bundleV2.VerificationMaterial_TransparencyLogProof{
			TransparencyLogProof: &bundleV2.TransparencyLogProof{Proof: (&proof.TLogProof{Checkpoint: signedNote, ExtraData: extraData}).Marshal(), Signature: sigPB},
		}},
	}))
	logID := sha256.Sum256(mustVal(x509.MarshalPKIXPublicKey(logSigner.Public())))
	return b2, &root.TransparencyLog{BaseURL: "https://" + origin, ID: logID[:], PublicKey: logSigner.Public(), ValidityPeriodStart: time.Now().Add(-time.Hour), ValidityPeriodEnd: time.Now().Add(time.Hour)}
}

func TestVerifyV1AndV2IsolationMatrix(t *testing.T) {
	artifact := []byte("pqc-artifact-payload")
	digest := sha256.Sum256(artifact)
	stmt := fmt.Appendf(nil, `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"img","digest":{"sha256":"%s"}}],"predicateType":"https://example.com/pqc","predicate":{}}`, hex.EncodeToString(digest[:]))
	const subject, issuer = "alice@example.com", "https://accounts.example.com"
	ids := []Identity{{Issuer: issuer, Subject: subject}}

	vs := mustVal(ca.NewVirtualSigstore())
	v1Blob := mustVal(vs.Sign(subject, issuer, artifact))
	rootCert, rootKey, err := test.GenerateRootCa()
	require.NoError(t, err)
	ecdsaLeaf, ecdsaLeafKey, err := test.GenerateLeafCert(subject, issuer, rootCert, rootKey)
	require.NoError(t, err)
	mldsa44Key := mustVal(mldsa.GenerateKey(mldsa.MLDSA44()))
	mldsa44V := mustVal(signature.LoadDefaultVerifier(mldsa44Key.Public()))
	mldsa65V := mustVal(signature.LoadDefaultVerifier(mustVal(mldsa.GenerateKey(mldsa.MLDSA65())).Public()))
	ecdsaKey := mustVal(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	ecdsaV := mustVal(signature.LoadECDSAVerifier(&ecdsaKey.PublicKey, crypto.SHA256))
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mkCert := func(pub crypto.PublicKey, parent *x509.Certificate, pKey crypto.Signer) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: parent == nil, BasicConstraintsValid: true}
		if parent == nil {
			parent = tmpl
		}
		return mustVal(x509.ParseCertificate(mustVal(x509.CreateCertificate(rand.Reader, tmpl, parent, pub, pKey))))
	}
	mldsaCert := mkCert(mldsa44Key.Public(), rootCert, rootKey)
	ecdsaByMLDSA := mkCert(&ecdsaLeafKey.PublicKey, mkCert(mldsa44Key.Public(), nil, mldsa44Key), mldsa44Key)
	msgSig := &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
		MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: digest[:]}, Signature: []byte("sig"),
	}}
	mkV1Cert := func(c *x509.Certificate) *sgbundle.Bundle {
		return mustVal(sgbundle.NewBundle(&protobundle.Bundle{MediaType: cbundle.BundleV03MediaType, Content: msgSig,
			VerificationMaterial: &protobundle.VerificationMaterial{Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: c.Raw}}}}))
	}
	v1MLDSAChain := mustVal(sgbundle.NewBundle(&protobundle.Bundle{MediaType: cbundle.BundleV03MediaType, Content: msgSig,
		VerificationMaterial: &protobundle.VerificationMaterial{Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{Certificates: []*protocommon.X509Certificate{{RawBytes: ecdsaLeaf.Raw}, {RawBytes: mldsaCert.Raw}}},
		}}}, sgbundle.AllowCertificateChain()))

	var typedNilV1 *sgbundle.Bundle
	var typedNilSV *signature.ECDSAVerifier
	var typedNilTM *root.TrustedRoot
	artOpt := func() verify.ArtifactPolicyOption { return verify.WithArtifact(bytes.NewReader(artifact)) }
	dgstOpt := func() verify.ArtifactPolicyOption { return verify.WithArtifactDigest("sha256", digest[:]) }
	for _, tc := range []struct {
		name    string
		co      *CheckOpts
		policy  verify.ArtifactPolicyOption
		entity  verify.SignedEntity
		wantErr string
	}{
		{"v1 nil CheckOpts", nil, artOpt(), v1Blob, "check options must not be nil"},
		{"v1 typed-nil bundle", &CheckOpts{TrustedMaterial: vs}, artOpt(), typedNilV1, "bundle must not be nil"},
		{"v1 nil policy", &CheckOpts{TrustedMaterial: vs}, nil, v1Blob, "artifact policy option must not be nil"},
		{"v1 typed-nil SV+TM", &CheckOpts{SigVerifier: typedNilSV, TrustedMaterial: typedNilTM}, artOpt(), v1Blob, "trusted root is required"},
		{"v1 classical rejected PQCOnly", &CheckOpts{PQCOnly: true, Identities: ids, IgnoreSCT: true, UseSignedTimestamps: true, TrustedMaterial: vs}, artOpt(), v1Blob, "--experimental-pqc-only"},
		{"v1 rejects ML-DSA key", &CheckOpts{SigVerifier: mldsa44V, IgnoreTlog: true, TrustedMaterial: vs}, artOpt(), v1Blob, "ML-DSA public keys are not supported for v1 bundles"},
		{"v1 rejects ML-DSA leaf cert", &CheckOpts{Identities: ids, IgnoreSCT: true, IgnoreTlog: true, TrustedMaterial: vs}, artOpt(), mkV1Cert(mldsaCert), "ML-DSA certificates are not supported for v1 bundles"},
		{"v1 rejects ML-DSA-signed cert", &CheckOpts{Identities: ids, IgnoreSCT: true, IgnoreTlog: true, TrustedMaterial: vs}, artOpt(), mkV1Cert(ecdsaByMLDSA), "ML-DSA certificates are not supported for v1 bundles"},
		{"v1 rejects ML-DSA chain cert", &CheckOpts{Identities: ids, IgnoreSCT: true, IgnoreTlog: true, AllowCertificateChain: true, TrustedMaterial: vs}, artOpt(), v1MLDSAChain, "ML-DSA certificates are not supported for v1 bundles"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyNewBundle(context.Background(), tc.co, tc.policy, tc.entity)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}

	oidcPlain, oidcLog := buildTestBundleV2(t, testV2BundleOpts{artifact: artifact, identity: subject, issuer: issuer})
	oidcDSSE, oidcDSSELog := buildTestBundleV2(t, testV2BundleOpts{dssePayload: stmt, identity: subject, issuer: issuer})
	keyPlain, keyLog := buildTestBundleV2(t, testV2BundleOpts{artifact: artifact, signerKey: mldsa44Key})
	keyDSSE, keyDSSELog := buildTestBundleV2(t, testV2BundleOpts{dssePayload: stmt, signerKey: mldsa44Key})
	ecdsaLogB, ecdsaLog := buildTestBundleV2(t, testV2BundleOpts{artifact: artifact, identity: subject, issuer: issuer, logKey: ecdsaKey})
	edLogB, edLog := buildTestBundleV2(t, testV2BundleOpts{artifact: artifact, identity: subject, issuer: issuer, logKey: ed25519Key})
	rawKeyV2 := mustVal(sgbundle.NewBundleV2(&bundleV2.Bundle{MediaType: cbundle.BundleV20MediaType, VerificationMaterial: &bundleV2.VerificationMaterial{Content: &bundleV2.VerificationMaterial_PublicKey{PublicKey: &bundleV2.PublicKey{Signature: &bundleV2.Signature{Signature: []byte("sig")}}}}}))
	certV2 := mustVal(sgbundle.NewBundleV2(&bundleV2.Bundle{MediaType: cbundle.BundleV20MediaType, VerificationMaterial: &bundleV2.VerificationMaterial{Content: &bundleV2.VerificationMaterial_Certificate{Certificate: &bundleV2.Certificate{Certificate: &protocommon.X509Certificate{RawBytes: []byte("d")}, Signature: &bundleV2.Signature{Signature: []byte("s")}, Timestamps: &bundleV2.TimestampVerificationData{Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: []byte("t")}}}}}}}))

	tmFor := func(tl *root.TransparencyLog) root.TrustedMaterial {
		return &testPQCTrustedMaterial{TrustedMaterial: &root.BaseTrustedMaterial{}, extraRekor: map[string]*root.TransparencyLog{"rekor-v3": tl}}
	}
	var typedNilB *sgbundle.BundleV2
	for _, tc := range []struct {
		name    string
		co      *CheckOpts
		policy  verify.ArtifactPolicyOption
		entity  verify.VerifiableEntity
		wantErr string
		wantIs  error
	}{
		{"v2 OIDC plain default", &CheckOpts{Identities: ids, TrustedMaterial: tmFor(oidcLog)}, artOpt(), oidcPlain, "", nil},
		{"v2 OIDC plain PQCOnly", &CheckOpts{PQCOnly: true, Identities: ids, TrustedMaterial: tmFor(oidcLog)}, dgstOpt(), oidcPlain, "", nil},
		{"v2 OIDC DSSE", &CheckOpts{PQCOnly: true, Identities: ids, TrustedMaterial: tmFor(oidcDSSELog)}, dgstOpt(), oidcDSSE, "", nil},
		{"v2 ML-DSA-44 key plain", &CheckOpts{PQCOnly: true, SigVerifier: mldsa44V, TrustedMaterial: tmFor(keyLog)}, artOpt(), keyPlain, "", nil},
		{"v2 ML-DSA-44 key DSSE", &CheckOpts{SigVerifier: mldsa44V, TrustedMaterial: tmFor(keyDSSELog)}, dgstOpt(), keyDSSE, "", nil},
		{"v2 OIDC wrong subject", &CheckOpts{Identities: []Identity{{Issuer: issuer, Subject: "bob@example.com"}}, TrustedMaterial: tmFor(oidcLog)}, artOpt(), oidcPlain, "failed to verify identity", nil},
		{"v2 OIDC with key", &CheckOpts{SigVerifier: mldsa44V, TrustedMaterial: tmFor(oidcLog)}, artOpt(), oidcPlain, "expected key signature", nil},
		{"v2 key with identity", &CheckOpts{Identities: ids, TrustedMaterial: tmFor(keyLog)}, artOpt(), keyPlain, "signed with a public key", nil},
		{"v2 key tampered", &CheckOpts{SigVerifier: mldsa44V, TrustedMaterial: tmFor(keyLog)}, verify.WithArtifact(bytes.NewReader([]byte("tampered"))), keyPlain, "artifact signature verification failed", nil},
		{"v2 rejects ECDSA key", &CheckOpts{SigVerifier: ecdsaV, TrustedMaterial: tmFor(keyLog)}, artOpt(), keyPlain, "requires an ML-DSA-44 public key", nil},
		{"v2 rejects ML-DSA-65 key", &CheckOpts{SigVerifier: mldsa65V, TrustedMaterial: tmFor(keyLog)}, artOpt(), keyPlain, "only supports ML-DSA-44", ErrUnsupportedMLDSAParameters},
		{"v2 rejects ECDSA log", &CheckOpts{Identities: ids, TrustedMaterial: tmFor(ecdsaLog)}, artOpt(), ecdsaLogB, "failed to verify checkpoint", nil},
		{"v2 rejects Ed25519 log", &CheckOpts{Identities: ids, TrustedMaterial: tmFor(edLog)}, artOpt(), edLogB, "ML-DSA-44", nil},
		{"v2 rejects IgnoreTlog", &CheckOpts{IgnoreTlog: true, Identities: ids, TrustedMaterial: tmFor(oidcLog)}, artOpt(), oidcPlain, "ignoring transparency log verification is not supported", nil},
		{"v2 rejects UseSignedTimestamps", &CheckOpts{UseSignedTimestamps: true, Identities: ids, TrustedMaterial: tmFor(oidcLog)}, artOpt(), oidcPlain, "signed timestamps are not supported", nil},
		{"v2 rejects typed-nil ML-DSA key", &CheckOpts{SigVerifier: stubPubVerifier{pub: (*mldsa.PublicKey)(nil)}, TrustedMaterial: tmFor(keyLog)}, artOpt(), keyPlain, "invalid ML-DSA public key", nil},
		{"v2 rejects zero-value ML-DSA key", &CheckOpts{SigVerifier: stubPubVerifier{pub: &mldsa.PublicKey{}}, TrustedMaterial: tmFor(keyLog)}, artOpt(), keyPlain, "invalid ML-DSA public key", nil},
		{"v2 rejects nil TM", &CheckOpts{Identities: ids}, artOpt(), oidcPlain, "trusted root is required", nil},
		{"v2 rejects typed-nil TM", &CheckOpts{Identities: ids, TrustedMaterial: typedNilTM}, artOpt(), oidcPlain, "trusted root is required", nil},
		{"v2 rejects key+identities", &CheckOpts{SigVerifier: mldsa44V, Identities: ids, TrustedMaterial: tmFor(keyLog)}, artOpt(), keyPlain, "cannot specify both", nil},
		{"v2 rejects empty policy", &CheckOpts{TrustedMaterial: tmFor(oidcLog)}, artOpt(), oidcPlain, "either a public key verifier or an expected identity is required", nil},
		{"v2 rejects PublicKey", &CheckOpts{SigVerifier: mldsa44V, TrustedMaterial: tmFor(keyLog)}, artOpt(), rawKeyV2, "v2 raw public-key (non-transparent) bundles are not yet supported", nil},
		{"v2 rejects Certificate", &CheckOpts{Identities: ids, TrustedMaterial: tmFor(oidcLog)}, artOpt(), certV2, "v2 certificate-based (non-transparent) bundles are not yet supported", nil},
		{"v2 rejects nil CheckOpts", nil, artOpt(), oidcPlain, "check options must not be nil", nil},
		{"v2 rejects typed-nil bundle", &CheckOpts{Identities: ids, TrustedMaterial: tmFor(oidcLog)}, artOpt(), typedNilB, "bundle must not be nil", nil},
		{"v2 rejects nil policy", &CheckOpts{Identities: ids, TrustedMaterial: tmFor(oidcLog)}, nil, oidcPlain, "artifact policy option must not be nil", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := VerifyBundleV2(context.Background(), tc.co, tc.policy, tc.entity)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				if tc.wantIs != nil {
					require.ErrorIs(t, err, tc.wantIs)
				}
				return
			}
			require.NoError(t, err)
			require.True(t, res != nil && res.Verified)
		})
	}
}

type stubPubVerifier struct {
	signature.Verifier
	pub crypto.PublicKey
}

func (s stubPubVerifier) PublicKey(...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.pub, nil
}
