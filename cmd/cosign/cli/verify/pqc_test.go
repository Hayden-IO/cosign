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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	sumdbNote "golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testPQCOrigin = "rekor-v3.cli.test"

func writePEMPubKey(t *testing.T, dir, name string, pub crypto.PublicKey) string {
	t.Helper()
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pub)
	require.NoError(t, err)
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, pemBytes, 0o600))
	return p
}

func makeCLITestV2Bundle(t *testing.T, logKey *mldsa.PrivateKey, artifact, dssePayload []byte, subject, issuer string, signerKey *mldsa.PrivateKey) []byte {
	t.Helper()
	var artifactDigest [32]byte
	var payloadPB *bundleV2.Payload
	if len(dssePayload) > 0 {
		const pt = "application/vnd.in-toto+json"
		artifactDigest = sha256.Sum256(dsse.PAE(pt, dssePayload))
		payloadPB = &bundleV2.Payload{PayloadType: pt, Payload: dssePayload}
	} else {
		artifactDigest = sha256.Sum256(artifact)
	}
	msgHash := sha256.Sum256(artifactDigest[:])
	dbl := func(b []byte) [32]byte { h := sha256.Sum256(b); return sha256.Sum256(h[:]) }

	var rotHash, receiptDigest [32]byte
	var contextHashes, extraData []byte
	var sigPB *bundleV2.Signature
	if signerKey != nil {
		pubDER, err := x509.MarshalPKIXPublicKey(signerKey.Public())
		require.NoError(t, err)
		sig, err := signerKey.Sign(rand.Reader, append([]byte("c2sp.org/identity-transparency/v1\x00"), msgHash[:]...), crypto.Hash(0))
		require.NoError(t, err)
		rotHash, receiptDigest = sha256.Sum256(append([]byte("ML-DSA-44"), pubDER...)), sha256.Sum256(sig)
		sigPB = &bundleV2.Signature{Signature: sig}
	} else {
		extraData = []byte("identity:" + subject + "\nissuer:" + issuer)
		rotHash = sha256.Sum256([]byte(issuer))
		ik2, iv2 := dbl([]byte("identity")), dbl([]byte(subject))
		issk2, issv2 := dbl([]byte("issuer")), dbl([]byte(issuer))
		if bytes.Compare(ik2[:], issk2[:]) < 0 {
			contextHashes = slices.Concat(ik2[:], iv2[:], issk2[:], issv2[:])
		} else {
			contextHashes = slices.Concat(issk2[:], issv2[:], ik2[:], iv2[:])
		}
	}
	leaf := slices.Concat([]byte{0x01}, rotHash[:], msgHash[:], contextHashes, receiptDigest[:])
	cp := formatsLog.Checkpoint{Origin: testPQCOrigin, Size: 1, Hash: rfc6962.DefaultHasher.HashLeaf(leaf)}
	sv, err := signature.LoadDefaultSigner(logKey)
	require.NoError(t, err)
	ns, err := note.NewNoteSigner(context.Background(), testPQCOrigin, sv)
	require.NoError(t, err)
	signedNote, err := sumdbNote.Sign(&sumdbNote.Note{Text: string(cp.Marshal())}, ns)
	require.NoError(t, err)
	b2, err := sgbundle.NewBundleV2(&bundleV2.Bundle{
		MediaType: cbundle.BundleV20MediaType, Payload: payloadPB,
		VerificationMaterial: &bundleV2.VerificationMaterial{Content: &bundleV2.VerificationMaterial_TransparencyLogProof{
			TransparencyLogProof: &bundleV2.TransparencyLogProof{Proof: (&proof.TLogProof{Checkpoint: signedNote, ExtraData: extraData}).Marshal(), Signature: sigPB},
		}},
	})
	require.NoError(t, err)
	out, err := b2.MarshalJSON()
	require.NoError(t, err)
	return out
}

func writePQCTrustedRootFile(t *testing.T, dir string, logKey *mldsa.PrivateKey) string {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(logKey.Public())
	require.NoError(t, err)
	logID := sha256.Sum256(pubDER)
	now := time.Now()
	trJSON, err := protojson.Marshal(&prototrustroot.TrustedRoot{
		MediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		Tlogs: []*prototrustroot.TransparencyLogInstance{{
			BaseUrl: "https://" + testPQCOrigin, HashAlgorithm: protocommon.HashAlgorithm_SHA2_256,
			PublicKey: &protocommon.PublicKey{
				RawBytes: pubDER, KeyDetails: protocommon.PublicKeyDetails_ML_DSA_44,
				ValidFor: &protocommon.TimeRange{Start: timestamppb.New(now.Add(-time.Hour)), End: timestamppb.New(now.Add(time.Hour))},
			},
			LogId: &protocommon.LogId{KeyId: logID[:]},
		}},
	})
	require.NoError(t, err)
	p := filepath.Join(dir, "pqc_trusted_root.json")
	require.NoError(t, os.WriteFile(p, trJSON, 0o600))
	return p
}

type nilMLDSAPubVerifier struct{}

func (nilMLDSAPubVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	var p *mldsa.PublicKey
	return p, nil
}
func (nilMLDSAPubVerifier) VerifySignature(_, _ io.Reader, _ ...signature.VerifyOption) error {
	return nil
}

type zeroMLDSAPubVerifier struct{ nilMLDSAPubVerifier }

func (zeroMLDSAPubVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return &mldsa.PublicKey{}, nil
}

func TestPQCOnlyHelpersAndHeader(t *testing.T) {
	var stderr bytes.Buffer
	ctx := ui.WithEnv(context.Background(), &ui.Env{Stderr: &stderr})

	WarnExperimentalPQCOnly(ctx)
	require.Contains(t, stderr.String(), "EXPERIMENTAL")
	require.Contains(t, stderr.String(), "--experimental-pqc-only")

	require.NoError(t, ValidatePQCOnlyFlags(false, false, false))
	require.ErrorContains(t, ValidatePQCOnlyFlags(true, false, false), "--insecure-ignore-tlog")
	require.ErrorContains(t, ValidatePQCOnlyFlags(true, false, false), "--private-infrastructure")
	require.ErrorContains(t, ValidatePQCOnlyFlags(false, true, false), "--sk")
	require.ErrorContains(t, ValidatePQCOnlyFlags(false, false, true), "--use-signed-timestamps")

	mldsa44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	mldsa65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	mldsa87, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v44, err := signature.LoadDefaultVerifier(mldsa44.Public())
	require.NoError(t, err)
	v65, err := signature.LoadDefaultVerifier(mldsa65.Public())
	require.NoError(t, err)
	v87, err := signature.LoadDefaultVerifier(mldsa87.Public())
	require.NoError(t, err)
	vEC, err := signature.LoadECDSAVerifier(&ecdsaKey.PublicKey, crypto.SHA256)
	require.NoError(t, err)
	var typedNilSV *signature.ECDSAVerifier

	require.NoError(t, ValidatePQCOnlyVerifier(nil))
	require.NoError(t, ValidatePQCOnlyVerifier(typedNilSV))
	require.NoError(t, ValidatePQCOnlyVerifier(v44))
	require.ErrorContains(t, ValidatePQCOnlyVerifier(nilMLDSAPubVerifier{}), "valid ML-DSA-44 public key")
	require.ErrorContains(t, ValidatePQCOnlyVerifier(zeroMLDSAPubVerifier{}), "valid ML-DSA-44 public key")
	require.ErrorContains(t, ValidatePQCOnlyVerifier(vEC), "requires an ML-DSA-44 public key")
	require.ErrorIs(t, ValidatePQCOnlyVerifier(v65), cosign.ErrUnsupportedMLDSAParameters)
	require.ErrorIs(t, ValidatePQCOnlyVerifier(v87), cosign.ErrUnsupportedMLDSAParameters)
	_, err = AssembleNewBundleFromPayload(ctx, []byte("payload"), []byte("sig"), nil, nil, nil, true, v44, nil, nil)
	require.ErrorContains(t, err, "ML-DSA public keys are not supported for v1 bundles")
	_, err = AssembleNewBundleFromPayload(ctx, []byte("payload"), []byte("sig"), nil, nil, &x509.Certificate{PublicKey: mldsa44.Public()}, true, nil, nil, nil)
	require.ErrorContains(t, err, "ML-DSA certificates are not supported for v1 bundles")

	require.False(t, verifyOfflineWithKey("k.pub", false, nil))
	require.False(t, verifyOfflineWithKey("k.pub", false, &cosign.CheckOpts{IgnoreTlog: true, PQCOnly: true}))
	require.True(t, verifyOfflineWithKey("k.pub", false, &cosign.CheckOpts{IgnoreTlog: true}))

	stderr.Reset()
	PrintVerificationHeader(ctx, "example.com/img", &cosign.CheckOpts{PQCOnly: true}, true, true)
	require.Contains(t, stderr.String(), "signing identity was verified against the transparency log")
	require.NotContains(t, stderr.String(), "certificate authority")

	stderr.Reset()
	PrintVerificationHeader(ctx, "example.com/img", &cosign.CheckOpts{PQCOnly: false}, true, true)
	require.Contains(t, stderr.String(), "code-signing certificate or signing identity")
}

func TestPQCOnlyUpfrontRejectionAcrossCommands(t *testing.T) {
	dir := t.TempDir()
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaPubPath := writePEMPubKey(t, dir, "ecdsa.pub", &ecdsaKey.PublicKey)
	mldsa65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	mldsa65PubPath := writePEMPubKey(t, dir, "mldsa65.pub", mldsa65.Public())
	mldsa87, err := mldsa.GenerateKey(mldsa.MLDSA87())
	require.NoError(t, err)
	mldsa87PubPath := writePEMPubKey(t, dir, "mldsa87.pub", mldsa87.Public())

	var stderr bytes.Buffer
	ctx := ui.WithEnv(context.Background(), &ui.Env{Stderr: &stderr})
	idOpts := options.CertVerifyOptions{CertIdentity: "alice@example.com", CertOidcIssuer: "https://issuer.example"}

	// verify (including embedded CommonVerifyOptions.IgnoreTlog & UseSignedTimestamps)
	require.ErrorContains(t, (&VerifyCommand{ExperimentalPQCOnly: true, IgnoreTlog: true, CertVerifyOptions: idOpts}).Exec(ctx, []string{"img"}), "--insecure-ignore-tlog")
	require.ErrorContains(t, (&VerifyCommand{CommonVerifyOptions: options.CommonVerifyOptions{ExperimentalPQCOnly: true, IgnoreTlog: true}, CertVerifyOptions: idOpts}).Exec(ctx, []string{"img"}), "--insecure-ignore-tlog")
	require.ErrorContains(t, (&VerifyCommand{ExperimentalPQCOnly: true, PrivateInfrastructure: true, CertVerifyOptions: idOpts}).Exec(ctx, []string{"img"}), "--private-infrastructure")
	require.ErrorContains(t, (&VerifyCommand{CommonVerifyOptions: options.CommonVerifyOptions{ExperimentalPQCOnly: true, UseSignedTimestamps: true}, CertVerifyOptions: idOpts}).Exec(ctx, []string{"img"}), "--use-signed-timestamps")
	require.ErrorContains(t, (&VerifyCommand{ExperimentalPQCOnly: true, Sk: true}).Exec(ctx, []string{"img"}), "--sk")
	stderr.Reset()
	require.ErrorContains(t, (&VerifyCommand{ExperimentalPQCOnly: true, KeyRef: ecdsaPubPath}).Exec(ctx, []string{"img"}), "ML-DSA-44")
	require.Contains(t, stderr.String(), "EXPERIMENTAL")
	require.ErrorIs(t, (&VerifyCommand{ExperimentalPQCOnly: true, KeyRef: mldsa87PubPath}).Exec(ctx, []string{"img"}), cosign.ErrUnsupportedMLDSAParameters)

	// verify-attestation
	require.ErrorContains(t, (&VerifyAttestationCommand{CommonVerifyOptions: options.CommonVerifyOptions{ExperimentalPQCOnly: true, IgnoreTlog: true}, CertVerifyOptions: idOpts}).Exec(ctx, []string{"img"}), "--insecure-ignore-tlog")
	require.ErrorContains(t, (&VerifyAttestationCommand{ExperimentalPQCOnly: true, PrivateInfrastructure: true, CertVerifyOptions: idOpts}).Exec(ctx, []string{"img"}), "--private-infrastructure")
	require.ErrorContains(t, (&VerifyAttestationCommand{CommonVerifyOptions: options.CommonVerifyOptions{ExperimentalPQCOnly: true, UseSignedTimestamps: true}, CertVerifyOptions: idOpts}).Exec(ctx, []string{"img"}), "--use-signed-timestamps")
	require.ErrorContains(t, (&VerifyAttestationCommand{ExperimentalPQCOnly: true, Sk: true}).Exec(ctx, []string{"img"}), "--sk")
	require.ErrorContains(t, (&VerifyAttestationCommand{ExperimentalPQCOnly: true, KeyRef: ecdsaPubPath}).Exec(ctx, []string{"img"}), "ML-DSA-44")
	require.ErrorIs(t, (&VerifyAttestationCommand{ExperimentalPQCOnly: true, KeyRef: mldsa65PubPath}).Exec(ctx, []string{"img"}), cosign.ErrUnsupportedMLDSAParameters)

	// verify-blob & verify-blob-attestation
	require.ErrorContains(t, (&VerifyBlobCmd{PQCOnly: true, IgnoreTlog: true, CertVerifyOptions: idOpts}).Exec(ctx, "blob"), "--insecure-ignore-tlog")
	require.ErrorContains(t, (&VerifyBlobCmd{PQCOnly: true, UseSignedTimestamps: true, CertVerifyOptions: idOpts}).Exec(ctx, "blob"), "--use-signed-timestamps")
	require.ErrorContains(t, (&VerifyBlobCmd{PQCOnly: true, Sk: true}).Exec(ctx, "blob"), "--sk")
	require.ErrorContains(t, (&VerifyBlobCmd{PQCOnly: true, KeyRef: ecdsaPubPath}).Exec(ctx, "blob"), "ML-DSA-44")
	require.ErrorIs(t, (&VerifyBlobCmd{PQCOnly: true, KeyRef: mldsa65PubPath}).Exec(ctx, "blob"), cosign.ErrUnsupportedMLDSAParameters)
	require.ErrorContains(t, (&VerifyBlobCmd{CertVerifyOptions: idOpts}).Exec(ctx, "blob"), "bundle path is required")

	require.ErrorContains(t, (&VerifyBlobAttestationCommand{PQCOnly: true, IgnoreTlog: true, CertVerifyOptions: idOpts}).Exec(ctx, "blob"), "--insecure-ignore-tlog")
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{PQCOnly: true, UseSignedTimestamps: true, CertVerifyOptions: idOpts}).Exec(ctx, "blob"), "--use-signed-timestamps")
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{PQCOnly: true, Sk: true}).Exec(ctx, "blob"), "--sk")
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{PQCOnly: true, KeyRef: ecdsaPubPath}).Exec(ctx, "blob"), "ML-DSA-44")
	require.ErrorIs(t, (&VerifyBlobAttestationCommand{PQCOnly: true, KeyRef: mldsa87PubPath}).Exec(ctx, "blob"), cosign.ErrUnsupportedMLDSAParameters)
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{CheckClaims: true, CertVerifyOptions: idOpts}).Exec(ctx, ""), "must provide path to blob or digest and digestAlg")
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{CheckClaims: false, CertVerifyOptions: idOpts}).Exec(ctx, ""), "bundle path is required")
}

func TestVerifyBlobAndBlobAttestationDualV1V2(t *testing.T) {
	dir := t.TempDir()
	const (
		subject   = "alice@example.com"
		issuer    = "https://accounts.example.com"
		predicate = "https://example.com/pqc-pred/v1"
	)

	artifact := []byte("cosign-pqc-blob-test")
	artifactPath := filepath.Join(dir, "blob.bin")
	require.NoError(t, os.WriteFile(artifactPath, artifact, 0o600))
	digest := sha256.Sum256(artifact)
	digestHex := hex.EncodeToString(digest[:])
	stmt := fmt.Appendf(nil, `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"blob.bin","digest":{"sha256":"%s"}}],"predicateType":"%s","predicate":{"ok":true}}`, digestHex, predicate)

	logKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	trPath := writePQCTrustedRootFile(t, dir, logKey)

	signerKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	mldsaPubPath := writePEMPubKey(t, dir, "mldsa44.pub", signerKey.Public())
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaPubPath := writePEMPubKey(t, dir, "ecdsa.pub", &ecdsaKey.PublicKey)

	oidcPlainPath := filepath.Join(dir, "oidc_plain.v2.json")
	keyPlainPath := filepath.Join(dir, "key_plain.v2.json")
	oidcDSSEPath := filepath.Join(dir, "oidc_dsse.v2.json")
	keyDSSEPath := filepath.Join(dir, "key_dsse.v2.json")
	require.NoError(t, os.WriteFile(oidcPlainPath, makeCLITestV2Bundle(t, logKey, artifact, nil, subject, issuer, nil), 0o600))
	require.NoError(t, os.WriteFile(keyPlainPath, makeCLITestV2Bundle(t, logKey, artifact, nil, "", "", signerKey), 0o600))
	require.NoError(t, os.WriteFile(oidcDSSEPath, makeCLITestV2Bundle(t, logKey, nil, stmt, subject, issuer, nil), 0o600))
	require.NoError(t, os.WriteFile(keyDSSEPath, makeCLITestV2Bundle(t, logKey, nil, stmt, "", "", signerKey), 0o600))

	rootCert, rootKey, err := test.GenerateRootCa()
	require.NoError(t, err)
	leafCert, leafKey, err := test.GenerateLeafCert(subject, issuer, rootCert, rootKey)
	require.NoError(t, err)
	v1TR, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: rootCert}}, nil, nil, nil)
	require.NoError(t, err)
	v1TRBytes, err := v1TR.MarshalJSON()
	require.NoError(t, err)
	v1TRPath := filepath.Join(dir, "v1_trusted_root.json")
	require.NoError(t, os.WriteFile(v1TRPath, v1TRBytes, 0o600))

	blobSig, err := ecdsa.SignASN1(rand.Reader, leafKey, digest[:])
	require.NoError(t, err)
	v1BlobJSON, err := protojson.Marshal(&protobundle.Bundle{
		MediaType:            cbundle.BundleV03MediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw}}},
		Content:              &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: digest[:]}, Signature: blobSig}},
	})
	require.NoError(t, err)
	v1BlobPath := filepath.Join(dir, "v1_blob.json")
	require.NoError(t, os.WriteFile(v1BlobPath, v1BlobJSON, 0o600))

	const pt = "application/vnd.in-toto+json"
	paeDigest := sha256.Sum256(dsse.PAE(pt, stmt))
	dsseSig, err := ecdsa.SignASN1(rand.Reader, leafKey, paeDigest[:])
	require.NoError(t, err)
	v1AttJSON, err := protojson.Marshal(&protobundle.Bundle{
		MediaType:            cbundle.BundleV03MediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw}}},
		Content:              &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{Payload: stmt, PayloadType: pt, Signatures: []*protodsse.Signature{{Sig: dsseSig}}}},
	})
	require.NoError(t, err)
	v1AttPath := filepath.Join(dir, "v1_att.json")
	require.NoError(t, os.WriteFile(v1AttPath, v1AttJSON, 0o600))

	idOpts := options.CertVerifyOptions{CertIdentity: subject, CertOidcIssuer: issuer}
	ctx := ui.WithEnv(context.Background(), &ui.Env{Stderr: io.Discard})

	// verify-blob: v2 OIDC/key, v1 default vs PQCOnly, plus default-mode strict separation and non-bypass checks.
	require.NoError(t, (&VerifyBlobCmd{BundlePath: oidcPlainPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath}).Exec(ctx, artifactPath))
	require.NoError(t, (&VerifyBlobCmd{BundlePath: oidcPlainPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, PQCOnly: true}).Exec(ctx, "sha256:"+digestHex))
	require.NoError(t, (&VerifyBlobCmd{BundlePath: keyPlainPath, KeyRef: mldsaPubPath, TrustedRootPath: trPath, PQCOnly: true}).Exec(ctx, artifactPath))
	require.NoError(t, (&VerifyBlobCmd{BundlePath: v1BlobPath, CertVerifyOptions: idOpts, TrustedRootPath: v1TRPath, IgnoreSCT: true, IgnoreTlog: true}).Exec(ctx, artifactPath))
	require.ErrorContains(t, (&VerifyBlobCmd{BundlePath: v1BlobPath, CertVerifyOptions: idOpts, TrustedRootPath: v1TRPath, IgnoreSCT: true, PQCOnly: true}).Exec(ctx, artifactPath), "--experimental-pqc-only")
	require.ErrorContains(t, (&VerifyBlobCmd{BundlePath: keyPlainPath, KeyRef: mldsaPubPath, IgnoreTlog: true}).Exec(ctx, artifactPath), "ignoring transparency log verification is not supported")
	require.ErrorContains(t, (&VerifyBlobCmd{BundlePath: keyPlainPath, KeyRef: mldsaPubPath, TrustedRootPath: trPath, UseSignedTimestamps: true}).Exec(ctx, artifactPath), "signed timestamps are not supported")
	require.ErrorContains(t, (&VerifyBlobCmd{BundlePath: oidcDSSEPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, PQCOnly: true}).Exec(ctx, artifactPath), "DSSE envelope")
	require.ErrorContains(t, (&VerifyBlobCmd{BundlePath: keyDSSEPath, KeyRef: mldsaPubPath, TrustedRootPath: trPath, PQCOnly: true}).Exec(ctx, artifactPath), "DSSE envelope")
	require.ErrorContains(t, (&VerifyBlobCmd{BundlePath: keyPlainPath, KeyRef: ecdsaPubPath, TrustedRootPath: trPath}).Exec(ctx, artifactPath), "ML-DSA-44")
	require.ErrorContains(t, (&VerifyBlobCmd{BundlePath: v1BlobPath, KeyRef: mldsaPubPath, TrustedRootPath: v1TRPath, IgnoreTlog: true}).Exec(ctx, artifactPath), "ML-DSA public keys are not supported for v1 bundles")
	require.Error(t, (&VerifyBlobCmd{BundlePath: oidcPlainPath, CertIdentity: "wrong@example.com", CertOidcIssuer: issuer, TrustedRootPath: trPath, PQCOnly: true}).Exec(ctx, artifactPath))

	// verify-blob-attestation: v2 OIDC/key, digest, CheckClaims=false, wrong predicate, non-DSSE, v1 default vs PQCOnly, non-bypass.
	require.NoError(t, (&VerifyBlobAttestationCommand{BundlePath: oidcDSSEPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, CheckClaims: true, PredicateType: predicate}).Exec(ctx, artifactPath))
	require.NoError(t, (&VerifyBlobAttestationCommand{BundlePath: oidcDSSEPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, CheckClaims: true, Digest: digestHex, DigestAlg: "sha256", PredicateType: predicate, PQCOnly: true}).Exec(ctx, ""))
	require.NoError(t, (&VerifyBlobAttestationCommand{BundlePath: oidcDSSEPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, CheckClaims: false, PredicateType: predicate, PQCOnly: true}).Exec(ctx, ""))
	require.NoError(t, (&VerifyBlobAttestationCommand{BundlePath: keyDSSEPath, KeyRef: mldsaPubPath, TrustedRootPath: trPath, CheckClaims: true, PredicateType: predicate, PQCOnly: true}).Exec(ctx, artifactPath))
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{BundlePath: oidcDSSEPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, CheckClaims: true, PredicateType: "https://example.com/other", PQCOnly: true}).Exec(ctx, artifactPath), "invalid predicate type")
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{BundlePath: oidcPlainPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, CheckClaims: true, PredicateType: predicate, PQCOnly: true}).Exec(ctx, artifactPath), "DSSE envelope")
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{BundlePath: oidcPlainPath, CertVerifyOptions: idOpts, TrustedRootPath: trPath, CheckClaims: false, PredicateType: predicate, PQCOnly: true}).Exec(ctx, ""), "DSSE envelope")
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{BundlePath: keyDSSEPath, KeyRef: mldsaPubPath, IgnoreTlog: true, CheckClaims: true, PredicateType: predicate}).Exec(ctx, artifactPath), "ignoring transparency log verification is not supported")
	require.NoError(t, (&VerifyBlobAttestationCommand{BundlePath: v1AttPath, CertVerifyOptions: idOpts, TrustedRootPath: v1TRPath, IgnoreSCT: true, IgnoreTlog: true, CheckClaims: true, PredicateType: predicate}).Exec(ctx, artifactPath))
	require.ErrorContains(t, (&VerifyBlobAttestationCommand{BundlePath: v1AttPath, CertVerifyOptions: idOpts, TrustedRootPath: v1TRPath, IgnoreSCT: true, CheckClaims: true, PredicateType: predicate, PQCOnly: true}).Exec(ctx, artifactPath), "--experimental-pqc-only")

	// cosign verify claim verifier must reject non-sign attestation predicates while accepting CosignSignPredicateType.
	imgHash := v1.Hash{Algorithm: "sha256", Hex: digestHex}
	mkAtt := func(pred string) oci.Signature {
		rawStmt := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"img","digest":{"sha256":%q}}],"predicateType":%q,"predicate":{}}`, digestHex, pred)
		envJSON, err := json.Marshal(dsse.Envelope{PayloadType: pt, Payload: base64.StdEncoding.EncodeToString([]byte(rawStmt))})
		require.NoError(t, err)
		att, err := static.NewAttestation(envJSON)
		require.NoError(t, err)
		return att
	}
	require.NoError(t, cosignSignClaimVerifier(mkAtt(types.CosignSignPredicateType), imgHash, nil))
	require.ErrorContains(t, cosignSignClaimVerifier(mkAtt("https://example.com/vuln/v1"), imgHash, nil), "unexpected predicate type")
}
