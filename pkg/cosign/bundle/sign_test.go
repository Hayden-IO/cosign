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

package bundle

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
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/cosign/v3/internal/test"
	bundletypes "github.com/sigstore/cosign/v3/pkg/cosign/bundle/types"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	verifyBundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	sumdbNote "golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestLocalCertChainProvider_GetCertificateChain(t *testing.T) {
	rootCert, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatalf("GenerateRootCa: %v", err)
	}
	subCert, subKey, err := test.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatalf("GenerateSubordinateCa: %v", err)
	}
	leafCert, _, err := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	rootPEM, err := cryptoutils.MarshalCertificateToPEM(rootCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	subAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}
	leafSubAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}

	testCases := []struct {
		name      string
		cert      []byte
		chain     []byte
		wantDER   [][]byte
		wantError bool
	}{
		{
			name:    "leaf with root-only chain drops the self-signed root",
			cert:    leafPEM,
			chain:   rootPEM,
			wantDER: [][]byte{leafCert.Raw},
		},
		{
			name:    "leaf with sub and root chain drops the self-signed root",
			cert:    leafPEM,
			chain:   subAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:    "leaf already present in chain is deduped and root is dropped",
			cert:    leafPEM,
			chain:   leafSubAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:      "invalid leaf PEM",
			cert:      []byte("not a pem"),
			chain:     rootPEM,
			wantError: true,
		},
		{
			name:      "invalid chain PEM",
			cert:      leafPEM,
			chain:     []byte("not a pem"),
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &localCertChainProvider{cert: tc.cert, chain: tc.chain}
			got, err := provider.GetCertificateChain(context.Background(), nil, nil)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.wantDER) {
				t.Fatalf("expected %d certs, got %d", len(tc.wantDER), len(got))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.wantDER[i]) {
					t.Errorf("cert at index %d does not match expected DER", i)
				}
			}
		})
	}
}

func TestVerifyTrustedMaterialPublicKeyVerifiers(t *testing.T) {
	t.Run("nil keyTrustedMaterial", func(t *testing.T) {
		v := &verifyTrustedMaterial{}
		if got := v.PublicKeyVerifiers(); got != nil {
			t.Fatalf("expected nil verifiers, got %v", got)
		}
		if _, err := v.PublicKeyVerifier("hint"); err == nil {
			t.Fatal("expected error from PublicKeyVerifier when keyTrustedMaterial is nil")
		}
	})

	t.Run("delegates to keyTrustedMaterial", func(t *testing.T) {
		priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatalf("mldsa.GenerateKey: %v", err)
		}
		verifier, err := signature.LoadDefaultVerifier(priv.Public())
		if err != nil {
			t.Fatalf("LoadDefaultVerifier: %v", err)
		}
		key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})
		v := &verifyTrustedMaterial{
			keyTrustedMaterial: root.NewTrustedPublicKeyVerifiers(key),
		}

		verifiers := v.PublicKeyVerifiers()
		if len(verifiers) != 1 {
			t.Fatalf("expected 1 verifier, got %d", len(verifiers))
		}
		if verifiers[0] != key {
			t.Fatalf("expected delegated verifier to match original key")
		}
	})
}

type mockSignTrustedMaterial struct {
	root.BaseTrustedMaterial
	rekorLog *root.TransparencyLog
}

func (m *mockSignTrustedMaterial) RekorLogs() map[string]*root.TransparencyLog {
	return map[string]*root.TransparencyLog{"rekor-v3": m.rekorLog}
}

type staticKeypair struct {
	pubKey crypto.PublicKey
	pubPEM string
	sigAlg protocommon.PublicKeyDetails
}

func (k *staticKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
}
func (k *staticKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	if k.sigAlg != protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED {
		return k.sigAlg
	}
	return protocommon.PublicKeyDetails_ML_DSA_44
}
func (k *staticKeypair) GetHint() []byte                { return nil }
func (k *staticKeypair) GetKeyAlgorithm() string        { return "ML-DSA-44" }
func (k *staticKeypair) GetPublicKey() crypto.PublicKey { return k.pubKey }
func (k *staticKeypair) GetPublicKeyPem() (string, error) {
	if k.pubPEM != "" {
		return k.pubPEM, nil
	}
	der, err := x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
func (k *staticKeypair) SignData(_ context.Context, _ []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

// startMockRekorV3Server starts a local HTTP server (127.0.0.1) implementing
// POST /api/v2/log/entries and returning a verifiable ML-DSA-44 signed
// c2sp.org/tlog-proof for both OIDC and public-key credentials.
func startMockRekorV3Server(t *testing.T, logPrivKey *mldsa.PrivateKey, origin string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/log/entries" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			http.Error(w, "unexpected content-type: "+ct, http.StatusUnsupportedMediaType)
			return
		}
		if ua := r.Header.Get("User-Agent"); !strings.Contains(ua, "cosign") {
			http.Error(w, "missing cosign user-agent: "+ua, http.StatusBadRequest)
			return
		}
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var req pbrekor.IdentityRequestV001
		if err := protojson.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.GetMessage()) != sha256.Size {
			http.Error(w, "message digest must be 32 bytes", http.StatusBadRequest)
			return
		}

		msgHash := sha256.Sum256(req.GetMessage())
		var rotHash [32]byte
		var receiptDigest [32]byte
		var contextHashes []byte
		var extraData []byte

		doubleSHA256 := func(b []byte) [32]byte {
			h := sha256.Sum256(b)
			return sha256.Sum256(h[:])
		}

		if pk := req.GetPublicKey(); pk != nil {
			// Verify the client's ML-DSA-44 signature over the domain-separated payload.
			parsedPub, err := x509.ParsePKIXPublicKey(pk.GetPublicKey())
			if err != nil {
				http.Error(w, "invalid public key: "+err.Error(), http.StatusBadRequest)
				return
			}
			mldsaPub, ok := parsedPub.(*mldsa.PublicKey)
			if !ok || mldsaPub.Parameters() != mldsa.MLDSA44() {
				http.Error(w, "expected ML-DSA-44 public key", http.StatusBadRequest)
				return
			}
			signPayload := append([]byte("c2sp.org/identity-transparency/v1\x00"), msgHash[:]...)
			if len(pk.GetContext()) > 0 {
				extraData = []byte("context:" + hex.EncodeToString(pk.GetContext()))
				k2, v2 := doubleSHA256([]byte("context")), sha256.Sum256(pk.GetContext())
				contextHashes = append(contextHashes, k2[:]...)
				contextHashes = append(contextHashes, v2[:]...)
				signPayload = append(signPayload, k2[:]...)
				signPayload = append(signPayload, v2[:]...)
			}
			if err := mldsa.Verify(mldsaPub, signPayload, pk.GetSignature(), nil); err != nil {
				http.Error(w, "invalid public key signature: "+err.Error(), http.StatusBadRequest)
				return
			}
			rotHash = sha256.Sum256(append([]byte("ML-DSA-44"), pk.GetPublicKey()...))
			receiptDigest = sha256.Sum256(pk.GetSignature())
		} else if oidc := req.GetOidc(); oidc != nil {
			if oidc.GetToken() == "" {
				http.Error(w, "empty oidc token", http.StatusBadRequest)
				return
			}
			extraData = []byte("identity:alice@example.com\nissuer:https://accounts.example.com")
			rotHash = sha256.Sum256([]byte("https://accounts.example.com"))
			ik2, iv2 := doubleSHA256([]byte("identity")), doubleSHA256([]byte("alice@example.com"))
			issk2, issv2 := doubleSHA256([]byte("issuer")), doubleSHA256([]byte("https://accounts.example.com"))
			if bytes.Compare(ik2[:], issk2[:]) < 0 {
				contextHashes = slices.Concat(ik2[:], iv2[:], issk2[:], issv2[:])
			} else {
				contextHashes = slices.Concat(issk2[:], issv2[:], ik2[:], iv2[:])
			}
		} else {
			http.Error(w, "missing credential", http.StatusBadRequest)
			return
		}

		leaf := make([]byte, 0, 1+len(rotHash)+len(msgHash)+len(contextHashes)+len(receiptDigest))
		leaf = append(leaf, 0x01)
		leaf = append(leaf, rotHash[:]...)
		leaf = append(leaf, msgHash[:]...)
		leaf = append(leaf, contextHashes...)
		leaf = append(leaf, receiptDigest[:]...)
		leafHash := rfc6962.DefaultHasher.HashLeaf(leaf)

		cp := formatsLog.Checkpoint{
			Origin: origin,
			Size:   1,
			Hash:   leafHash,
		}
		signer, err := signature.LoadDefaultSigner(logPrivKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		noteSigner, err := note.NewNoteSigner(r.Context(), origin, signer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		signedNote, err := sumdbNote.Sign(&sumdbNote.Note{Text: string(cp.Marshal())}, noteSigner)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tlogProof := proof.TLogProof{
			Index:      0,
			Checkpoint: signedNote,
			ExtraData:  extraData,
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(tlogProof.Marshal())
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func makeTestSigningConfig(t *testing.T, services ...root.Service) *root.SigningConfig {
	t.Helper()
	sc, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		nil,
		nil,
		services,
		root.ServiceConfiguration{},
		nil,
		root.ServiceConfiguration{},
	)
	if err != nil {
		t.Fatalf("NewSigningConfig: %v", err)
	}
	return sc
}

func TestSignIdentityData_Success(t *testing.T) {
	logPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	const origin = "rekor-v3.local"
	rekorV3Srv, v3Calls := startMockRekorV3Server(t, logPrivKey, origin)

	// Start a decoy Rekor v2 server to verify SignIdentityData ignores non-v3 services.
	var v2Calls atomic.Int32
	rekorV2Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		v2Calls.Add(1)
		http.Error(w, "v2 should not be called", http.StatusInternalServerError)
	}))
	t.Cleanup(rekorV2Srv.Close)

	sc := makeTestSigningConfig(t,
		root.Service{
			URL:                 rekorV2Srv.URL,
			MajorAPIVersion:     2,
			ValidityPeriodStart: time.Now().Add(-time.Hour),
		},
		root.Service{
			URL:                 rekorV3Srv.URL,
			MajorAPIVersion:     3,
			ValidityPeriodStart: time.Now().Add(-time.Hour),
		},
	)
	tm := &mockSignTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			BaseURL:   "https://" + origin,
			PublicKey: logPrivKey.Public(),
		},
	}

	keypair, err := sign.NewMLDSAKeypair()
	if err != nil {
		t.Fatalf("NewMLDSAKeypair: %v", err)
	}
	ctxDigest := sha256.Sum256([]byte("test-signing-context"))

	dsseContent := &sign.DSSEData{
		Data:        []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://sigstore.dev/cosign/sign/v1"}`),
		PayloadType: verifyBundle.IntotoMediaType,
	}
	plainContent := &sign.PlainData{Data: []byte("hello post-quantum world")}

	testCases := []struct {
		name          string
		ctx           context.Context
		content       sign.Content
		cred          sign.IdentityCredential
		tm            root.TrustedMaterial
		wantPayload   bool
		wantSignature bool
	}{
		{
			name:          "OIDC PlainData with self-verification",
			ctx:           context.Background(),
			content:       plainContent,
			cred:          &sign.OIDCCredential{Token: "test-oidc-token"},
			tm:            tm,
			wantPayload:   false,
			wantSignature: false,
		},
		{
			name:          "OIDC DSSEData with self-verification",
			ctx:           context.Background(),
			content:       dsseContent,
			cred:          &sign.OIDCCredential{Token: "test-oidc-token"},
			tm:            tm,
			wantPayload:   true,
			wantSignature: false,
		},
		{
			name:          "ML-DSA-44 PublicKey PlainData with self-verification",
			ctx:           context.Background(),
			content:       plainContent,
			cred:          &sign.PublicKeyCredential{Keypair: keypair},
			tm:            tm,
			wantPayload:   false,
			wantSignature: true,
		},
		{
			name:          "ML-DSA-44 PublicKey PlainData with 32-byte Context and self-verification",
			ctx:           context.Background(),
			content:       plainContent,
			cred:          &sign.PublicKeyCredential{Keypair: keypair, Context: ctxDigest[:]},
			tm:            tm,
			wantPayload:   false,
			wantSignature: true,
		},
		{
			name:          "ML-DSA-44 PublicKey DSSEData with self-verification",
			ctx:           context.Background(),
			content:       dsseContent,
			cred:          &sign.PublicKeyCredential{Keypair: keypair},
			tm:            tm,
			wantPayload:   true,
			wantSignature: true,
		},
		{
			name:          "OIDC PlainData with nil TrustedMaterial and nil ctx",
			ctx:           nil,
			content:       plainContent,
			cred:          &sign.OIDCCredential{Token: "test-oidc-token"},
			tm:            nil,
			wantPayload:   false,
			wantSignature: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bundleBytes, err := SignIdentityData(tc.ctx, tc.content, tc.cred, sc, tc.tm)
			if err != nil {
				t.Fatalf("SignIdentityData: %v", err)
			}
			var pb bundleV2.Bundle
			if err := protojson.Unmarshal(bundleBytes, &pb); err != nil {
				t.Fatalf("protojson.Unmarshal: %v", err)
			}
			if pb.GetMediaType() != bundletypes.BundleV20MediaType {
				t.Errorf("MediaType = %q, want %q", pb.GetMediaType(), bundletypes.BundleV20MediaType)
			}
			tlogProof := pb.GetVerificationMaterial().GetTransparencyLogProof()
			if tlogProof == nil || len(tlogProof.GetProof()) == 0 {
				t.Fatal("expected non-empty TransparencyLogProof")
			}
			if hasSig := len(tlogProof.GetSignature().GetSignature()) > 0; hasSig != tc.wantSignature {
				t.Errorf("has signature = %v, want %v", hasSig, tc.wantSignature)
			}
			if hasPayload := pb.GetPayload() != nil; hasPayload != tc.wantPayload {
				t.Errorf("has payload = %v, want %v", hasPayload, tc.wantPayload)
			}
			if _, err := verifyBundle.NewBundleV2(&pb); err != nil {
				t.Fatalf("NewBundleV2 validation failed: %v", err)
			}
		})
	}

	if got := v2Calls.Load(); got != 0 {
		t.Errorf("expected Rekor v2 server not to be called, got %d calls", got)
	}
	if got := int(v3Calls.Load()); got != len(testCases) {
		t.Errorf("expected %d Rekor v3 calls, got %d", len(testCases), got)
	}
}

func TestSignIdentityData_ValidationErrors(t *testing.T) {
	logPrivKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	rekorV3Srv, _ := startMockRekorV3Server(t, logPrivKey, "rekor-v3.local")

	validSC := makeTestSigningConfig(t, root.Service{
		URL:                 rekorV3Srv.URL,
		MajorAPIVersion:     3,
		ValidityPeriodStart: time.Now().Add(-time.Hour),
	})
	v1OnlySC := makeTestSigningConfig(t, root.Service{
		URL:                 rekorV3Srv.URL,
		MajorAPIVersion:     1,
		ValidityPeriodStart: time.Now().Add(-time.Hour),
	})
	v2OnlySC := makeTestSigningConfig(t, root.Service{
		URL:                 rekorV3Srv.URL,
		MajorAPIVersion:     2,
		ValidityPeriodStart: time.Now().Add(-time.Hour),
	})
	expiredV3SC := makeTestSigningConfig(t, root.Service{
		URL:                 rekorV3Srv.URL,
		MajorAPIVersion:     3,
		ValidityPeriodStart: time.Now().Add(-2 * time.Hour),
		ValidityPeriodEnd:   time.Now().Add(-time.Hour),
	})
	emptySC := makeTestSigningConfig(t)

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	mldsa44KP, err := sign.NewMLDSAKeypair()
	if err != nil {
		t.Fatalf("NewMLDSAKeypair: %v", err)
	}
	mldsa65Priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey(65): %v", err)
	}
	mldsa87Priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey(87): %v", err)
	}
	wrongLogPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey(wrong): %v", err)
	}
	wrongTM := &mockSignTrustedMaterial{
		rekorLog: &root.TransparencyLog{
			BaseURL:   "https://rekor-v3.local",
			PublicKey: wrongLogPriv.Public(),
		},
	}

	plain := &sign.PlainData{Data: []byte("payload")}
	oidcCred := &sign.OIDCCredential{Token: "token"}

	testCases := []struct {
		name        string
		content     sign.Content
		cred        sign.IdentityCredential
		sc          *root.SigningConfig
		tm          root.TrustedMaterial
		wantErrText string
	}{
		{"nil content", nil, oidcCred, validSC, nil, "content must not be nil"},
		{"typed nil PlainData content", (*sign.PlainData)(nil), oidcCred, validSC, nil, "content must not be nil"},
		{"nil credential", plain, nil, validSC, nil, "credential must not be nil"},
		{"typed nil OIDC credential", plain, (*sign.OIDCCredential)(nil), validSC, nil, "credential must not be nil"},
		{"typed nil PublicKey credential", plain, (*sign.PublicKeyCredential)(nil), validSC, nil, "credential must not be nil"},
		{"PublicKey credential with nil keypair", plain, &sign.PublicKeyCredential{}, validSC, nil, "public key credential keypair must not be nil"},
		{"PublicKey credential with typed nil keypair", plain, &sign.PublicKeyCredential{Keypair: (*sign.MLDSAKeypair)(nil)}, validSC, nil, "public key credential keypair must not be nil"},
		{"nil signing config", plain, oidcCred, nil, nil, "signing config is required"},
		{"typed nil trusted material rejected before network call", plain, oidcCred, validSC, (*root.TrustedRoot)(nil), "trusted material must not be nil"},
		{"empty Rekor URLs in signing config", plain, oidcCred, emptySC, nil, "no Rekor v3 transparency log"},
		{"Rekor v1 only signing config fails closed", plain, oidcCred, v1OnlySC, nil, "selecting Rekor v3 transparency log"},
		{"Rekor v2 only signing config fails closed", plain, oidcCred, v2OnlySC, nil, "selecting Rekor v3 transparency log"},
		{"expired Rekor v3 signing config fails closed", plain, oidcCred, expiredV3SC, nil, "selecting Rekor v3 transparency log"},
		{"ECDSA key rejected for PQC transparent signing", plain, &sign.PublicKeyCredential{Keypair: &staticKeypair{pubKey: &ecdsaPriv.PublicKey}}, validSC, nil, "requires an ML-DSA-44 key"},
		{"ML-DSA-65 key rejected with future-support message", plain, &sign.PublicKeyCredential{Keypair: &staticKeypair{pubKey: mldsa65Priv.Public()}}, validSC, nil, "mldsa-65 and mldsa-87 will be supported in the future"},
		{"ML-DSA-87 key rejected with future-support message", plain, &sign.PublicKeyCredential{Keypair: &staticKeypair{pubKey: mldsa87Priv.Public()}}, validSC, nil, "mldsa-65 and mldsa-87 will be supported in the future"},
		{"typed nil ML-DSA public key rejected without panic", plain, &sign.PublicKeyCredential{Keypair: &staticKeypair{pubKey: (*mldsa.PublicKey)(nil)}}, validSC, nil, "invalid ML-DSA public key"},
		{"uninitialized ML-DSA public key rejected without panic", plain, &sign.PublicKeyCredential{Keypair: &staticKeypair{pubKey: &mldsa.PublicKey{}}}, validSC, nil, "invalid ML-DSA public key"},
		{"mismatched TrustedMaterial fails self-verification for OIDC", plain, oidcCred, validSC, wrongTM, "error signing identity bundle"},
		{"mismatched TrustedMaterial fails self-verification for PublicKey", plain, &sign.PublicKeyCredential{Keypair: mldsa44KP}, validSC, wrongTM, "error signing identity bundle"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SignIdentityData(context.Background(), tc.content, tc.cred, tc.sc, tc.tm)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrText)
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErrText, err)
			}
		})
	}
}

func TestSignData_RejectsMLDSAForV1Bundles(t *testing.T) {
	sc := makeTestSigningConfig(t)
	content := &sign.PlainData{Data: []byte("hello")}

	t.Run("ML-DSA-44 keypair rejected immediately", func(t *testing.T) {
		kp, err := sign.NewMLDSAKeypair()
		if err != nil {
			t.Fatalf("NewMLDSAKeypair: %v", err)
		}
		_, err = SignData(context.Background(), content, kp, "", nil, nil, sc, nil, SignOptions{})
		if err == nil {
			t.Fatal("expected error when signing v1 bundle with ML-DSA key")
		}
		if !strings.Contains(err.Error(), "ML-DSA keys are not supported for v1 bundles") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
		alg    protocommon.PublicKeyDetails
	}{
		{name: "ML-DSA-65", params: mldsa.MLDSA65(), alg: protocommon.PublicKeyDetails_ML_DSA_65},
		{name: "ML-DSA-87", params: mldsa.MLDSA87(), alg: protocommon.PublicKeyDetails_ML_DSA_87},
	} {
		t.Run(tc.name+" keypair rejected", func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tc.params)
			if err != nil {
				t.Fatalf("mldsa.GenerateKey: %v", err)
			}
			stub := &staticKeypair{pubKey: priv.Public(), sigAlg: tc.alg}
			_, err = SignData(context.Background(), content, stub, "", nil, nil, sc, nil, SignOptions{})
			if err == nil || !strings.Contains(err.Error(), "ML-DSA keys are not supported for v1 bundles") {
				t.Fatalf("expected ML-DSA rejection error, got: %v", err)
			}
		})
	}

	t.Run("ML-DSA PEM keypair with nil GetPublicKey and idToken rejected before Fulcio", func(t *testing.T) {
		kp, err := sign.NewMLDSAKeypair()
		if err != nil {
			t.Fatalf("NewMLDSAKeypair: %v", err)
		}
		pubPEM, err := kp.GetPublicKeyPem()
		if err != nil {
			t.Fatalf("GetPublicKeyPem: %v", err)
		}
		stub := &staticKeypair{
			pubKey: nil,
			pubPEM: pubPEM,
			sigAlg: protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
		}
		_, err = SignData(context.Background(), content, stub, "fake-oidc-token", nil, nil, sc, nil, SignOptions{})
		if err == nil || !strings.Contains(err.Error(), "ML-DSA keys are not supported for v1 bundles") {
			t.Fatalf("expected ML-DSA rejection error, got: %v", err)
		}
	})

	t.Run("ML-DSA certificate rejected in v1 SignData", func(t *testing.T) {
		mldsaPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			t.Fatalf("mldsa.GenerateKey: %v", err)
		}
		ecdsaKP, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			t.Fatalf("NewEphemeralKeypair: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, mldsaPriv.Public(), mldsaPriv)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		_, err = SignData(context.Background(), content, ecdsaKP, "", certPEM, nil, sc, nil, SignOptions{})
		if err == nil || !strings.Contains(err.Error(), "ML-DSA certificates are not supported for v1 bundles") {
			t.Fatalf("expected ML-DSA certificate rejection error, got: %v", err)
		}
		// Trailing malformed PEM bytes must not bypass ML-DSA certificate rejection.
		_, err = SignData(context.Background(), content, ecdsaKP, "", append(certPEM, []byte("-----BEGIN CERTIFICATE-----\nnot-base64\n")...), nil, sc, nil, SignOptions{})
		if err == nil || !strings.Contains(err.Error(), "ML-DSA certificates are not supported for v1 bundles") {
			t.Fatalf("expected ML-DSA rejection with trailing PEM garbage, got: %v", err)
		}
		// Classical leaf signed by an ML-DSA CA must also be rejected (SignatureAlgorithm check).
		hybridDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, ecdsaKP.GetPublicKey(), mldsaPriv)
		if err != nil {
			t.Fatalf("CreateCertificate(hybrid): %v", err)
		}
		hybridPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hybridDER})
		_, err = SignData(context.Background(), content, ecdsaKP, "", hybridPEM, nil, sc, nil, SignOptions{})
		if err == nil || !strings.Contains(err.Error(), "ML-DSA certificates are not supported for v1 bundles") {
			t.Fatalf("expected ML-DSA-signed cert rejection, got: %v", err)
		}
		// Custom CertificateProvider returning an ML-DSA-signed cert must also be rejected.
		_, err = SignData(context.Background(), content, ecdsaKP, "", nil, nil, sc, nil, SignOptions{
			CertificateProvider: &localCertProvider{cert: hybridPEM},
		})
		if err == nil || !strings.Contains(err.Error(), "ML-DSA certificates are not supported for v1 bundles") {
			t.Fatalf("expected CertificateProvider ML-DSA cert rejection, got: %v", err)
		}
	})
}
