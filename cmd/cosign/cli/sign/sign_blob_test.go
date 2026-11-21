// Copyright 2024 The Sigstore Authors.
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

package sign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	sumdbNote "golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestSignBlobCmd(t *testing.T) {
	td := t.TempDir()
	bundlePath := filepath.Join(td, "bundle.sigstore.json")

	keys, _ := cosign.GenerateKeyPair(nil)
	keyRef := writeFile(t, td, string(keys.PrivateBytes), "key.pem")

	blob := []byte("foo")
	blobPath := writeFile(t, td, string(blob), "foo.txt")

	rootOpts := &options.RootOptions{}
	keyOpts := options.KeyOpts{KeyRef: keyRef, BundlePath: bundlePath}

	// Test happy path
	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", ""); err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	assertOfflineBundle(t, bundlePath)

	// Test signing with a certificate
	rootCert, rootKey, _ := test.GenerateRootCa()
	cert, certPrivKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", rootCert, rootKey)
	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	signCertPath := writeFile(t, td, string(certPemBytes), "cert.pem")
	x509Encoded, err := x509.MarshalPKCS8PrivateKey(certPrivKey)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	encBytes, err := encrypted.Encrypt(x509Encoded, nil)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  cosign.SigstorePrivateKeyPemType,
	})
	certPrivKeyRef := writeFile(t, td, string(pemBytes), "certkey.pem")
	keyOpts.KeyRef = certPrivKeyRef

	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, signCertPath, ""); err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x509Encoded, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	encBytes, err = encrypted.Encrypt(x509Encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  cosign.SigstorePrivateKeyPemType,
	})

	// Test signing using Ed25519 key with custom signing config and no transparency log upload
	edKeyRef := writeFile(t, td, string(pemBytes), "ed_key.pem")
	keyOpts = options.KeyOpts{
		KeyRef:        edKeyRef,
		BundlePath:    bundlePath,
		SigningConfig: signcommon.NewEmptySigningConfig(),
	}
	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", ""); err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	assertEd25519Sig(t, pub, blob, readBundleSignature(t, bundlePath))

	// Test signing using Ed25519 key with default signing config and no transparency log upload
	keyOpts = options.KeyOpts{KeyRef: edKeyRef, BundlePath: bundlePath}
	if err := SignBlobCmd(t.Context(), rootOpts, keyOpts, blobPath, "", ""); err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	assertEd25519Sig(t, pub, blob, readBundleSignature(t, bundlePath))
}

func writeFile(t *testing.T, td string, blob string, name string) string {
	// Write blob to disk
	blobPath := filepath.Join(td, name)
	if err := os.WriteFile(blobPath, []byte(blob), 0o644); err != nil {
		t.Fatal(err)
	}
	return blobPath
}

func readBundleSignature(t *testing.T, bundlePath string) []byte {
	t.Helper()
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("failed to read bundle: %v", err)
	}
	var bundle struct {
		MessageSignature struct {
			Signature string `json:"signature"`
		} `json:"messageSignature"`
	}
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatalf("failed to unmarshal bundle: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(bundle.MessageSignature.Signature)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}
	return sig
}

func assertOfflineBundle(t *testing.T, bundlePath string) {
	t.Helper()
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("failed to read bundle: %v", err)
	}
	var bundle protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatalf("failed to unmarshal bundle: %v", err)
	}
	vm := bundle.GetVerificationMaterial()
	// Public key hint rules out a certificate or certificate chain (content is a oneof field).
	if vm.GetPublicKey() == nil {
		t.Errorf("expected a public key hint, got %T", vm.GetContent())
	}
	if n := len(vm.GetTlogEntries()); n != 0 {
		t.Errorf("expected no transparency log entries, got %d", n)
	}
	if n := len(vm.GetTimestampVerificationData().GetRfc3161Timestamps()); n != 0 {
		t.Errorf("expected no RFC 3161 timestamps, got %d", n)
	}
}

func assertEd25519Sig(t *testing.T, pub ed25519.PublicKey, msg, sig []byte) {
	t.Helper()
	if ed25519.Verify(pub, msg, sig) {
		return
	}
	errString := "expected ed25519 signature"
	if ed25519.VerifyWithOptions(pub, msg, sig, &ed25519.Options{Hash: crypto.SHA512}) == nil {
		errString += ", received ed25519ph signature"
	}
	t.Fatal("signature verification failed: " + errString)
}

func startTestRekorV3Server(t *testing.T) *root.SigningConfig {
	t.Helper()
	logPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	const origin = "rekor-v3.local"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/log/entries" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
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
			http.Error(w, "expected 32-byte digest", http.StatusBadRequest)
			return
		}
		msgHash := sha256.Sum256(req.GetMessage())
		leafHash := rfc6962.DefaultHasher.HashLeaf(msgHash[:])
		cp := formatsLog.Checkpoint{Origin: origin, Size: 1, Hash: leafHash}
		signer, err := signature.LoadDefaultSigner(logPriv)
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
		p := proof.TLogProof{Index: 0, Checkpoint: signedNote}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(p.Marshal())
	}))
	t.Cleanup(srv.Close)

	sc, err := root.NewSigningConfig(
		root.SigningConfigMediaType02, nil, nil,
		[]root.Service{{URL: srv.URL, MajorAPIVersion: 3, ValidityPeriodStart: time.Now().Add(-time.Hour)}},
		root.ServiceConfiguration{}, nil, root.ServiceConfiguration{},
	)
	if err != nil {
		t.Fatalf("NewSigningConfig: %v", err)
	}
	return sc
}

func TestSignBlobCmd_ExperimentalPQC(t *testing.T) {
	sc := startTestRekorV3Server(t)

	td := t.TempDir()
	blobPath := writeFile(t, td, "hello pqc blob", "blob.txt")

	algo, err := signature.GetAlgorithmDetails(v1.PublicKeyDetails_ML_DSA_44)
	if err != nil {
		t.Fatalf("GetAlgorithmDetails: %v", err)
	}
	keys, err := cosign.GenerateKeyPairWithAlgorithm(&algo, nil)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithAlgorithm: %v", err)
	}
	mldsaKeyPath := writeFile(t, td, string(keys.PrivateBytes), "mldsa44.key")
	// Use zero Timeout to verify SignBlobCmd does not cancel ctx immediately.
	rootOpts := &options.RootOptions{}

	t.Run("OIDC PQC sign-blob produces v2 bundle", func(t *testing.T) {
		outPath := filepath.Join(td, "oidc-v2.sigstore.json")
		tokenPath := writeFile(t, td, "test-id-token", "oidc-token")
		ko := options.KeyOpts{
			ExperimentalPQC:  true,
			IDToken:          tokenPath,
			BundlePath:       outPath,
			SigningConfig:    sc,
			SkipConfirmation: true,
		}
		if err := SignBlobCmd(t.Context(), rootOpts, ko, blobPath, "", ""); err != nil {
			t.Fatalf("SignBlobCmd: %v", err)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatalf("stat bundle: %v", err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("expected 0600 bundle perms, got %o", info.Mode().Perm())
			}
		}
		b, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read bundle: %v", err)
		}
		var pb bundleV2.Bundle
		if err := protojson.Unmarshal(b, &pb); err != nil {
			t.Fatalf("protojson.Unmarshal: %v", err)
		}
		if pb.GetMediaType() != cbundle.BundleV20MediaType {
			t.Errorf("MediaType = %q, want %q", pb.GetMediaType(), cbundle.BundleV20MediaType)
		}
		if pb.GetPayload() != nil {
			t.Error("expected nil payload for blob v2 bundle")
		}
		if pb.GetVerificationMaterial().GetTransparencyLogProof().GetSignature() != nil {
			t.Error("expected nil signature for OIDC v2 bundle")
		}
	})

	t.Run("managed ML-DSA-44 key PQC sign-blob produces v2 bundle", func(t *testing.T) {
		outPath := filepath.Join(td, "key-v2.sigstore.json")
		ko := options.KeyOpts{
			ExperimentalPQC:  true,
			KeyRef:           mldsaKeyPath,
			BundlePath:       outPath,
			SigningConfig:    sc,
			SkipConfirmation: true,
		}
		if err := SignBlobCmd(t.Context(), nil, ko, blobPath, "", ""); err != nil {
			t.Fatalf("SignBlobCmd: %v", err)
		}
		if runtime.GOOS != "windows" {
			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatalf("stat bundle: %v", err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("expected 0600 bundle perms, got %o", info.Mode().Perm())
			}
		}
		b, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read bundle: %v", err)
		}
		var pb bundleV2.Bundle
		if err := protojson.Unmarshal(b, &pb); err != nil {
			t.Fatalf("protojson.Unmarshal: %v", err)
		}
		if pb.GetMediaType() != cbundle.BundleV20MediaType {
			t.Errorf("MediaType = %q, want %q", pb.GetMediaType(), cbundle.BundleV20MediaType)
		}
		if len(pb.GetVerificationMaterial().GetTransparencyLogProof().GetSignature().GetSignature()) == 0 {
			t.Error("expected non-empty signature for managed-key v2 bundle")
		}
	})

	t.Run("PQC sign-blob rejects empty BundlePath before signing", func(t *testing.T) {
		ko := options.KeyOpts{ExperimentalPQC: true, KeyRef: mldsaKeyPath, SigningConfig: sc}
		err := SignBlobCmd(t.Context(), rootOpts, ko, blobPath, "", "")
		if err == nil || !strings.Contains(err.Error(), "--bundle path is required") {
			t.Fatalf("expected --bundle required error, got: %v", err)
		}
	})

	t.Run("default v1 sign-blob rejects ML-DSA-44 key", func(t *testing.T) {
		outPath := filepath.Join(td, "v1-mldsa.sigstore.json")
		ko := options.KeyOpts{
			KeyRef:        mldsaKeyPath,
			BundlePath:    outPath,
			SigningConfig: signcommon.NewEmptySigningConfig(),
		}
		err := SignBlobCmd(t.Context(), rootOpts, ko, blobPath, "", "")
		if err == nil {
			t.Fatal("expected v1 SignBlobCmd to reject ML-DSA-44 key")
		}
		if !strings.Contains(err.Error(), "ML-DSA keys are not supported for v1 bundles") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
