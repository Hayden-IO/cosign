// Copyright 2025 The Sigstore Authors.
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

package signcommon

import (
	"context"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign/privacy"
	"github.com/sigstore/cosign/v3/internal/test"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	pbrekor "github.com/sigstore/rekor-tiles/v2/pkg/generated/protobuf"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	formatsLog "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	sumdbNote "golang.org/x/mod/sumdb/note"
	"google.golang.org/protobuf/encoding/protojson"
)

func pass(s string) cosign.PassFunc {
	return func(_ bool) ([]byte, error) {
		return []byte(s), nil
	}
}

func generateCertificateFiles(t *testing.T, tmpDir string, pf cosign.PassFunc) (privFile, certFile, chainFile string, privKey *ecdsa.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate) {
	t.Helper()

	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, privKey, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	pemRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	pemSub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCert.Raw})
	pemLeaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}
	password := []byte{}
	if pf != nil {
		password, err = pf(true)
		if err != nil {
			t.Fatalf("failed to read password: %v", err)
		}
	}

	encBytes, err := encrypted.Encrypt(x509Encoded, password)
	if err != nil {
		t.Fatalf("failed to encrypt key: %v", err)
	}

	// store in PEM format
	privBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  cosign.CosignPrivateKeyPemType,
	})

	tmpPrivFile, err := os.CreateTemp(tmpDir, "cosign_test_*.key")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer tmpPrivFile.Close()
	if _, err := tmpPrivFile.Write(privBytes); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	tmpCertFile, err := os.CreateTemp(tmpDir, "cosign.crt")
	if err != nil {
		t.Fatalf("failed to create temp certificate file: %v", err)
	}
	defer tmpCertFile.Close()
	if _, err := tmpCertFile.Write(pemLeaf); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}

	tmpChainFile, err := os.CreateTemp(tmpDir, "cosign_chain.crt")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	pemChain := pemSub
	pemChain = append(pemChain, pemRoot...)
	if _, err := tmpChainFile.Write(pemChain); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	return tmpPrivFile.Name(), tmpCertFile.Name(), tmpChainFile.Name(), privKey, leafCert, []*x509.Certificate{subCert, rootCert}
}

func Test_signerFromKeyRefSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, chainFile, privKey, cert, chain := generateCertificateFiles(t, tmpDir, pass("foo"))

	signer, err := signerFromKeyRef(ctx, certFile, chainFile, keyFile, pass("foo"), nil)
	if err != nil {
		t.Fatalf("unexpected error generating signer: %v", err)
	}
	// Expect public key matches
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("unexpected error fetching pubkey: %v", err)
	}
	if !privKey.Public().(*ecdsa.PublicKey).Equal(pubKey) {
		t.Fatalf("public keys must be equal")
	}
	// Expect certificate matches
	expectedPemBytes, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate: %v", err)
	}
	if !reflect.DeepEqual(signer.Cert, expectedPemBytes) {
		t.Fatalf("certificates must match")
	}
	// Expect certificate chain matches
	expectedPemBytesChain, err := cryptoutils.MarshalCertificatesToPEM(chain)
	if err != nil {
		t.Fatalf("unexpected error marshalling certificate chain: %v", err)
	}
	if !reflect.DeepEqual(signer.Chain, expectedPemBytesChain) {
		t.Fatalf("certificate chains must match")
	}
}

func Test_signerFromKeyRefFailure(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, _, _, _, _ := generateCertificateFiles(t, tmpDir, pass("foo"))
	// Second set of files
	tmpDir2 := t.TempDir()
	_, certFile2, chainFile2, _, _, _ := generateCertificateFiles(t, tmpDir2, pass("bar"))

	// Public keys don't match
	_, err := signerFromKeyRef(ctx, certFile2, chainFile2, keyFile, pass("foo"), nil)
	if err == nil || err.Error() != "public key in certificate does not match the provided public key" {
		t.Fatalf("expected mismatched keys error, got %v", err)
	}
	// Certificate chain cannot be verified
	_, err = signerFromKeyRef(ctx, certFile, chainFile2, keyFile, pass("foo"), nil)
	if err == nil || !strings.Contains(err.Error(), "unable to validate certificate chain") {
		t.Fatalf("expected chain verification error, got %v", err)
	}
	// Certificate chain specified without certificate
	_, err = signerFromKeyRef(ctx, "", chainFile2, keyFile, pass("foo"), nil)
	if err == nil || !strings.Contains(err.Error(), "no leaf certificate found or provided while specifying chain") {
		t.Fatalf("expected no leaf error, got %v", err)
	}
}

func Test_signerFromKeyRefFailureEmptyChainFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	keyFile, certFile, _, _, _, _ := generateCertificateFiles(t, tmpDir, pass("foo"))

	tmpChainFile, err := os.CreateTemp(tmpDir, "cosign_chain_empty.crt")
	if err != nil {
		t.Fatalf("failed to create temp chain file: %v", err)
	}
	defer tmpChainFile.Close()
	if _, err := tmpChainFile.Write([]byte{}); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	_, err = signerFromKeyRef(ctx, certFile, tmpChainFile.Name(), keyFile, pass("foo"), nil)
	if err == nil || err.Error() != "no certificates in certificate chain" {
		t.Fatalf("expected empty chain error, got %v", err)
	}
}

func Test_ParseOCIReference(t *testing.T) {
	var tests = []struct {
		ref             string
		expectedWarning string
	}{
		{"image:bytag", "WARNING: Image reference image:bytag uses a tag, not a digest"},
		{"image:bytag@sha256:abcdef", ""},
		{"image:@sha256:abcdef", ""},
	}
	for _, tt := range tests {
		stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
			ParseOCIReference(ctx, tt.ref)
		})
		if len(tt.expectedWarning) > 0 {
			assert.Contains(t, stderr, tt.expectedWarning, stderr, "bad warning message")
		} else {
			assert.Empty(t, stderr, "expected no warning")
		}
	}
}

func mustSigningConfigWithRekor(t *testing.T, rekorURL string) *root.SigningConfig {
	t.Helper()
	sc := NewEmptySigningConfig()
	if rekorURL != "" {
		sc = sc.WithRekorLogURLs(root.Service{
			URL:                 rekorURL,
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now(),
		}).WithRekorTlogConfig(prototrustroot.ServiceSelector_ANY, 1)
	}
	return sc
}

func mustSigningConfigWithFulcio(t *testing.T, fulcioURL string) *root.SigningConfig {
	t.Helper()
	sc := NewEmptySigningConfig()
	if fulcioURL != "" {
		sc = sc.WithFulcioCertificateAuthorityURLs(root.Service{
			URL:                 fulcioURL,
			MajorAPIVersion:     1,
			ValidityPeriodStart: time.Now(),
		})
	}
	return sc
}

func assertEmptySigningConfig(t *testing.T, sc *root.SigningConfig) {
	t.Helper()
	if !assert.NotNil(t, sc) {
		return
	}
	assert.Empty(t, sc.FulcioCertificateAuthorityURLs())
	assert.Empty(t, sc.OIDCProviderURLs())
	assert.Empty(t, sc.RekorLogURLs())
	assert.Empty(t, sc.TimestampAuthorityURLs())
}

func TestConfirmPrivacyStatement(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *root.SigningConfig
		keyRef        string
		sk            bool
		wantWarning   bool
	}{
		{
			name:          "custom Rekor URL with key skips public instance statement",
			signingConfig: mustSigningConfigWithRekor(t, "http://localhost:3000"),
			keyRef:        "cosign.key",
			wantWarning:   false,
		},
		{
			name:          "region-specific public good Rekor URL shows public instance statement",
			signingConfig: mustSigningConfigWithRekor(t, "https://rekor.us-central1.sigstore.dev"),
			keyRef:        "cosign.key",
			wantWarning:   true,
		},
		{
			name:          "staging public good Rekor URL shows public instance statement",
			signingConfig: mustSigningConfigWithRekor(t, "https://rekor.sigstage.dev"),
			keyRef:        "cosign.key",
			wantWarning:   true,
		},
		{
			name:          "cleared public good Rekor URL with key skips statement",
			signingConfig: mustSigningConfigWithRekor(t, options.DefaultRekorURL).WithRekorLogURLs(),
			keyRef:        "cosign.key",
			wantWarning:   false,
		},
		{
			name:          "keyless with public good Fulcio URL shows public instance statement",
			signingConfig: mustSigningConfigWithFulcio(t, options.DefaultFulcioURL),
			wantWarning:   true,
		},
		{
			name:          "keyless with staging public good Fulcio URL shows public instance statement",
			signingConfig: mustSigningConfigWithFulcio(t, "https://fulcio.sigstage.dev"),
			wantWarning:   true,
		},
		{
			name:          "keyless with custom Fulcio URL skips public instance statement",
			signingConfig: mustSigningConfigWithFulcio(t, "http://localhost:5555"),
			wantWarning:   false,
		},
		{
			name:          "public good Fulcio URL with key and without Rekor URL skips statement",
			signingConfig: mustSigningConfigWithFulcio(t, options.DefaultFulcioURL),
			keyRef:        "cosign.key",
			wantWarning:   false,
		},
		{
			name:          "nil signing config skips public instance statement",
			signingConfig: nil,
			wantWarning:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privacy.StatementOnce = sync.Once{}
			ko := options.KeyOpts{
				KeyRef:           tt.keyRef,
				Sk:               tt.sk,
				SigningConfig:    tt.signingConfig,
				SkipConfirmation: true,
			}
			var err error
			stderr := ui.RunWithTestCtx(func(ctx context.Context, _ ui.WriteFunc) {
				err = ConfirmPrivacyStatement(ctx, ko)
			})
			assert.NoError(t, err)
			if tt.wantWarning {
				assert.Contains(t, stderr, "hosted by sigstore", "should warn about the public good instance's data retention policy")
			} else {
				assert.NotContains(t, stderr, "hosted by sigstore", "should not warn about the public good instance's data retention policy")
			}
		})
	}
}

func TestShouldUploadToTlog(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *root.SigningConfig
		tlogUpload    bool
		wantUpload    bool
	}{
		{
			name:          "tlogUpload false returns false",
			signingConfig: mustSigningConfigWithRekor(t, options.DefaultRekorURL),
			tlogUpload:    false,
			wantUpload:    false,
		},
		{
			name:          "signing config with no Rekor URLs returns false",
			signingConfig: mustSigningConfigWithRekor(t, options.DefaultRekorURL).WithRekorLogURLs(),
			tlogUpload:    true,
			wantUpload:    false,
		},
		{
			name:          "tlogUpload true with Rekor URL returns true",
			signingConfig: mustSigningConfigWithRekor(t, "http://localhost:3000"),
			tlogUpload:    true,
			wantUpload:    true,
		},
		{
			name:          "nil signing config with tlogUpload true returns true",
			signingConfig: nil,
			tlogUpload:    true,
			wantUpload:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ko := options.KeyOpts{
				SigningConfig:    tt.signingConfig,
				SkipConfirmation: true,
			}
			upload := ShouldUploadToTlog(context.Background(), ko, nil, tt.tlogUpload)
			assert.Equal(t, tt.wantUpload, upload)
		})
	}
}

func TestHasPublicGoodRekorURL(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *root.SigningConfig
		want          bool
	}{
		{"nil signing config returns false", nil, false},
		{"empty signing config returns false", mustSigningConfigWithRekor(t, ""), false},
		{"custom Rekor URL returns false", mustSigningConfigWithRekor(t, "http://localhost:3000"), false},
		{"public good Rekor URL returns true", mustSigningConfigWithRekor(t, options.DefaultRekorURL), true},
		{"signing config with cleared Rekor URLs returns false", mustSigningConfigWithRekor(t, options.DefaultRekorURL).WithRekorLogURLs(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasPublicGoodRekorURL(tt.signingConfig))
		})
	}
}

func TestHasPublicGoodFulcioURL(t *testing.T) {
	tests := []struct {
		name          string
		signingConfig *root.SigningConfig
		want          bool
	}{
		{"nil signing config returns false", nil, false},
		{"empty signing config returns false", mustSigningConfigWithFulcio(t, ""), false},
		{"custom Fulcio URL returns false", mustSigningConfigWithFulcio(t, "http://localhost:5555"), false},
		{"public good Fulcio URL returns true", mustSigningConfigWithFulcio(t, options.DefaultFulcioURL), true},
		{"staging public good Fulcio URL returns true", mustSigningConfigWithFulcio(t, "https://fulcio.sigstage.dev"), true},
		{"signing config with cleared Fulcio URLs returns false", mustSigningConfigWithFulcio(t, options.DefaultFulcioURL).WithFulcioCertificateAuthorityURLs(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasPublicGoodFulcioURL(tt.signingConfig))
		})
	}
}

func TestIsPublicGoodURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"empty is not public good", "", false},
		{"default Rekor production URL", options.DefaultRekorURL, true},
		{"default Fulcio production URL", options.DefaultFulcioURL, true},
		{"region-specific production URL", "https://rekor.us-central1.sigstore.dev", true},
		{"staging Rekor URL", "https://rekor.sigstage.dev", true},
		{"staging Fulcio URL", "https://fulcio.sigstage.dev", true},
		{"region-specific staging URL", "https://rekor.us-central1.sigstage.dev", true},
		{"custom self-hosted URL", "http://localhost:3000", false},
		{"uppercase hostname is still public good", "https://REKOR.SIGSTORE.DEV", true},
		{"lookalike domain is not public good", "https://sigstore.dev.evil.example.com", false},
		{"lookalike suffix without dot boundary is not public good", "https://notsigstore.dev", false},
		{"unparseable URL", "://bad-url", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isPublicGoodURL(tt.url))
		})
	}
}

func TestLoadSigningConfigAndTrustedMaterial(t *testing.T) {
	ctx := t.Context()

	t.Run("empty signing config file bypasses TUF and leaves TrustedMaterial nil", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		sc := NewEmptySigningConfig()
		scBytes, err := sc.MarshalJSON()
		assert.NoError(t, err)

		scPath := filepath.Join(t.TempDir(), "empty_signing_config.json")
		assert.NoError(t, os.WriteFile(scPath, scBytes, 0600))

		ko := options.KeyOpts{KeyRef: "cosign.key"}
		err = LoadSigningConfigAndTrustedMaterial(ctx, &ko, false, scPath, "")
		assert.NoError(t, err)
		assert.NotNil(t, ko.SigningConfig)
		assert.Nil(t, ko.TrustedMaterial)

		entries, err := os.ReadDir(tufDir)
		assert.NoError(t, err)
		assert.Empty(t, entries, "expected TUF directory to remain empty when signing config has no services")
	})

	t.Run("noSigningConfig true with explicit trusted root loads TrustedMaterial without contacting TUF", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		trPath := filepath.Join(t.TempDir(), "trusted_root.json")
		trJSON := `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`
		assert.NoError(t, os.WriteFile(trPath, []byte(trJSON), 0600))

		ko := options.KeyOpts{KeyRef: "cosign.key"}
		err := LoadSigningConfigAndTrustedMaterial(ctx, &ko, true, "", trPath)
		assert.NoError(t, err)
		assertEmptySigningConfig(t, ko.SigningConfig)
		assert.NotNil(t, ko.TrustedMaterial)

		entries, err := os.ReadDir(tufDir)
		assert.NoError(t, err)
		assert.Empty(t, entries, "expected TUF directory to remain empty when explicit trusted root is provided")
	})

	t.Run("invalid signing config path fails fast without contacting TUF", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		ko := options.KeyOpts{KeyRef: "cosign.key"}
		err := LoadSigningConfigAndTrustedMaterial(ctx, &ko, false, "/nonexistent/signing_config.json", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error reading signing config from file")

		entries, err := os.ReadDir(tufDir)
		assert.NoError(t, err)
		assert.Empty(t, entries, "expected TUF directory to remain empty when signing config path is invalid")
	})

	t.Run("noSigningConfig true with no signing config and no key ref sets empty signing config and bypasses TUF", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		ko := options.KeyOpts{KeyRef: ""}
		var err error
		stderr := ui.RunWithTestCtx(func(c context.Context, _ ui.WriteFunc) {
			err = LoadSigningConfigAndTrustedMaterial(c, &ko, true, "", "")
		})
		assert.NoError(t, err)
		assertEmptySigningConfig(t, ko.SigningConfig)
		assert.Nil(t, ko.TrustedMaterial)
		assert.NotContains(t, stderr, "Could not fetch trusted_root.json from the TUF repository.")
	})

	t.Run("noSigningConfig true with no signing config and key ref sets empty signing config and bypasses TUF", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		ko := options.KeyOpts{KeyRef: "cosign.key"}
		err := LoadSigningConfigAndTrustedMaterial(ctx, &ko, true, "", "")
		assert.NoError(t, err)
		assertEmptySigningConfig(t, ko.SigningConfig)
		assert.Nil(t, ko.TrustedMaterial)

		entries, err := os.ReadDir(tufDir)
		assert.NoError(t, err)
		assert.Empty(t, entries, "expected TUF directory to remain empty")
	})

	t.Run("signing config with services triggers TUF fetch", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		sc := mustSigningConfigWithFulcio(t, "https://fulcio.example.com")
		scBytes, err := sc.MarshalJSON()
		assert.NoError(t, err)

		scPath := filepath.Join(t.TempDir(), "signing_config.json")
		assert.NoError(t, os.WriteFile(scPath, scBytes, 0600))

		ko := options.KeyOpts{KeyRef: "cosign.key"}
		var loadErr error
		stderr := ui.RunWithTestCtx(func(c context.Context, _ ui.WriteFunc) {
			loadErr = LoadSigningConfigAndTrustedMaterial(c, &ko, false, scPath, "")
		})
		assert.NoError(t, loadErr)
		assert.NotNil(t, ko.SigningConfig)
		assert.Nil(t, ko.TrustedMaterial)
		assert.Contains(t, stderr, "Could not fetch trusted_root.json from the TUF repository. Continuing without trusted root.")
	})

	t.Run("invalid trusted root path returns error", func(t *testing.T) {
		ko := options.KeyOpts{KeyRef: "cosign.key"}
		err := LoadSigningConfigAndTrustedMaterial(ctx, &ko, true, "", "/nonexistent/trusted_root.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "loading trusted root")
	})

	t.Run("noSigningConfig false fails when TUF signing config cannot be retrieved", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", tufDir)

		ko := options.KeyOpts{KeyRef: "cosign.key"}
		err := LoadSigningConfigAndTrustedMaterial(ctx, &ko, false, "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "getting signing config from TUF")
	})
}

func TestRequireFulcioForCertificate(t *testing.T) {
	withFulcio := mustSigningConfigWithFulcio(t, options.DefaultFulcioURL)
	withoutFulcio := mustSigningConfigWithRekor(t, options.DefaultRekorURL)

	tests := []struct {
		name          string
		ko            options.KeyOpts
		wantErrSubstr string
	}{
		{
			name: "keyless with Fulcio",
			ko:   options.KeyOpts{SigningConfig: withFulcio},
		},
		{
			name:          "keyless without Fulcio",
			ko:            options.KeyOpts{SigningConfig: withoutFulcio},
			wantErrSubstr: "keyless signing requires a signing config with a Fulcio certificate authority",
		},
		{
			name:          "keyless with empty signing config",
			ko:            options.KeyOpts{SigningConfig: NewEmptySigningConfig()},
			wantErrSubstr: "keyless signing requires a signing config with a Fulcio certificate authority",
		},
		{
			name:          "keyless with nil signing config",
			ko:            options.KeyOpts{},
			wantErrSubstr: "keyless signing requires a signing config with a Fulcio certificate authority",
		},
		{
			name: "key without Fulcio",
			ko:   options.KeyOpts{KeyRef: "cosign.key", SigningConfig: withoutFulcio},
		},
		{
			name: "key with nil signing config",
			ko:   options.KeyOpts{KeyRef: "cosign.key"},
		},
		{
			name: "security key without Fulcio",
			ko:   options.KeyOpts{Sk: true, SigningConfig: withoutFulcio},
		},
		{
			name: "key with certificate and Fulcio",
			ko:   options.KeyOpts{KeyRef: "cosign.key", IssueCertificateForExistingKey: true, SigningConfig: withFulcio},
		},
		{
			name:          "key with certificate without Fulcio",
			ko:            options.KeyOpts{KeyRef: "cosign.key", IssueCertificateForExistingKey: true, SigningConfig: withoutFulcio},
			wantErrSubstr: "certificate-based signing requires a signing config with a Fulcio certificate authority",
		},
		{
			name:          "security key with certificate and nil signing config",
			ko:            options.KeyOpts{Sk: true, IssueCertificateForExistingKey: true},
			wantErrSubstr: "certificate-based signing requires a signing config with a Fulcio certificate authority",
		},
		{
			name: "experimental PQC keyless without Fulcio succeeds",
			ko:   options.KeyOpts{ExperimentalPQC: true, SigningConfig: withoutFulcio},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireFulcioForCertificate(tt.ko)
			if tt.wantErrSubstr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErrSubstr)
		})
	}
}

func makeRekorSigningConfig(t *testing.T, url string, majorVersion uint32) *root.SigningConfig {
	t.Helper()
	sc, err := root.NewSigningConfig(
		root.SigningConfigMediaType02, nil, nil,
		[]root.Service{{URL: url, MajorAPIVersion: majorVersion, ValidityPeriodStart: time.Now().Add(-time.Hour)}},
		root.ServiceConfiguration{}, nil, root.ServiceConfiguration{},
	)
	if err != nil {
		t.Fatalf("NewSigningConfig: %v", err)
	}
	return sc
}

func TestValidatePQCSigningOpts(t *testing.T) {
	v3SC := makeRekorSigningConfig(t, "http://127.0.0.1:1234", 3)
	v2SC := makeRekorSigningConfig(t, "http://127.0.0.1:1234", 2)
	expiredV3SC, err := root.NewSigningConfig(
		root.SigningConfigMediaType02, nil, nil,
		[]root.Service{{URL: "http://127.0.0.1:1234", MajorAPIVersion: 3, ValidityPeriodStart: time.Now().Add(-2 * time.Hour), ValidityPeriodEnd: time.Now().Add(-time.Hour)}},
		root.ServiceConfiguration{}, nil, root.ServiceConfiguration{},
	)
	assert.NoError(t, err)
	mixedSC, err := root.NewSigningConfig(
		root.SigningConfigMediaType02, nil, nil,
		[]root.Service{
			{URL: "http://127.0.0.1:1234", MajorAPIVersion: 2, ValidityPeriodStart: time.Now().Add(-time.Hour)},
			{URL: "http://127.0.0.1:1235", MajorAPIVersion: 3, ValidityPeriodStart: time.Now().Add(-time.Hour)},
		},
		root.ServiceConfiguration{}, nil, root.ServiceConfiguration{},
	)
	assert.NoError(t, err)

	tests := []struct {
		name      string
		ko        options.KeyOpts
		cert      string
		certChain string
		wantErr   string
	}{
		{"disabled skips checks", options.KeyOpts{Sk: true}, "c.pem", "chain.pem", ""},
		{"valid with Rekor v3", options.KeyOpts{ExperimentalPQC: true, SigningConfig: v3SC}, "", "", ""},
		{"valid with mixed Rekor v2 and v3", options.KeyOpts{ExperimentalPQC: true, SigningConfig: mixedSC}, "", "", ""},
		{"rejects --sk", options.KeyOpts{ExperimentalPQC: true, Sk: true, SigningConfig: v3SC}, "", "", "--sk"},
		{"rejects --certificate", options.KeyOpts{ExperimentalPQC: true, SigningConfig: v3SC}, "cert.pem", "", "--certificate"},
		{"rejects --certificate-chain", options.KeyOpts{ExperimentalPQC: true, SigningConfig: v3SC}, "", "chain.pem", "--certificate"},
		{"rejects --issue-certificate", options.KeyOpts{ExperimentalPQC: true, IssueCertificateForExistingKey: true, SigningConfig: v3SC}, "", "", "--issue-certificate"},
		{"rejects TSA CACert", options.KeyOpts{ExperimentalPQC: true, TSAClientCACert: "ca.pem", SigningConfig: v3SC}, "", "", "timestamp authority"},
		{"rejects TSA ClientCert", options.KeyOpts{ExperimentalPQC: true, TSAClientCert: "c.pem", SigningConfig: v3SC}, "", "", "timestamp authority"},
		{"rejects TSA ClientKey", options.KeyOpts{ExperimentalPQC: true, TSAClientKey: "k.pem", SigningConfig: v3SC}, "", "", "timestamp authority"},
		{"rejects TSA ServerName", options.KeyOpts{ExperimentalPQC: true, TSAServerName: "tsa.local", SigningConfig: v3SC}, "", "", "timestamp authority"},
		{"rejects --signing-algorithm", options.KeyOpts{ExperimentalPQC: true, SigningAlgorithm: "ecdsa-sha2-256-nistp256", SigningConfig: v3SC}, "", "", "--signing-algorithm"},
		{"rejects nil SigningConfig", options.KeyOpts{ExperimentalPQC: true}, "", "", "signing config"},
		{"rejects empty SigningConfig", options.KeyOpts{ExperimentalPQC: true, SigningConfig: NewEmptySigningConfig()}, "", "", "Rekor v3"},
		{"rejects Rekor v2 only", options.KeyOpts{ExperimentalPQC: true, SigningConfig: v2SC}, "", "", "Rekor v3"},
		{"rejects expired Rekor v3", options.KeyOpts{ExperimentalPQC: true, SigningConfig: expiredV3SC}, "", "", "Rekor v3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePQCSigningOpts(tc.ko, tc.cert, tc.certChain)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestWarnExperimentalPQCAndPrivacyStatement(t *testing.T) {
	var errBuf strings.Builder
	ctx := ui.WithEnv(t.Context(), &ui.Env{Stderr: &errBuf})
	WarnExperimentalPQC(ctx)
	assert.Contains(t, errBuf.String(), "EXPERIMENTAL PQC SIGNING ENABLED")

	// ConfirmPrivacyStatement triggers for PQC staging Rekor v3 (.sigstage.dev).
	privacy.StatementOnce = sync.Once{}
	t.Cleanup(func() { privacy.StatementOnce = sync.Once{} })

	var infoBuf strings.Builder
	ctx = ui.WithEnv(t.Context(), &ui.Env{Stderr: &infoBuf})
	stagingSC := makeRekorSigningConfig(t, "https://rekor.v2.sigstage.dev", 3)
	err := ConfirmPrivacyStatement(ctx, options.KeyOpts{
		ExperimentalPQC:  true,
		SigningConfig:    stagingSC,
		SkipConfirmation: true,
	})
	assert.NoError(t, err)
	assert.Contains(t, infoBuf.String(), privacy.Statement)
}

func TestGetIdentityCredential(t *testing.T) {
	td := t.TempDir()

	t.Run("rejects security key directly", func(t *testing.T) {
		_, _, err := GetIdentityCredential(t.Context(), options.KeyOpts{ExperimentalPQC: true, Sk: true})
		assert.ErrorContains(t, err, "--sk")
	})

	t.Run("keyless OIDC uses IDToken without generating key", func(t *testing.T) {
		tokenPath := filepath.Join(td, "id-token")
		if err := os.WriteFile(tokenPath, []byte("test-oidc-token"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cred, cleanup, err := GetIdentityCredential(t.Context(), options.KeyOpts{
			ExperimentalPQC: true,
			IDToken:         tokenPath,
		})
		if err != nil {
			t.Fatalf("GetIdentityCredential: %v", err)
		}
		defer cleanup()
		oidcCred, ok := cred.(*sign.OIDCCredential)
		assert.True(t, ok)
		assert.Equal(t, "test-oidc-token", oidcCred.Token)
	})

	t.Run("managed ML-DSA-44 key succeeds", func(t *testing.T) {
		algo, err := signature.GetAlgorithmDetails(v1.PublicKeyDetails_ML_DSA_44)
		assert.NoError(t, err)
		keys, err := cosign.GenerateKeyPairWithAlgorithm(&algo, pass("pqc"))
		assert.NoError(t, err)
		keyPath := filepath.Join(td, "mldsa44.key")
		assert.NoError(t, os.WriteFile(keyPath, keys.PrivateBytes, 0600))

		cred, cleanup, err := GetIdentityCredential(t.Context(), options.KeyOpts{
			ExperimentalPQC: true,
			KeyRef:          keyPath,
			PassFunc:        pass("pqc"),
		})
		if err != nil {
			t.Fatalf("GetIdentityCredential: %v", err)
		}
		defer cleanup()
		pkCred, ok := cred.(*sign.PublicKeyCredential)
		assert.True(t, ok)
		assert.NotNil(t, pkCred.Keypair)
	})

	t.Run("managed ECDSA key rejected", func(t *testing.T) {
		keys, err := cosign.GenerateKeyPair(pass("ecdsa"))
		assert.NoError(t, err)
		keyPath := filepath.Join(td, "ecdsa.key")
		assert.NoError(t, os.WriteFile(keyPath, keys.PrivateBytes, 0600))

		_, _, err = GetIdentityCredential(t.Context(), options.KeyOpts{
			ExperimentalPQC: true,
			KeyRef:          keyPath,
			PassFunc:        pass("ecdsa"),
		})
		assert.ErrorContains(t, err, "requires an ML-DSA-44 key")
	})

	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
	}{
		{"ML-DSA-65", mldsa.MLDSA65()},
		{"ML-DSA-87", mldsa.MLDSA87()},
	} {
		t.Run("managed "+tc.name+" key rejected with future-support message", func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tc.params)
			assert.NoError(t, err)
			der, err := x509.MarshalPKCS8PrivateKey(priv)
			assert.NoError(t, err)
			enc, err := encrypted.Encrypt(der, []byte("pqc"))
			assert.NoError(t, err)
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: cosign.SigstorePrivateKeyPemType, Bytes: enc})
			keyPath := filepath.Join(td, tc.name+".key")
			assert.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

			_, _, err = GetIdentityCredential(t.Context(), options.KeyOpts{
				ExperimentalPQC: true,
				KeyRef:          keyPath,
				PassFunc:        pass("pqc"),
			})
			assert.True(t, errors.Is(err, cosign.ErrUnsupportedMLDSAParameters), "got err: %v", err)
		})
	}
}

func startMockRekorV3(t *testing.T) *httptest.Server {
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
			http.Error(w, "invalid message digest length", http.StatusBadRequest)
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
	return srv
}

func TestNewAttestationBundle_ExperimentalPQC(t *testing.T) {
	srv := startMockRekorV3(t)
	sc := makeRekorSigningConfig(t, srv.URL, 3)

	// ExperimentalPQC must fail closed if TUF cannot supply a trusted root and --trusted-root is omitted.
	td := t.TempDir()
	scBytes, err := sc.MarshalJSON()
	assert.NoError(t, err)
	scPath := filepath.Join(td, "sc.json")
	assert.NoError(t, os.WriteFile(scPath, scBytes, 0600))
	t.Setenv("TUF_ROOT", td)
	t.Setenv("TUF_MIRROR", "https://tuf.example.invalid")
	koNoTR := options.KeyOpts{ExperimentalPQC: true}
	assert.ErrorContains(t, LoadSigningConfigAndTrustedMaterial(t.Context(), &koNoTR, false, scPath, ""), "loading trusted root for --experimental-pqc")

	tokenPath := filepath.Join(td, "oidc-token")
	assert.NoError(t, os.WriteFile(tokenPath, []byte("test-token"), 0600))
	algo, err := signature.GetAlgorithmDetails(v1.PublicKeyDetails_ML_DSA_44)
	assert.NoError(t, err)
	keys, err := cosign.GenerateKeyPairWithAlgorithm(&algo, pass("pqc"))
	assert.NoError(t, err)
	keyPath := filepath.Join(td, "mldsa44.key")
	assert.NoError(t, os.WriteFile(keyPath, keys.PrivateBytes, 0600))
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://sigstore.dev/cosign/sign/v1"}`)

	for _, tc := range []struct {
		name    string
		ko      options.KeyOpts
		wantSig bool
	}{
		{"OIDC keyless attestation v2 bundle", options.KeyOpts{ExperimentalPQC: true, IDToken: tokenPath, SigningConfig: sc}, false},
		{"managed ML-DSA-44 key attestation v2 bundle", options.KeyOpts{ExperimentalPQC: true, KeyRef: keyPath, PassFunc: pass("pqc"), SigningConfig: sc}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewAttestationBundle(t.Context(), tc.ko, "", "", CommonBundleOpts{Payload: payload}, sc, nil)
			assert.NoError(t, err)
			var pb bundleV2.Bundle
			assert.NoError(t, protojson.Unmarshal(got, &pb))
			assert.Equal(t, cbundle.BundleV20MediaType, pb.GetMediaType())
			assert.Equal(t, payload, pb.GetPayload().GetPayload())
			assert.Equal(t, tc.wantSig, len(pb.GetVerificationMaterial().GetTransparencyLogProof().GetSignature().GetSignature()) > 0)
		})
	}
}
