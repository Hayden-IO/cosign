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

package bundle

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/internal/useragent"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

type SignOptions struct {
	TSAClientTransport  http.RoundTripper
	CertificateProvider sign.CertificateProvider
}

func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

func isMLDSASigningAlgorithm(alg protocommon.PublicKeyDetails) bool {
	switch alg {
	case protocommon.PublicKeyDetails_ML_DSA_44,
		protocommon.PublicKeyDetails_ML_DSA_65,
		protocommon.PublicKeyDetails_ML_DSA_87:
		return true
	default:
		return false
	}
}

func rejectMLDSAKeypairForV1(keypair sign.Keypair) error {
	if isNilValue(keypair) {
		return nil
	}
	if _, isMLDSA := keypair.GetPublicKey().(*mldsa.PublicKey); isMLDSA {
		return errors.New("ML-DSA keys are not supported for v1 bundles; use --experimental-pqc to sign with a v2 bundle")
	}
	if isMLDSASigningAlgorithm(keypair.GetSigningAlgorithm()) {
		return errors.New("ML-DSA keys are not supported for v1 bundles; use --experimental-pqc to sign with a v2 bundle")
	}
	if keypair.GetPublicKey() == nil {
		if pubPEM, err := keypair.GetPublicKeyPem(); err == nil && pubPEM != "" {
			if block, _ := pem.Decode([]byte(pubPEM)); block != nil {
				if pubKey, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
					if _, isMLDSA := pubKey.(*mldsa.PublicKey); isMLDSA {
						return errors.New("ML-DSA keys are not supported for v1 bundles; use --experimental-pqc to sign with a v2 bundle")
					}
				}
			}
		}
	}
	return nil
}

func isMLDSACert(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	if _, ok := c.PublicKey.(*mldsa.PublicKey); ok {
		return true
	}
	switch c.SignatureAlgorithm {
	case x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return true
	}
	return false
}

func rejectMLDSACertForV1(certPEM []byte) error {
	rest := certPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if isMLDSACert(c) {
			return errors.New("ML-DSA certificates are not supported for v1 bundles; use --experimental-pqc to sign with a v2 bundle")
		}
	}
	return nil
}

func SignData(ctx context.Context, content sign.Content, keypair sign.Keypair, idToken string, cert []byte, certChain []byte, signingConfig *root.SigningConfig, trustedMaterial root.TrustedMaterial, opts SignOptions) ([]byte, error) {
	if err := rejectMLDSAKeypairForV1(keypair); err != nil {
		return nil, err
	}
	if err := rejectMLDSACertForV1(cert); err != nil {
		return nil, err
	}
	if err := rejectMLDSACertForV1(certChain); err != nil {
		return nil, err
	}

	var bundleOpts sign.BundleOptions

	if trustedMaterial != nil {
		bundleOpts.TrustedRoot = trustedMaterial
	}

	switch {
	case opts.CertificateProvider != nil:
		bundleOpts.CertificateProvider = opts.CertificateProvider
		if idToken != "" {
			bundleOpts.CertificateProviderOptions = &sign.CertificateProviderOptions{
				IDToken: idToken,
			}
		}
	case idToken != "":
		provider, err := newFulcioProvider(signingConfig)
		if err != nil {
			return nil, err
		}
		bundleOpts.CertificateProvider = provider
		bundleOpts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: idToken,
		}
	case cert != nil && len(certChain) > 0:
		bundleOpts.CertificateChainProvider = &localCertChainProvider{cert: cert, chain: certChain}
	case cert != nil:
		bundleOpts.CertificateProvider = &localCertProvider{cert}
	default:
		publicKeyPem, err := keypair.GetPublicKeyPem()
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(publicKeyPem))
		if block == nil {
			return nil, errors.New("failed to decode public key PEM")
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		if _, isMLDSA := pubKey.(*mldsa.PublicKey); isMLDSA {
			return nil, errors.New("ML-DSA keys are not supported for v1 bundles; use --experimental-pqc to sign with a v2 bundle")
		}
		verifier, err := signature.LoadDefaultVerifier(pubKey)
		if err != nil {
			return nil, fmt.Errorf("loading verifier: %w", err)
		}
		key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})
		keyTrustedMaterial := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return key, nil
		})
		if bundleOpts.TrustedRoot != nil {
			trustedMaterial := &verifyTrustedMaterial{
				TrustedMaterial:    bundleOpts.TrustedRoot,
				keyTrustedMaterial: keyTrustedMaterial,
			}
			bundleOpts.TrustedRoot = trustedMaterial
		}
	}

	if len(signingConfig.TimestampAuthorityURLs()) != 0 {
		tsaSvcs, err := root.SelectServices(signingConfig.TimestampAuthorityURLs(),
			signingConfig.TimestampAuthorityURLsConfig(), sign.TimestampAuthorityAPIVersions, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		for _, tsaSvc := range tsaSvcs {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:       tsaSvc.URL,
				Timeout:   30 * time.Second,
				Retries:   1,
				UserAgent: useragent.Get(),
			}
			if opts.TSAClientTransport != nil {
				tsaOpts.Transport = opts.TSAClientTransport
			}
			bundleOpts.TimestampAuthorities = append(bundleOpts.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts))
		}
	}

	var usingRekorV2 bool
	if len(signingConfig.RekorLogURLs()) != 0 {
		rekorSvcs, err := root.SelectServices(signingConfig.RekorLogURLs(),
			signingConfig.RekorLogURLsConfig(), sign.RekorAPIVersions, time.Now())
		if err != nil {
			return nil, err
		}
		for _, rekorSvc := range rekorSvcs {
			if rekorSvc.MajorAPIVersion == 2 {
				usingRekorV2 = true
			}
			rekorOpts := &sign.RekorOptions{
				BaseURL:   rekorSvc.URL,
				Timeout:   90 * time.Second,
				Retries:   1,
				Version:   rekorSvc.MajorAPIVersion,
				UserAgent: useragent.Get(),
			}
			bundleOpts.TransparencyLogs = append(bundleOpts.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}
	// When requesting a short-lived Fulcio certificate, a timestamp must be provided during
	// verification. It can come from either Rekor v1 providing a signed entry timestamp, or
	// from a timestamp authority. Rekor v2 doesn't timestamp entries, so when a client
	// is configured to use Rekor v2 when retrieving a Fulcio certificate, we enforce
	// that a timestamp authority is provided as well.
	if usingRekorV2 && len(bundleOpts.TimestampAuthorities) == 0 && idToken != "" {
		return nil, fmt.Errorf("a timestamp authority must be provided to request a short-lived certificate that will be logged to Rekor")
	}

	spinner := ui.NewSpinner(ctx, "Signing artifact...")
	defer spinner.Stop()

	bundle, err := sign.Bundle(content, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("error signing bundle: %w", err)
	}
	if vm := bundle.GetVerificationMaterial(); vm != nil {
		if cert := vm.GetCertificate(); cert != nil && len(cert.RawBytes) > 0 {
			if c, err := x509.ParseCertificate(cert.RawBytes); err == nil && isMLDSACert(c) {
				return nil, errors.New("ML-DSA certificates are not supported for v1 bundles; use --experimental-pqc to sign with a v2 bundle")
			}
		}
		for _, cert := range vm.GetX509CertificateChain().GetCertificates() {
			if cert != nil && len(cert.RawBytes) > 0 {
				if c, err := x509.ParseCertificate(cert.RawBytes); err == nil && isMLDSACert(c) {
					return nil, errors.New("ML-DSA certificates are not supported for v1 bundles; use --experimental-pqc to sign with a v2 bundle")
				}
			}
		}
	}
	return protojson.Marshal(bundle)
}

// SignIdentityData creates a Bundle v2 using the transparent PQC identity flow
// (Rekor v3) with either an OIDC token or an ML-DSA-44 public key credential.
func SignIdentityData(ctx context.Context, content sign.Content, cred sign.IdentityCredential, signingConfig *root.SigningConfig, trustedMaterial root.TrustedMaterial) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if isNilValue(content) {
		return nil, errors.New("content must not be nil")
	}
	if isNilValue(cred) {
		return nil, errors.New("credential must not be nil")
	}
	if signingConfig == nil {
		return nil, errors.New("signing config is required for PQC transparent signing")
	}
	if trustedMaterial != nil && isNilValue(trustedMaterial) {
		return nil, errors.New("trusted material must not be nil")
	}

	rekorURLs := signingConfig.RekorLogURLs()
	if len(rekorURLs) == 0 {
		return nil, errors.New("no Rekor v3 transparency log configured in signing config")
	}
	rekorSvc, err := root.SelectService(rekorURLs, sign.IdentityRekorAPIVersions, time.Now())
	if err != nil {
		return nil, fmt.Errorf("selecting Rekor v3 transparency log: %w", err)
	}

	rekorClient := sign.NewIdentityRekorClient(
		rekorSvc.URL,
		sign.WithIdentityRekorTimeout(90*time.Second),
		sign.WithIdentityRekorRetries(1),
		sign.WithIdentityRekorUserAgent(useragent.Get()),
	)

	bundleOpts := sign.IdentityBundleOptions{
		TransparencyLog: rekorClient,
		Context:         ctx,
		TrustedRoot:     trustedMaterial,
	}

	if pkCred, ok := cred.(*sign.PublicKeyCredential); ok {
		if pkCred == nil || isNilValue(pkCred.Keypair) {
			return nil, errors.New("public key credential keypair must not be nil")
		}
		pubKey := pkCred.Keypair.GetPublicKey()
		mldsaPub, ok := pubKey.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PQC transparent signing requires an ML-DSA-44 key, got %T", pubKey)
		}
		params, err := cryptoutils.ValidateMLDSAPublicKey(mldsaPub)
		if err != nil {
			return nil, fmt.Errorf("invalid ML-DSA public key: %w", err)
		}
		if params != mldsa.MLDSA44() {
			return nil, fmt.Errorf("unsupported ML-DSA parameters %s: only mldsa-44 is currently supported for transparent signing; mldsa-65 and mldsa-87 will be supported in the future for non-transparent signatures", params)
		}
		if trustedMaterial != nil {
			verifier, err := signature.LoadDefaultVerifier(mldsaPub)
			if err != nil {
				return nil, fmt.Errorf("loading ML-DSA verifier: %w", err)
			}
			key := root.NewExpiringKey(verifier, time.Time{}, time.Time{})
			bundleOpts.TrustedRoot = &verifyTrustedMaterial{
				TrustedMaterial:    trustedMaterial,
				keyTrustedMaterial: root.NewTrustedPublicKeyVerifiers(key),
			}
		}
	}

	spinner := ui.NewSpinner(ctx, "Signing artifact...")
	defer spinner.Stop()

	b, err := sign.IdentityBundle(content, cred, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("error signing identity bundle: %w", err)
	}
	return protojson.Marshal(b)
}

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	if v.keyTrustedMaterial == nil {
		return nil, fmt.Errorf("no public key material available")
	}
	return v.keyTrustedMaterial.PublicKeyVerifier(hint)
}

func (v *verifyTrustedMaterial) PublicKeyVerifiers() []root.TimeConstrainedVerifier {
	if v.keyTrustedMaterial == nil {
		return nil
	}
	return v.keyTrustedMaterial.PublicKeyVerifiers()
}

type localCertProvider struct {
	cert []byte
}

func (c *localCertProvider) GetCertificate(_ context.Context, _ sign.Keypair, _ *sign.CertificateProviderOptions) ([]byte, error) {
	certBlock, _ := pem.Decode(c.cert)
	if certBlock == nil {
		return nil, fmt.Errorf("could not decode cert")
	}
	return certBlock.Bytes, nil
}

type localCertChainProvider struct {
	cert  []byte
	chain []byte
}

func (c *localCertChainProvider) GetCertificateChain(_ context.Context, _ sign.Keypair, _ *sign.CertificateProviderOptions) ([][]byte, error) {
	leafCerts, err := cryptoutils.UnmarshalCertificatesFromPEM(c.cert)
	if err != nil || len(leafCerts) == 0 {
		return nil, fmt.Errorf("could not decode leaf certificate")
	}
	chainCerts, err := cryptoutils.UnmarshalCertificatesFromPEM(c.chain)
	if err != nil || len(chainCerts) == 0 {
		return nil, fmt.Errorf("could not decode certificate chain")
	}

	leaf := leafCerts[0]
	derChain := [][]byte{leaf.Raw}
	for _, cert := range chainCerts {
		if cert.Equal(leaf) {
			continue
		}
		if isSelfSigned(cert) {
			continue
		}
		derChain = append(derChain, cert.Raw)
	}
	return derChain, nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

type cachingCertProvider struct {
	provider sign.CertificateProvider
	once     sync.Once
	fetch    func() ([]byte, error)
}

func (c *cachingCertProvider) GetCertificate(ctx context.Context, keypair sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	c.once.Do(func() {
		c.fetch = sync.OnceValues(func() ([]byte, error) {
			return c.provider.GetCertificate(ctx, keypair, opts)
		})
	})
	return c.fetch()
}

func newFulcioProvider(signingConfig *root.SigningConfig) (sign.CertificateProvider, error) {
	if len(signingConfig.FulcioCertificateAuthorityURLs()) == 0 {
		return nil, fmt.Errorf("no fulcio URLs provided in signing config")
	}
	fulcioSvc, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, time.Now())
	if err != nil {
		return nil, err
	}
	fulcioOpts := &sign.FulcioOptions{
		BaseURL:   fulcioSvc.URL,
		Timeout:   30 * time.Second,
		Retries:   1,
		UserAgent: useragent.Get(),
	}
	return sign.NewFulcio(fulcioOpts), nil
}

// NewCachingFulcioProvider creates a caching Fulcio provider from the given signing config.
// This function should not be used in long-running processes, as the certificate will
// expire.
func NewCachingFulcioProvider(signingConfig *root.SigningConfig) (sign.CertificateProvider, error) {
	provider, err := newFulcioProvider(signingConfig)
	if err != nil {
		return nil, err
	}
	return &cachingCertProvider{provider: provider}, nil
}
