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
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign/privacy"
	"github.com/sigstore/cosign/v3/internal/auth"
	"github.com/sigstore/cosign/v3/internal/key"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"

	pb_go_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// SignerVerifier contains keys or certs to sign and verify.
type SignerVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
	close func()
}

// Close closes the key context if there is one.
func (c *SignerVerifier) Close() {
	if c.close != nil {
		c.close()
	}
}

// GetKeypairAndToken creates a keypair object from provided key or cert flags or generates an ephemeral key.
// For an ephemeral key, it also uses the key to fetch an OIDC token, the pair of which are later used to get a Fulcio cert.
//
// Ensure the returned SignerVerifier is closed via calling SignerVerifier.Close.
func GetKeypairAndToken(ctx context.Context, ko options.KeyOpts, cert, certChain string) (sign.Keypair, []byte, []byte, string, error) {
	var keypair sign.Keypair
	var ephemeralKeypair bool
	var idToken string
	var sv *SignerVerifier
	var err error

	sv, ephemeralKeypair, err = signerFromKeyOpts(ctx, cert, certChain, ko)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("getting signer: %w", err)
	}
	keypair, err = key.NewSignerVerifierKeypair(sv, ko.DefaultLoadOptions)
	if err != nil {
		sv.Close()
		return nil, nil, nil, "", fmt.Errorf("creating signerverifier keypair: %w", err)
	}
	certBytes := sv.Cert
	chainBytes := sv.Chain

	if ephemeralKeypair || ko.IssueCertificateForExistingKey {
		idToken, err = auth.RetrieveIDToken(ctx, auth.IDTokenConfig{
			TokenOrPath:      ko.IDToken,
			DisableProviders: ko.OIDCDisableProviders,
			Provider:         ko.OIDCProvider,
			AuthFlow:         ko.FulcioAuthFlow,
			OIDCServices:     ko.SigningConfig.OIDCProviderURLs(),
			ClientID:         ko.OIDCClientID,
			ClientSecret:     ko.OIDCClientSecret,
			RedirectURL:      ko.OIDCRedirectURL,
		})
		if err != nil {
			sv.Close()
			return nil, nil, nil, "", fmt.Errorf("retrieving ID token: %w", err)
		}
	}

	return keypair, certBytes, chainBytes, idToken, nil
}

// ShouldUploadToTlog determines whether the user wants to upload the entry to Rekor.
func ShouldUploadToTlog(ctx context.Context, ko options.KeyOpts, ref name.Reference, tlogUpload bool) bool {
	// return false if not uploading to the tlog has been requested
	if !tlogUpload {
		return false
	}

	if ko.SigningConfig != nil && len(ko.SigningConfig.RekorLogURLs()) == 0 {
		return false
	}

	if ko.SkipConfirmation {
		return true
	}

	// We don't need to validate the ref, just return true
	if ref == nil {
		return true
	}

	// Check if the image is public (no auth in Get)
	if _, err := remote.Get(ref, remote.WithContext(ctx)); err != nil {
		ui.Warnf(ctx, "%q appears to be a private repository, please confirm uploading to the transparency log", ref.Context().String())
		if ui.ConfirmContinue(ctx) != nil {
			ui.Infof(ctx, "not uploading to transparency log")
			return false
		}
	}
	return true
}

// ConfirmPrivacyStatement prompts the user with the Sigstore privacy statement
// if the operation will record data to a public transparency log.
func ConfirmPrivacyStatement(ctx context.Context, ko options.KeyOpts) error {
	isKeyless := (!ko.ExperimentalPQC && ko.KeyRef == "" && !ko.Sk) || ko.IssueCertificateForExistingKey
	// The privacy statement applies when publishing to the public Rekor
	// transparency log or the public Fulcio Certificate Transparency (CT) log.
	if hasPublicGoodRekorURL(ko.SigningConfig) ||
		(isKeyless && hasPublicGoodFulcioURL(ko.SigningConfig)) {
		var statementErr error
		privacy.StatementOnce.Do(func() {
			ui.Infof(ctx, privacy.Statement)
			ui.Infof(ctx, privacy.StatementConfirmation)
			if !ko.SkipConfirmation {
				if err := ui.ConfirmContinue(ctx); err != nil {
					statementErr = err
				}
			}
		})
		return statementErr
	}
	return nil
}

// publicGoodHostSuffixes are the hostname suffixes of services operated as part
// of the sigstore public good instance (production and staging). A literal
// comparison against options.DefaultRekorURL or options.DefaultFulcioURL is not
// sufficient because the public good instance is served from multiple region-
// and year-specific hostnames.
var publicGoodHostSuffixes = []string{".sigstore.dev", ".sigstage.dev"}

// hasPublicGoodRekorURL reports whether a signing config contains a rekor URL that
// points at the sigstore public good instance (production or staging).
func hasPublicGoodRekorURL(sc *root.SigningConfig) bool {
	if sc == nil {
		return false
	}
	for _, s := range sc.RekorLogURLs() {
		if isPublicGoodURL(s.URL) {
			return true
		}
	}
	return false
}

// hasPublicGoodFulcioURL reports whether a signing config contains a fulcio URL that
// points at the sigstore public good instance (production or staging).
func hasPublicGoodFulcioURL(sc *root.SigningConfig) bool {
	if sc == nil {
		return false
	}
	for _, s := range sc.FulcioCertificateAuthorityURLs() {
		if isPublicGoodURL(s.URL) {
			return true
		}
	}
	return false
}

// isPublicGoodURL reports whether a URL points at the sigstore public good
// instance (production or staging).
func isPublicGoodURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	for _, suffix := range publicGoodHostSuffixes {
		if host == suffix[1:] || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func signerFromKeyOpts(ctx context.Context, certPath string, certChainPath string, ko options.KeyOpts) (*SignerVerifier, bool, error) {
	var sv *SignerVerifier
	var err error
	genKey := false
	switch {
	case ko.Sk:
		sv, err = signerFromSecurityKey(ctx, ko.Slot)
	case ko.KeyRef != "":
		sv, err = signerFromKeyRef(ctx, certPath, certChainPath, ko.KeyRef, ko.PassFunc, ko.DefaultLoadOptions)
	default:
		genKey = true
		ui.Infof(ctx, "Generating ephemeral keys...")
		sv, err = signerFromNewKey(ko.SigningAlgorithm, ko.DefaultLoadOptions)
	}
	if err != nil {
		return nil, false, err
	}
	return sv, genKey, nil
}

func signerFromSecurityKey(ctx context.Context, keySlot string) (*SignerVerifier, error) {
	sk, err := pivkey.GetKeyWithSlot(keySlot)
	if err != nil {
		return nil, err
	}
	sv, err := sk.SignerVerifier()
	if err != nil {
		sk.Close()
		return nil, err
	}

	// Handle the -cert flag.
	// With PIV, we assume the certificate is in the same slot on the PIV
	// token as the private key. If it's not there, show a warning to the
	// user.
	certFromPIV, err := sk.Certificate()
	var pemBytes []byte
	if err != nil {
		ui.Warnf(ctx, "no x509 certificate retrieved from the PIV token")
	} else {
		pemBytes, err = cryptoutils.MarshalCertificateToPEM(certFromPIV)
		if err != nil {
			sk.Close()
			return nil, err
		}
	}

	return &SignerVerifier{
		Cert:           pemBytes,
		SignerVerifier: sv,
		close:          sk.Close,
	}, nil
}

func signerFromKeyRef(ctx context.Context, certPath, certChainPath, keyRef string, passFunc cosign.PassFunc, defaultLoadOptions *[]signature.LoadOption) (*SignerVerifier, error) {
	k, err := sigs.SignerVerifierFromKeyRef(ctx, keyRef, passFunc, defaultLoadOptions)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	certSigner := &SignerVerifier{
		SignerVerifier: k,
	}

	var leafCert *x509.Certificate

	// Attempt to extract certificate from PKCS11 token
	// With PKCS11, we assume the certificate is in the same slot on the PKCS11
	// token as the private key. If it's not there, show a warning to the
	// user.
	if pkcs11Key, ok := k.(*pkcs11key.Key); ok {
		certFromPKCS11, _ := pkcs11Key.Certificate()
		certSigner.close = pkcs11Key.Close

		if certFromPKCS11 == nil {
			ui.Warnf(ctx, "no x509 certificate retrieved from the PKCS11 token")
		} else {
			pemBytes, err := cryptoutils.MarshalCertificateToPEM(certFromPKCS11)
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			// Check that the provided public key and certificate key match
			pubKey, err := k.PublicKey()
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			if cryptoutils.EqualKeys(pubKey, certFromPKCS11.PublicKey) != nil {
				pkcs11Key.Close()
				return nil, errors.New("pkcs11 key and certificate do not match")
			}
			leafCert = certFromPKCS11
			certSigner.Cert = pemBytes
		}
	}

	// Handle --cert flag
	if certPath != "" {
		// Allow both DER and PEM encoding
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		// Handle PEM
		if bytes.HasPrefix(certBytes, []byte("-----")) {
			decoded, _ := pem.Decode(certBytes)
			if decoded.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("supplied PEM file is not a certificate: %s", certPath)
			}
			certBytes = decoded.Bytes
		}
		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("parse x509 certificate: %w", err)
		}
		pk, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("get public key: %w", err)
		}
		if cryptoutils.EqualKeys(pk, parsedCert.PublicKey) != nil {
			return nil, errors.New("public key in certificate does not match the provided public key")
		}
		pemBytes, err := cryptoutils.MarshalCertificateToPEM(parsedCert)
		if err != nil {
			return nil, fmt.Errorf("marshaling certificate to PEM: %w", err)
		}
		if certSigner.Cert != nil {
			ui.Warnf(ctx, "overriding x509 certificate retrieved from the PKCS11 token")
		}
		leafCert = parsedCert
		certSigner.Cert = pemBytes
	}

	if certChainPath == "" {
		return certSigner, nil
	} else if certSigner.Cert == nil {
		return nil, errors.New("no leaf certificate found or provided while specifying chain")
	}

	// Handle --cert-chain flag
	// Accept only PEM encoded certificate chain
	certChainBytes, err := os.ReadFile(certChainPath)
	if err != nil {
		return nil, fmt.Errorf("reading certificate chain from path: %w", err)
	}
	certChain, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(certChainBytes))
	if err != nil {
		return nil, fmt.Errorf("loading certificate chain: %w", err)
	}
	if len(certChain) == 0 {
		return nil, errors.New("no certificates in certificate chain")
	}
	// Verify certificate chain is valid
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certChain[len(certChain)-1])
	subPool := x509.NewCertPool()
	for _, c := range certChain[:len(certChain)-1] {
		subPool.AddCert(c)
	}
	if _, err := cosign.TrustedCert(leafCert, rootPool, subPool); err != nil {
		return nil, fmt.Errorf("unable to validate certificate chain: %w", err)
	}
	certSigner.Chain = certChainBytes

	return certSigner, nil
}

func signerFromNewKey(signingAlgorithm string, defaultLoadOptions *[]signature.LoadOption) (*SignerVerifier, error) {
	keyDetails, err := ParseSignatureAlgorithmFlag(signingAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("parsing signature algorithm: %w", err)
	}
	algo, err := signature.GetAlgorithmDetails(keyDetails)
	if err != nil {
		return nil, fmt.Errorf("getting algorithm details: %w", err)
	}

	privKey, err := cosign.GeneratePrivateKeyWithAlgorithm(&algo)
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}

	defaultLoadOptions = cosign.GetDefaultLoadOptions(defaultLoadOptions)
	sv, err := signature.LoadSignerVerifierFromAlgorithmDetails(privKey, algo, *defaultLoadOptions...)
	if err != nil {
		return nil, err
	}

	return &SignerVerifier{
		SignerVerifier: sv,
	}, nil
}

type CommonBundleOpts struct {
	Payload       []byte
	Digest        name.Digest
	PredicateType string
	BundlePath    string
	Upload        bool
	OCIRemoteOpts []ociremote.Option
}

// WarnExperimentalPQC emits a prominent warning to stderr when experimental
// post-quantum signing is enabled.
func WarnExperimentalPQC(ctx context.Context) {
	ui.Warnf(ctx, "EXPERIMENTAL PQC SIGNING ENABLED: Post-quantum cryptography (ML-DSA / Rekor v3) and Bundle v2 are experimental and subject to breaking changes. Do not rely on these signatures for production workloads.")
}

// ValidatePQCFlags validates CLI flags that are incompatible with
// --experimental-pqc without requiring a loaded SigningConfig.
func ValidatePQCFlags(ko options.KeyOpts, cert, certChain string) error {
	if !ko.ExperimentalPQC {
		return nil
	}
	if ko.Sk {
		return errors.New("--sk (security key) is not supported with --experimental-pqc")
	}
	if cert != "" || certChain != "" {
		return errors.New("--certificate and --certificate-chain are not supported with --experimental-pqc")
	}
	if ko.IssueCertificateForExistingKey {
		return errors.New("--issue-certificate is not supported with --experimental-pqc")
	}
	if ko.TSAClientCACert != "" || ko.TSAClientCert != "" || ko.TSAClientKey != "" || ko.TSAServerName != "" {
		return errors.New("timestamp authority flags are not supported with --experimental-pqc")
	}
	if ko.SigningAlgorithm != "" {
		return errors.New("--signing-algorithm is not supported with --experimental-pqc")
	}
	return nil
}

// ValidatePQCSigningOpts validates signing options when --experimental-pqc is enabled.
func ValidatePQCSigningOpts(ko options.KeyOpts, cert, certChain string) error {
	if err := ValidatePQCFlags(ko, cert, certChain); err != nil {
		return err
	}
	if !ko.ExperimentalPQC {
		return nil
	}
	if ko.SigningConfig == nil {
		return errors.New("--experimental-pqc requires a signing config with a Rekor v3 transparency log")
	}
	if _, err := root.SelectService(ko.SigningConfig.RekorLogURLs(), sign.IdentityRekorAPIVersions, time.Now()); err != nil {
		return fmt.Errorf("--experimental-pqc requires an active Rekor v3 transparency log in signing config (run 'cosign initialize --experimental-pqc-staging' or provide --signing-config): %w", err)
	}
	return nil
}

// GetIdentityCredential constructs a sign.IdentityCredential for transparent PQC
// signing (OIDC keyless or managed ML-DSA-44 key). Callers must invoke the
// returned cleanup function when non-nil.
func GetIdentityCredential(ctx context.Context, ko options.KeyOpts) (sign.IdentityCredential, func(), error) {
	if ko.Sk {
		return nil, nil, errors.New("--sk (security key) is not supported with --experimental-pqc")
	}
	if ko.KeyRef == "" {
		var oidcServices []root.Service
		if ko.SigningConfig != nil {
			oidcServices = ko.SigningConfig.OIDCProviderURLs()
		}
		idToken, err := auth.RetrieveIDToken(ctx, auth.IDTokenConfig{
			TokenOrPath:      ko.IDToken,
			DisableProviders: ko.OIDCDisableProviders,
			Provider:         ko.OIDCProvider,
			AuthFlow:         ko.FulcioAuthFlow,
			OIDCServices:     oidcServices,
			ClientID:         ko.OIDCClientID,
			ClientSecret:     ko.OIDCClientSecret,
			RedirectURL:      ko.OIDCRedirectURL,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("retrieving ID token: %w", err)
		}
		return &sign.OIDCCredential{Token: idToken}, func() {}, nil
	}

	sv, err := sigs.SignerVerifierFromKeyRef(ctx, ko.KeyRef, ko.PassFunc, ko.DefaultLoadOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("reading key: %w", err)
	}
	cleanup := func() {
		if closer, ok := sv.(interface{ Close() }); ok {
			closer.Close()
		}
	}
	pubKey, err := sv.PublicKey()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("getting public key: %w", err)
	}
	mldsaPub, ok := pubKey.(*mldsa.PublicKey)
	if !ok {
		cleanup()
		return nil, nil, fmt.Errorf("--experimental-pqc requires an ML-DSA-44 key (generate one with 'cosign generate-key-pair --algorithm mldsa-44'), got %T", pubKey)
	}
	params, err := cryptoutils.ValidateMLDSAPublicKey(mldsaPub)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("invalid ML-DSA public key: %w", err)
	}
	if params != mldsa.MLDSA44() {
		cleanup()
		return nil, nil, fmt.Errorf("unsupported ML-DSA parameters %s: %w", params, cosign.ErrUnsupportedMLDSAParameters)
	}
	kp, err := key.NewSignerVerifierKeypair(sv, ko.DefaultLoadOptions)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("creating signerverifier keypair: %w", err)
	}
	return &sign.PublicKeyCredential{Keypair: kp}, kp.Close, nil
}

// NewAttestationBundle uses signing config and trusted root to sign an attestation and create a bundle.
func NewAttestationBundle(ctx context.Context, ko options.KeyOpts, cert, certChain string, bundleOpts CommonBundleOpts, signingConfig *root.SigningConfig, trustedMaterial root.TrustedMaterial) ([]byte, error) {
	if ko.ExperimentalPQC {
		koCopy := ko
		if signingConfig != nil {
			koCopy.SigningConfig = signingConfig
		}
		if err := ValidatePQCSigningOpts(koCopy, cert, certChain); err != nil {
			return nil, err
		}
		cred, cleanup, err := GetIdentityCredential(ctx, koCopy)
		if err != nil {
			return nil, fmt.Errorf("getting identity credential: %w", err)
		}
		if cleanup != nil {
			defer cleanup()
		}
		content := &sign.DSSEData{
			Data:        bundleOpts.Payload,
			PayloadType: "application/vnd.in-toto+json",
		}
		bundle, err := cbundle.SignIdentityData(ctx, content, cred, koCopy.SigningConfig, trustedMaterial)
		if err != nil {
			return nil, fmt.Errorf("signing PQC bundle: %w", err)
		}
		return bundle, nil
	}

	keypair, certBytes, chainBytes, idToken, err := GetKeypairAndToken(ctx, ko, cert, certChain)
	if err != nil {
		return nil, fmt.Errorf("getting keypair and token: %w", err)
	}
	if closer, ok := keypair.(interface{ Close() }); ok {
		defer closer.Close()
	}

	content := &sign.DSSEData{
		Data:        bundleOpts.Payload,
		PayloadType: "application/vnd.in-toto+json",
	}

	var tsaClientTransport http.RoundTripper
	if ko.TSAClientCACert != "" || (ko.TSAClientCert != "" && ko.TSAClientKey != "") {
		tsaClientTransport, err = client.GetHTTPTransport(ko.TSAClientCACert, ko.TSAClientCert, ko.TSAClientKey, ko.TSAServerName, 30*time.Second)
		if err != nil {
			return nil, fmt.Errorf("getting TSA client transport: %w", err)
		}
	}
	signOpts := cbundle.SignOptions{TSAClientTransport: tsaClientTransport}

	bundle, err := cbundle.SignData(ctx, content, keypair, idToken, certBytes, chainBytes, signingConfig, trustedMaterial, signOpts)
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}

	return bundle, nil
}

// ParseOCIReference parses a string reference to an OCI image into a reference, warning if the reference did not include a digest.
func ParseOCIReference(ctx context.Context, refStr string, opts ...name.Option) (name.Reference, error) {
	ref, err := name.ParseReference(refStr, opts...)
	if err != nil {
		return nil, fmt.Errorf("parsing reference: %w", err)
	}
	if _, ok := ref.(name.Digest); !ok {
		ui.Warnf(ctx, ui.TagReferenceMessage, refStr)
	}
	return ref, nil
}

func ParseSignatureAlgorithmFlag(signingAlgorithm string) (pb_go_v1.PublicKeyDetails, error) {
	if signingAlgorithm == "" {
		var err error
		signingAlgorithm, err = signature.FormatSignatureAlgorithmFlag(pb_go_v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
		if err != nil {
			return pb_go_v1.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED, fmt.Errorf("formatting signature algorithm: %w", err)
		}
	}
	return signature.ParseSignatureAlgorithmFlag(signingAlgorithm)
}

// LoadSigningConfigAndTrustedMaterial loads the signing config and trusted material from the given options.
func LoadSigningConfigAndTrustedMaterial(ctx context.Context, ko *options.KeyOpts, noSigningConfig bool, signingConfigPath, trustedRootPath string) error {
	var err error
	switch {
	case signingConfigPath != "":
		ko.SigningConfig, err = root.NewSigningConfigFromPath(signingConfigPath)
		if err != nil {
			return fmt.Errorf("error reading signing config from file: %w", err)
		}
	case noSigningConfig:
		ko.SigningConfig = NewEmptySigningConfig()
	default:
		ko.SigningConfig, err = cosign.SigningConfig()
		if err != nil {
			return fmt.Errorf("error getting signing config from TUF: %w", err)
		}
	}

	// Fetch a trusted root when:
	// * an explicit --trusted-root path is provided
	// * using a signing config with at least one service configured
	if trustedRootPath != "" {
		ko.TrustedMaterial, err = root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return fmt.Errorf("loading trusted root: %w", err)
		}
	} else if signingConfigHasServices(ko.SigningConfig) {
		ko.TrustedMaterial, err = cosign.TrustedRoot()
		if err != nil {
			if ko.ExperimentalPQC {
				return fmt.Errorf("loading trusted root for --experimental-pqc self-verification (specify --trusted-root or initialize a PQC TUF root): %w", err)
			}
			ui.Warnf(ctx, "Could not fetch trusted_root.json from the TUF repository. Continuing without trusted root. Error from TUF: %v", err)
		}
	}
	if ko.ExperimentalPQC && ko.TrustedMaterial == nil {
		return fmt.Errorf("trusted root is required for --experimental-pqc self-verification (specify --trusted-root or initialize a PQC TUF root)")
	}

	return nil
}

// RequireFulcioForCertificate returns an error when keyless or certificate-based signing is
// requested and the signing config has no Fulcio certificate authority.
func RequireFulcioForCertificate(ko options.KeyOpts) error {
	if ko.ExperimentalPQC {
		// Transparent PQC OIDC signing submits directly to Rekor v3 and does not use Fulcio.
		return nil
	}
	var signType string
	switch {
	case ko.KeyRef == "" && !ko.Sk:
		signType = "keyless"
	case ko.IssueCertificateForExistingKey:
		signType = "certificate-based"
	default:
		return nil
	}
	if ko.SigningConfig != nil && len(ko.SigningConfig.FulcioCertificateAuthorityURLs()) > 0 {
		return nil
	}
	return fmt.Errorf("%s signing requires a signing config with a Fulcio certificate authority", signType)
}

func signingConfigHasServices(sc *root.SigningConfig) bool {
	if sc == nil {
		return false
	}
	return len(sc.FulcioCertificateAuthorityURLs()) > 0 ||
		len(sc.RekorLogURLs()) > 0 ||
		len(sc.TimestampAuthorityURLs()) > 0
}

// NewEmptySigningConfig returns a signing config with no services configured.
func NewEmptySigningConfig() *root.SigningConfig {
	// root.NewSigningConfig only errors when an unsupported media type is provided.
	// Since root.SigningConfigMediaType02 is a supported constant, this call cannot fail.
	sc, _ := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		nil,
		nil,
		nil,
		root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
		nil,
		root.ServiceConfiguration{Selector: prototrustroot.ServiceSelector_ANY},
	)
	return sc
}

// ProtoHashAlgoToHash converts a protobuf HashAlgorithm to a crypto.Hash.
func ProtoHashAlgoToHash(ha pb_go_v1.HashAlgorithm) crypto.Hash {
	switch ha {
	case pb_go_v1.HashAlgorithm_SHA2_256:
		return crypto.SHA256
	case pb_go_v1.HashAlgorithm_SHA2_384:
		return crypto.SHA384
	case pb_go_v1.HashAlgorithm_SHA2_512:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}
