//
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

package cosign

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func isNilInterface(v any) bool {
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

func isMLDSACert(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if _, ok := cert.PublicKey.(*mldsa.PublicKey); ok {
		return true
	}
	switch cert.SignatureAlgorithm {
	case x509.MLDSA44, x509.MLDSA65, x509.MLDSA87:
		return true
	}
	return false
}

func rejectMLDSAInV1Bundle(bundle verify.SignedEntity) error {
	if vc, err := bundle.VerificationContent(); err == nil && !isNilInterface(vc) {
		if isMLDSACert(vc.Certificate()) {
			return errors.New("ML-DSA certificates are not supported for v1 bundles")
		}
		if slices.ContainsFunc(vc.Intermediates(), isMLDSACert) {
			return errors.New("ML-DSA certificates are not supported for v1 bundles")
		}
	}
	if b, ok := bundle.(*sgbundle.Bundle); ok && b.Bundle != nil {
		if chain := b.GetVerificationMaterial().GetX509CertificateChain(); chain != nil {
			for _, rawCert := range chain.GetCertificates() {
				cert, err := x509.ParseCertificate(rawCert.GetRawBytes())
				if err != nil {
					return fmt.Errorf("parsing certificate in bundle chain: %w", err)
				}
				if isMLDSACert(cert) {
					return errors.New("ML-DSA certificates are not supported for v1 bundles")
				}
			}
		}
	}
	return nil
}

// VerifyNewBundle verifies a Sigstore v1 bundle with the given parameters.
func VerifyNewBundle(_ context.Context, co *CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, bundle verify.SignedEntity) (*verify.VerificationResult, error) {
	if co == nil {
		return nil, errors.New("check options must not be nil")
	}
	if isNilInterface(bundle) {
		return nil, errors.New("bundle must not be nil")
	}
	if artifactPolicyOption == nil {
		return nil, errors.New("artifact policy option must not be nil")
	}
	if co.PQCOnly {
		return nil, errors.New("v1 bundles are not accepted when --experimental-pqc-only is set")
	}

	// Copy co so rekorV2Bundle's UseSignedTimestamps write and typed-nil
	// normalizations stay per-call and don't race a shared *CheckOpts.
	// TODO(cody)(cosign v4): Consider changing function signature to take a
	// non-pointer CheckOpts and avoid this copy.
	coCopy := *co
	if isNilInterface(coCopy.SigVerifier) {
		coCopy.SigVerifier = nil
	}
	if isNilInterface(coCopy.TrustedMaterial) {
		coCopy.TrustedMaterial = nil
	}

	if coCopy.SigVerifier != nil {
		pub, err := coCopy.SigVerifier.PublicKey(coCopy.PKOpts...)
		if err != nil {
			return nil, fmt.Errorf("getting public key from verifier: %w", err)
		}
		if _, ok := pub.(*mldsa.PublicKey); ok {
			return nil, errors.New("ML-DSA public keys are not supported for v1 bundles")
		}
	}
	if err := rejectMLDSAInV1Bundle(bundle); err != nil {
		return nil, err
	}

	if err := rekorV2Bundle(bundle, &coCopy); err != nil {
		return nil, err
	}
	trustedMaterial, verifierOptions, policyOptions, err := coCopy.verificationOptions()
	if err != nil {
		return nil, err
	}
	verifier, err := verify.NewVerifier(trustedMaterial, verifierOptions...)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(bundle, verify.NewPolicy(artifactPolicyOption, policyOptions...))
}

// VerifyBundleV2 verifies a Sigstore v2 bundle using the identity transparency verifier.
func VerifyBundleV2(_ context.Context, co *CheckOpts, artifactPolicyOption verify.ArtifactPolicyOption, bundle verify.VerifiableEntity) (*verify.IdentityVerificationResult, error) {
	if co == nil {
		return nil, errors.New("check options must not be nil")
	}
	if isNilInterface(bundle) {
		return nil, errors.New("bundle must not be nil")
	}
	if artifactPolicyOption == nil {
		return nil, errors.New("artifact policy option must not be nil")
	}
	if !bundle.HasTransparencyLogProof() {
		switch {
		case bundle.HasCertificate():
			return nil, errors.New("v2 certificate-based (non-transparent) bundles are not yet supported")
		case bundle.HasPublicKey():
			return nil, errors.New("v2 raw public-key (non-transparent) bundles are not yet supported")
		default:
			return nil, errors.New("v2 bundle does not contain a transparency log proof")
		}
	}
	if co.IgnoreTlog {
		return nil, errors.New("ignoring transparency log verification is not supported for v2 transparent bundles")
	}
	if co.UseSignedTimestamps {
		return nil, errors.New("signed timestamps are not supported for v2 transparent bundles")
	}
	if isNilInterface(co.TrustedMaterial) {
		return nil, errors.New("a trusted root is required for v2 bundle verification")
	}

	hasKey := !isNilInterface(co.SigVerifier)
	if hasKey && len(co.Identities) > 0 {
		return nil, errors.New("cannot specify both a public key verifier and certificate identities for v2 bundle verification")
	}
	if !hasKey && len(co.Identities) == 0 {
		return nil, errors.New("either a public key verifier or an expected identity is required for v2 bundle verification")
	}

	vTrustedMaterial := &verifyTrustedMaterial{TrustedMaterial: co.TrustedMaterial}
	policyOptions := make([]verify.PolicyOption, 0, 1)

	if hasKey {
		pub, err := co.SigVerifier.PublicKey(co.PKOpts...)
		if err != nil {
			return nil, fmt.Errorf("getting public key from verifier: %w", err)
		}
		mldsaPub, ok := pub.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("v2 transparent bundle verification requires an ML-DSA-44 public key, got %T", pub)
		}
		params, err := cryptoutils.ValidateMLDSAPublicKey(mldsaPub)
		if err != nil {
			return nil, fmt.Errorf("invalid ML-DSA public key: %w", err)
		}
		if params != mldsa.MLDSA44() {
			return nil, fmt.Errorf("v2 transparent bundle verification only supports ML-DSA-44 public keys (got %s): %w", params, ErrUnsupportedMLDSAParameters)
		}
		newExpiringKey := root.NewExpiringKey(co.SigVerifier, time.Time{}, time.Time{})
		vTrustedMaterial.keyTrustedMaterial = root.NewTrustedPublicKeyVerifiers(newExpiringKey)
		policyOptions = append(policyOptions, verify.WithKey())
	} else {
		certIDPolicy, err := co.buildCertificateIdentityPolicy()
		if err != nil {
			return nil, err
		}
		policyOptions = append(policyOptions, certIDPolicy)
	}

	verifier, err := verify.NewIdentityVerifier(vTrustedMaterial)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(bundle, verify.NewPolicy(artifactPolicyOption, policyOptions...))
}

// rekorV2Bundle checks if a bundle contains only Rekor v2 entries, and if so, mandates that
// a signed timestamp is provided when verifying a certificate. Unlike Rekor v1, Rekor v2 does
// not provide timestamps, and so when verifying a short-lived certificates, users either explicitly
// need to specify --use-signed-timestamps, or we'll opportunistically set it here.
// This check does nothing if users skip transparency log verification or provide a key, since
// a trusted timestamp is unneeded.
// If a bundle were to contain both a Rekor v1 and Rekor v2 entry, but with trust material that
// will only successfully verify the Rekor v1 entry, this would cause a verification failure.
// Therefore, if we have a mixed bundle, we will do nothing and require that the user explicitly
// opt in to checking for signed timestamps.
// There is one edge case that isn't handled - A bundle with a Rekor v2 entry with a certificate
// that should be validated using the current time rather than a provided timestamp. If someone runs
// into this, we can add a flag like --use-current-time.
func rekorV2Bundle(bundle verify.SignedEntity, co *CheckOpts) error {
	// Without a transparency log entry, users will need to opt in to verifying timestamps.
	// With a key, there's no need for timestamps.
	if co.IgnoreTlog || co.SigVerifier != nil {
		return nil
	}
	logEntries, err := bundle.TlogEntries()
	if err != nil {
		return err
	}
	var hasRekorV1, hasRekorV2 bool
	for _, logEntry := range logEntries {
		// Rekor v2 entries do not specify an integrated time
		if logEntry.IntegratedTime().IsZero() {
			hasRekorV2 = true
		} else {
			hasRekorV1 = true
		}
	}
	if hasRekorV2 && !hasRekorV1 {
		co.UseSignedTimestamps = true
	}
	return nil
}
