//
// Copyright 2022 The Sigstore Authors.
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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/cosign/v3/pkg/policy"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// VerifyBlobAttestationCommand verifies an attestation on a supplied blob
// nolint
type VerifyBlobAttestationCommand struct {
	options.KeyOpts
	options.CertVerifyOptions

	TrustedRootPath string

	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSHA        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string

	IgnoreSCT  bool
	IgnoreTlog bool

	CheckClaims   bool
	PredicateType string
	// TODO: Add policies

	UseSignedTimestamps bool

	Digest    string
	DigestAlg string

	AllowCertificateChain bool
	PQCOnly               bool
}

// Exec runs the verification command
func (c *VerifyBlobAttestationCommand) Exec(ctx context.Context, artifactPath string) (err error) {
	// key and cert identity are mutually exclusive
	if options.NOf(c.KeyRef, c.CertIdentity, c.CertIdentityRegexp) > 1 {
		return &options.KeyAndIdentityParseError{}
	}

	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	if c.PQCOnly {
		if err := ValidatePQCOnlyFlags(c.IgnoreTlog, c.Sk, c.UseSignedTimestamps); err != nil {
			return err
		}
		WarnExperimentalPQCOnly(ctx)
	}

	var identities []cosign.Identity
	if c.KeyRef == "" && !c.Sk {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	co := &cosign.CheckOpts{
		Identities:                   identities,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSHA,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		IgnoreTlog:                   c.IgnoreTlog,
		UseSignedTimestamps:          c.UseSignedTimestamps,
		AllowCertificateChain:        c.AllowCertificateChain,
		PQCOnly:                      c.PQCOnly,
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.Sk, co)

	// User provides a key. Otherwise, verification requires a Fulcio certificate
	// or OIDC transparency log identity provided in an attached bundle.
	var closeSV func()
	co.SigVerifier, closeSV, err = LoadVerifierFromKey(ctx, c.KeyRef, c.Slot, c.Sk)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
	}
	defer closeSV()

	if c.PQCOnly {
		if err := ValidatePQCOnlyVerifier(co.SigVerifier); err != nil {
			return err
		}
	}

	var digestAlg string
	var digest []byte
	if c.CheckClaims {
		switch {
		case artifactPath != "":
			if c.Digest != "" {
				ui.Warnf(ctx, "Ignoring provided --digest in favor of provided blob")
			}
			if c.DigestAlg != "" {
				ui.Warnf(ctx, "Ignoring provided --digestAlg because a blob was provided")
			}
		case c.Digest != "" && c.DigestAlg != "":
			digest, err = hex.DecodeString(c.Digest)
			if err != nil {
				return fmt.Errorf("unable to decode provided digest: %w", err)
			}
			digestAlg = c.DigestAlg
		default:
			return errors.New("must provide path to blob or digest and digestAlg")
		}
	}

	if c.BundlePath == "" {
		return errors.New("bundle path is required")
	}

	err = SetTrustedMaterial(c.TrustedRootPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}
	if co.TrustedMaterial == nil && !vOfflineKey {
		return fmt.Errorf("a trusted root is required for verification; provide one via --trusted-root")
	}

	loaded, err := cbundle.LoadBundleFromPath(c.BundlePath, co.BundleOptions()...)
	if err != nil {
		return err
	}

	var policyOpt sgverify.ArtifactPolicyOption
	switch {
	case !c.CheckClaims:
		policyOpt = sgverify.WithoutArtifactUnsafe()
	case artifactPath != "":
		// Pass the artifact directly so sigstore-go can peek at the bundle
		// and choose the correct hash algorithm automatically, rather than
		// requiring the caller to supply --digestAlg up-front.
		artifactFile, err := os.Open(filepath.Clean(artifactPath))
		if err != nil {
			return err
		}
		defer artifactFile.Close()
		policyOpt = sgverify.WithArtifact(artifactFile)
	default:
		policyOpt = sgverify.WithArtifactDigest(digestAlg, digest)
	}

	var rawEnv *dsse.Envelope
	switch {
	case loaded.IsV1():
		if _, err := cosign.VerifyNewBundle(ctx, co, policyOpt, loaded.V1); err != nil {
			return err
		}
		sigContent, err := loaded.V1.SignatureContent()
		if err != nil {
			return fmt.Errorf("fetching signature content: %w", err)
		}
		envContent := sigContent.EnvelopeContent()
		if envContent == nil {
			return fmt.Errorf("bundle does not contain a DSSE envelope")
		}
		rawEnv = envContent.RawEnvelope()
	case loaded.IsV2():
		if !loaded.V2.HasEnvelope() {
			return fmt.Errorf("bundle does not contain a DSSE envelope")
		}
		if _, err := cosign.VerifyBundleV2(ctx, co, policyOpt, loaded.V2); err != nil {
			return err
		}
		envContent, err := loaded.V2.Envelope()
		if err != nil {
			return fmt.Errorf("fetching envelope from v2 bundle: %w", err)
		}
		rawEnv = envContent.RawEnvelope()
	default:
		return errors.New("empty bundle")
	}

	if rawEnv == nil {
		return fmt.Errorf("bundle does not contain a raw DSSE envelope")
	}
	envCopy := *rawEnv
	if envCopy.Signatures == nil {
		envCopy.Signatures = []dsse.Signature{}
	}

	payloadBytes, err := json.Marshal(&envCopy)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}

	att, err := static.NewAttestation(payloadBytes)
	if err != nil {
		return fmt.Errorf("creating attestation from envelope: %w", err)
	}

	// This checks the predicate type -- if no error is returned and no payload is, then
	// the attestation is not of the given predicate type.
	b, gotPredicateType, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, att)
	if err != nil {
		return fmt.Errorf("converting to consumable policy validation: %w", err)
	}
	if b == nil {
		return fmt.Errorf("invalid predicate type, expected %s got %s", c.PredicateType, gotPredicateType)
	}

	ui.Infof(ctx, "Verified OK")
	return nil
}
