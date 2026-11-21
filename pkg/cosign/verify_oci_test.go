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
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ocistatic "github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ocilayout "github.com/sigstore/cosign/v3/pkg/oci/layout"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
)

//go:embed testdata/oci-attestation.sigstore.json
var testAttestation []byte

//go:embed testdata/trusted_root_pgi.json
var testTrustedRootPGI []byte

func TestGetBundles_Empty(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:tag", u.Host))
	assert.NoError(t, err)

	// If tag doesn't exist, should return ErrImageTagNotFound
	bundles, hash, err := GetBundles(context.Background(), ref, []ociremote.Option{})
	imgTagNotFound := &ErrImageTagNotFound{}
	assert.ErrorAs(t, err, &imgTagNotFound)
	assert.Len(t, bundles, 0)
	assert.Nil(t, hash)

	// Write an image
	img, err := random.Image(10, 10)
	assert.NoError(t, err)
	assert.NoError(t, remote.Write(ref, img))

	// Check that no matching attestation error is returned
	bundles, hash, err = GetBundles(context.Background(), ref, []ociremote.Option{})
	var noMatchErr *ErrNoMatchingAttestations
	assert.ErrorAs(t, err, &noMatchErr)
	assert.Len(t, bundles, 0)
	assert.Nil(t, hash)

	// Get digest from tag
	desc, err := remote.Head(ref)
	assert.NoError(t, err)
	digestRef := ref.Context().Digest(desc.Digest.String())

	// Write invalid attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, []byte("invalid"), "foo/bar")
	assert.NoError(t, err)

	// Should still return no matching attestation error, as it failed to parse the bundle
	bundles, hash, err = GetBundles(context.Background(), ref, []ociremote.Option{})
	assert.ErrorAs(t, err, &noMatchErr)
	assert.Len(t, bundles, 0)
	assert.Nil(t, hash)
}

func TestGetBundles_Valid(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:tag", u.Host))
	assert.NoError(t, err)

	// Test data uses empty image
	assert.NoError(t, remote.Write(ref, empty.Image))

	// Get digest from tag
	desc, err := remote.Head(ref)
	assert.NoError(t, err)
	digestRef := ref.Context().Digest(desc.Digest.String())

	// Write valid test attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1")
	assert.NoError(t, err)

	// Retrieve the attestation
	bundles, hash, err := GetBundles(context.Background(), ref, []ociremote.Option{})
	assert.NoError(t, err)
	assert.Len(t, bundles, 1)
	assert.NotNil(t, hash)

	// Compare the output to the test data
	expected := sgbundle.Bundle{}
	err = expected.UnmarshalJSON(testAttestation)
	assert.NoError(t, err)
	if !proto.Equal(bundles[0].Bundle, &expected) {
		t.Errorf("got %v, want %v", bundles[0].Bundle, &expected)
	}
}

func TestGetBundles_WithTargetRepository(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)
	host := u.Host

	sourceRef, err := name.ParseReference(fmt.Sprintf("%s/source-repo:tag", host))
	assert.NoError(t, err)

	targetRepo, err := name.NewRepository(fmt.Sprintf("%s/target-repo", host))
	assert.NoError(t, err)

	// Write the source image.
	assert.NoError(t, remote.Write(sourceRef, empty.Image))

	// Get the source image digest.
	desc, err := remote.Head(sourceRef)
	assert.NoError(t, err)

	// Write the attestation referrer into the target repo.
	// Pass the source digest as subject (so WriteReferrer can HEAD it) and
	// WithTargetRepository so the referrer manifest is stored in target-repo.
	sourceDigestRef := sourceRef.Context().Digest(desc.Digest.String())
	err = ociremote.WriteAttestationNewBundleFormat(sourceDigestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1",
		ociremote.WithTargetRepository(targetRepo),
	)
	assert.NoError(t, err)

	// Without WithTargetRepository, the bundle is not found in the source repo.
	bundles, hash, err := GetBundles(context.Background(), sourceRef, []ociremote.Option{})
	var noMatchErr *ErrNoMatchingAttestations
	assert.ErrorAs(t, err, &noMatchErr)
	assert.Len(t, bundles, 0)
	assert.Nil(t, hash)

	// With WithTargetRepository, the bundle is found in the target repo.
	bundles, hash, err = GetBundles(context.Background(), sourceRef, []ociremote.Option{
		ociremote.WithTargetRepository(targetRepo),
	})
	assert.NoError(t, err)
	assert.Len(t, bundles, 1)
	assert.NotNil(t, hash)

	expected := sgbundle.Bundle{}
	err = expected.UnmarshalJSON(testAttestation)
	assert.NoError(t, err)
	if !proto.Equal(bundles[0].Bundle, &expected) {
		t.Errorf("got %v, want %v", bundles[0].Bundle, &expected)
	}

	// Also test a non-loopback HTTP target repository (e.g. registry.local:5000)
	// where name.Insecure is required on the target repository and must be
	// preserved by GetBundles even when nameOpts is omitted.
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		reqClone := req.Clone(req.Context())
		reqClone.URL.Host = host
		reqClone.Host = host
		return http.DefaultTransport.RoundTrip(reqClone)
	})
	httpTargetRepo, err := name.NewRepository("registry.local:5000/http-target-repo", name.Insecure)
	assert.NoError(t, err)
	err = ociremote.WriteAttestationNewBundleFormat(sourceDigestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1",
		ociremote.WithTargetRepository(httpTargetRepo),
		ociremote.WithNameOptions(name.Insecure),
		ociremote.WithRemoteOptions(remote.WithTransport(rt)),
	)
	assert.NoError(t, err)

	// Without nameOpts, GetBundles preserves httpTargetRepo's Insecure scheme via bundleRepo.Digest().
	bundles, hash, err = GetBundles(context.Background(), sourceRef, []ociremote.Option{
		ociremote.WithTargetRepository(httpTargetRepo),
		ociremote.WithRemoteOptions(remote.WithTransport(rt)),
	})
	assert.NoError(t, err)
	assert.Len(t, bundles, 1)
	assert.NotNil(t, hash)
	if !proto.Equal(bundles[0].Bundle, &expected) {
		t.Errorf("got %v, want %v", bundles[0].Bundle, &expected)
	}

	// With name.Insecure passed in nameOpts, GetBundles parses bundleRepo@digest with nameOpts.
	bundles, hash, err = GetBundles(context.Background(), sourceRef, []ociremote.Option{
		ociremote.WithTargetRepository(httpTargetRepo),
		ociremote.WithRemoteOptions(remote.WithTransport(rt)),
	}, name.Insecure)
	assert.NoError(t, err)
	assert.Len(t, bundles, 1)
	assert.NotNil(t, hash)
	if !proto.Equal(bundles[0].Bundle, &expected) {
		t.Errorf("got %v, want %v", bundles[0].Bundle, &expected)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TODO: This test is getting long and maybe should be refactored into a
// table-based test to exercise more permutations.
func TestVerifyImageAttestationsSigstoreBundle(t *testing.T) {
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	defer s.Close()

	u, err := url.Parse(s.URL)
	assert.NoError(t, err)

	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:tag", u.Host))
	assert.NoError(t, err)

	ref2, err := name.ParseReference(fmt.Sprintf("%s/repo:tag2", u.Host))
	assert.NoError(t, err)

	// Parse test root
	trustedRoot, err := root.NewTrustedRootFromJSON(testTrustedRootPGI)
	assert.NoError(t, err)

	// Test data uses empty image
	assert.NoError(t, remote.Write(ref, empty.Image))

	// Also write a second image to test that we only verify the correct image
	randomImage, err := random.Image(10, 10)
	assert.NoError(t, err)
	assert.NoError(t, remote.Write(ref2, randomImage))

	// Attempt to verify non-existent attestation
	atts, bundleVerified, err := VerifyImageAttestations(context.Background(), ref, &CheckOpts{
		TrustedMaterial: trustedRoot,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: ".*",
			},
		},
	})
	var errNoMatchingAttestations *ErrNoMatchingAttestations
	assert.ErrorAs(t, err, &errNoMatchingAttestations)
	assert.False(t, bundleVerified)
	assert.Len(t, atts, 0)

	// Get digest from tag
	desc, err := remote.Head(ref)
	assert.NoError(t, err)
	digestRef := ref.Context().Digest(desc.Digest.String())

	// Write valid test attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1")
	assert.NoError(t, err)

	// Verify the attestation
	atts, bundleVerified, err = VerifyImageAttestations(context.Background(), ref, &CheckOpts{
		TrustedMaterial: trustedRoot,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: ".*",
			},
		},
	})
	assert.NoError(t, err)
	assert.True(t, bundleVerified)
	assert.Len(t, atts, 1)

	// Wrong identity should not verify
	atts, bundleVerified, err = VerifyImageAttestations(context.Background(), ref, &CheckOpts{
		TrustedMaterial: trustedRoot,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: "wrong",
			},
		},
	})
	assert.ErrorAs(t, err, &errNoMatchingAttestations)
	assert.False(t, bundleVerified)
	assert.Len(t, atts, 0)

	// Add same attestation to different image with different digest to test that we only verify the correct image
	// Get digest from tag
	desc, err = remote.Head(ref2)
	assert.NoError(t, err)
	digestRef = ref2.Context().Digest(desc.Digest.String())

	// Write valid test attestation
	err = ociremote.WriteAttestationNewBundleFormat(digestRef, testAttestation, "https://cosign.sigstore.dev/attestation/v1")
	assert.NoError(t, err)

	// Verify the attestation
	atts, bundleVerified, err = VerifyImageAttestations(context.Background(), ref2, &CheckOpts{
		TrustedMaterial: trustedRoot,
		Identities: []Identity{
			{
				IssuerRegExp:  ".*",
				SubjectRegExp: ".*",
			},
		},
	})
	assert.Error(t, err)
	assert.ErrorAs(t, err, &errNoMatchingAttestations)
	// TODO: This error message comes from sigstore-go. We may want to update the upstream with a sentinal error type.
	assert.ErrorContains(t, err, "provided artifact digest does not match any digest in statement")
	assert.False(t, bundleVerified)
	assert.Len(t, atts, 0)
}

func TestVerifyImageAttestationsMixedV1AndV2(t *testing.T) {
	s := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer s.Close()
	u := mustVal(url.Parse(s.URL))
	mustRef := func(repo string) name.Reference {
		r := mustVal(name.ParseReference(fmt.Sprintf("%s/%s:tag", u.Host, repo)))
		assert.NoError(t, remote.Write(r, empty.Image))
		return r
	}
	v1Ref, mixedRef, v2Ref := mustRef("v1-only"), mustRef("mixed"), mustRef("v2-only")
	desc := mustVal(remote.Head(mixedRef))
	trV1 := mustVal(root.NewTrustedRootFromJSON(testTrustedRootPGI))
	stmt := fmt.Appendf(nil, `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"img","digest":{"sha256":"%s"}}],"predicateType":"https://cosign.sigstore.dev/attestation/v1","predicate":{}}`, desc.Digest.Hex)
	v2B, v2Log := buildTestBundleV2(t, testV2BundleOpts{dssePayload: stmt, identity: "alice@example.com", issuer: "https://accounts.example.com"})
	v2Bytes := mustVal(v2B.MarshalJSON())
	tm := &testPQCTrustedMaterial{TrustedMaterial: trV1, extraRekor: map[string]*root.TransparencyLog{"rekor-v3": v2Log}}

	const pt = "https://cosign.sigstore.dev/attestation/v1"
	for _, w := range []struct {
		ref name.Reference
		b   []byte
	}{{v1Ref, testAttestation}, {mixedRef, testAttestation}, {mixedRef, v2Bytes}, {v2Ref, v2Bytes}} {
		assert.NoError(t, ociremote.WriteAttestationNewBundleFormat(w.ref.Context().Digest(desc.Digest.String()), w.b, pt))
	}

	allB, _, err := GetAllBundles(context.Background(), mixedRef, nil)
	assert.True(t, err == nil && len(allB) == 2)
	v1B, _, err := GetBundles(context.Background(), mixedRef, nil)
	assert.True(t, err == nil && len(v1B) == 1)
	var noMatchErr *ErrNoMatchingAttestations
	_, _, err = GetBundles(context.Background(), v2Ref, nil)
	assert.ErrorAs(t, err, &noMatchErr)
	_, _, err = VerifyImageAttestations(context.Background(), mixedRef, nil)
	assert.ErrorContains(t, err, "check options must not be nil")

	wild := []Identity{{IssuerRegExp: ".*", SubjectRegExp: ".*"}}
	atts, ok, err := VerifyImageAttestations(context.Background(), mixedRef, &CheckOpts{TrustedMaterial: tm, Identities: wild, ClaimVerifier: IntotoSubjectClaimVerifier})
	assert.True(t, err == nil && ok && len(atts) == 2)
	atts, ok, err = VerifyImageAttestations(context.Background(), mixedRef, &CheckOpts{PQCOnly: true, TrustedMaterial: tm, Identities: wild, ClaimVerifier: IntotoSubjectClaimVerifier})
	assert.True(t, err == nil && ok && len(atts) == 1)
	_, ok, err = VerifyImageAttestations(context.Background(), v1Ref, &CheckOpts{PQCOnly: true, TrustedMaterial: tm, Identities: wild})
	assert.ErrorAs(t, err, &noMatchErr)
	assert.False(t, ok)
	atts, ok, err = VerifyImageAttestations(context.Background(), v2Ref, &CheckOpts{
		PQCOnly: true, TrustedMaterial: tm, ClaimVerifier: IntotoSubjectClaimVerifier,
		Identities: []Identity{{Issuer: "https://accounts.example.com", Subject: "alice@example.com"}},
	})
	assert.True(t, err == nil && ok && len(atts) == 1)

	// Verify local OCI layout loading and verification of a v2 bundle.
	dir := t.TempDir()
	img := empty.Image
	imgDigest, imgSize := mustVal(img.Digest()), mustVal(img.Size())
	assert.NoError(t, ocilayout.WriteSignedImage(dir, signed.Image(img)))
	v2Layer := ocistatic.NewLayer(v2Bytes, ggcrtypes.MediaType(cbundle.BundleV20MediaType))
	lDigest, lSize := mustVal(v2Layer.Digest()), mustVal(v2Layer.Size())
	blobsDir := filepath.Join(dir, "blobs", "sha256")
	assert.NoError(t, os.WriteFile(filepath.Join(blobsDir, lDigest.Hex), v2Bytes, 0o600))
	cfgHash := sha256.Sum256([]byte("{}"))
	manifestBytes := mustVal(json.Marshal(&v1.Manifest{
		SchemaVersion: 2, MediaType: ggcrtypes.OCIManifestSchema1, ArtifactType: cbundle.BundleV20MediaType,
		Config:  v1.Descriptor{MediaType: ggcrtypes.OCIEmptyJSON, Digest: v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(cfgHash[:])}, Size: 2},
		Subject: &v1.Descriptor{MediaType: ggcrtypes.OCIManifestSchema1, Digest: imgDigest, Size: imgSize},
		Layers:  []v1.Descriptor{{MediaType: ggcrtypes.MediaType(cbundle.BundleV20MediaType), Digest: lDigest, Size: lSize}},
	}))
	mHash := sha256.Sum256(manifestBytes)
	assert.NoError(t, os.WriteFile(filepath.Join(blobsDir, hex.EncodeToString(mHash[:])), manifestBytes, 0o600))

	allLocal, hash, err := GetAllLocalBundles(dir)
	assert.True(t, err == nil && len(allLocal) == 1 && allLocal[0].IsV2() && *hash == imgDigest)
	_, _, err = GetLocalBundles(dir)
	assert.ErrorAs(t, err, &noMatchErr)
	_, _, err = VerifyLocalImageAttestations(context.Background(), dir, nil)
	assert.ErrorContains(t, err, "check options must not be nil")
	atts, ok, err = VerifyLocalImageAttestations(context.Background(), dir, &CheckOpts{
		PQCOnly: true, TrustedMaterial: tm, ClaimVerifier: IntotoSubjectClaimVerifier,
		Identities: []Identity{{Issuer: "https://accounts.example.com", Subject: "alice@example.com"}},
	})
	assert.True(t, err == nil && ok && len(atts) == 1)

	// Symlink escaping blobs/sha256 and tampered blob digest must both be rejected.
	blobFile := filepath.Join(blobsDir, lDigest.Hex)
	outside := filepath.Join(t.TempDir(), "outside.json")
	assert.NoError(t, os.WriteFile(outside, v2Bytes, 0o600))
	assert.NoError(t, os.Remove(blobFile))
	assert.NoError(t, os.Symlink(outside, blobFile))
	_, _, err = GetAllLocalBundles(dir)
	assert.ErrorAs(t, err, &noMatchErr)
	assert.NoError(t, os.Remove(blobFile))
	assert.NoError(t, os.WriteFile(blobFile, append(v2Bytes, ' '), 0o600))
	_, _, err = GetAllLocalBundles(dir)
	assert.ErrorAs(t, err, &noMatchErr)
}
