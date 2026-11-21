//
// Copyright 2021 The Sigstore Authors.
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

package remote

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	bundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle/types"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	"github.com/sigstore/cosign/v3/pkg/oci/signed"
	cosignstatic "github.com/sigstore/cosign/v3/pkg/oci/static"
	ctypes "github.com/sigstore/cosign/v3/pkg/types"
)

func TestWriteSignatures(t *testing.T) {
	rw := remote.Write
	t.Cleanup(func() {
		remoteWrite = rw
	})
	i, err := random.Image(300 /* byteSize */, 7 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	want := 6 // Add 6 signatures
	for i := range want {
		sig, err := cosignstatic.NewSignature(nil, fmt.Sprintf("%d", i))
		if err != nil {
			t.Fatalf("static.NewSignature() = %v", err)
		}
		si, err = mutate.AttachSignatureToImage(si, sig)
		if err != nil {
			t.Fatalf("SignEntity() = %v", err)
		}
	}

	ref := name.MustParseReference("gcr.io/bistroless/static:nonroot")

	remoteWrite = func(_ name.Reference, img v1.Image, _ ...remote.Option) error {
		l, err := img.Layers()
		if err != nil {
			return err
		}

		if got := len(l); got != want {
			t.Errorf("got %d layers, wanted %d", got, want)
		}

		return nil
	}
	if err := WriteSignatures(ref.Context(), si); err != nil {
		t.Fatalf("WriteSignature() = %v", err)
	}
}

func TestWriteAttestations(t *testing.T) {
	rw := remote.Write
	t.Cleanup(func() {
		remoteWrite = rw
	})
	i, err := random.Image(300 /* byteSize */, 7 /* layers */)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	want := 6 // Add 6 attestations
	for i := range want {
		sig, err := cosignstatic.NewAttestation([]byte(fmt.Sprintf("%d", i)))
		if err != nil {
			t.Fatalf("static.NewSignature() = %v", err)
		}
		si, err = mutate.AttachAttestationToImage(si, sig)
		if err != nil {
			t.Fatalf("SignEntity() = %v", err)
		}
	}

	ref := name.MustParseReference("gcr.io/bistroless/static:nonroot")

	remoteWrite = func(_ name.Reference, img v1.Image, _ ...remote.Option) error {
		l, err := img.Layers()
		if err != nil {
			return err
		}

		if got := len(l); got != want {
			t.Errorf("got %d layers, wanted %d", got, want)
		}

		return nil
	}
	if err := WriteAttestations(ref.Context(), si); err != nil {
		t.Fatalf("WriteAttestations() = %v", err)
	}
}

func TestReferrerManifest(t *testing.T) {
	// Test referrerManifest.RawManifest()
	rm := referrerManifest{
		Manifest: v1.Manifest{
			SchemaVersion: 2,
			MediaType:     types.OCIManifestSchema1,
			Config: v1.Descriptor{
				MediaType: "application/vnd.oci.empty.v1+json",
				Digest:    v1.Hash{Algorithm: "sha256", Hex: "abc123"},
				Size:      100,
			},
			Layers: []v1.Descriptor{},
		},
		ArtifactType: "test.artifact.type",
	}

	manifestBytes, err := rm.RawManifest()
	if err != nil {
		t.Fatalf("RawManifest() = %v", err)
	}

	if len(manifestBytes) == 0 {
		t.Error("RawManifest returned empty bytes")
	}

	// Test referrerManifest.MediaType()
	mediaType, err := rm.MediaType()
	if err != nil {
		t.Fatalf("MediaType() = %v", err)
	}
	if mediaType != types.OCIManifestSchema1 {
		t.Errorf("MediaType() = %s, want %s", mediaType, types.OCIManifestSchema1)
	}

	// Test referrerManifest.targetRef()
	repo := name.MustParseReference("gcr.io/test/repo").Context()
	targetRef, err := rm.targetRef(repo)
	if err != nil {
		t.Fatalf("targetRef() = %v", err)
	}
	if targetRef == nil {
		t.Error("targetRef returned nil")
	}
}

func TestTaggableManifest(t *testing.T) {
	// Test taggableManifest.RawManifest()
	tm := taggableManifest{
		raw:       []byte(`{"test":"manifest"}`),
		mediaType: types.DockerManifestSchema2,
	}

	manifestBytes, err := tm.RawManifest()
	if err != nil {
		t.Fatalf("RawManifest() = %v", err)
	}
	if string(manifestBytes) != `{"test":"manifest"}` {
		t.Errorf("RawManifest() = %s, want %s", string(manifestBytes), `{"test":"manifest"}`)
	}

	// Test taggableManifest.MediaType()
	mediaType, err := tm.MediaType()
	if err != nil {
		t.Fatalf("MediaType() = %v", err)
	}
	if mediaType != types.DockerManifestSchema2 {
		t.Errorf("MediaType() = %s, want %s", mediaType, types.DockerManifestSchema2)
	}
}

func TestWriteAttestationNewBundleFormat(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	bundleBytes := []byte(`{"payload":"test","signatures":[]}`)
	predicateType := "https://test.predicate.type"
	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err := WriteAttestationNewBundleFormat(digest, bundleBytes, predicateType)
	if err != nil {
		t.Fatalf("WriteAttestationNewBundleFormat() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Error("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Errorf("Expected referrerManifest, got %T", capturedManifest)
		return
	}

	// Verify the artifact type contains bundle media type
	if refManifest.ArtifactType == "" {
		t.Error("Expected ArtifactType to be set")
	}

	// Verify annotations are set correctly
	if refManifest.Annotations["dev.sigstore.bundle.content"] != "dsse-envelope" {
		t.Errorf("Expected bundle.content annotation to be 'dsse-envelope', got %s", refManifest.Annotations["dev.sigstore.bundle.content"])
	}
	if refManifest.Annotations["dev.sigstore.bundle.predicateType"] != predicateType {
		t.Errorf("Expected predicateType annotation to be %s, got %s", predicateType, refManifest.Annotations["dev.sigstore.bundle.predicateType"])
	}

	// Verify the layer has the org.opencontainers.image.title annotation
	if len(refManifest.Layers) == 0 {
		t.Fatal("Expected at least one layer in manifest")
	}
	layer := refManifest.Layers[0]
	if layer.Annotations == nil {
		t.Fatal("Expected layer to have annotations, but Annotations is nil")
	}
	title, ok := layer.Annotations["org.opencontainers.image.title"]
	if !ok {
		t.Error("Expected layer to have 'org.opencontainers.image.title' annotation, but it was not found")
	}
	// Verify the title format matches {algorithm}-{hex}.sigstore.json
	expectedTitle := fmt.Sprintf("%s-%s.sigstore.json", layer.Digest.Algorithm, layer.Digest.Hex)
	if title != expectedTitle {
		t.Errorf("Expected layer title to be %s, got %s", expectedTitle, title)
	}
}

func TestWriteAttestationNewBundleFormat_MediaTypes(t *testing.T) {
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)
	predicateType := "https://sigstore.dev/cosign/sign/v1"

	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	testCases := []struct {
		name          string
		bundleBytes   []byte
		wantMediaType string
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:          "bundle v2.0 uses v2.0 media type and artifactType",
			bundleBytes:   []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v2.0+json","verificationMaterial":{}}`),
			wantMediaType: bundle.BundleV20MediaType,
		},
		{
			name:          "bundle v2.0 with snake_case media_type uses v2.0 media type",
			bundleBytes:   []byte(`{"media_type":"application/vnd.dev.sigstore.bundle.v2.0+json","verification_material":{}}`),
			wantMediaType: bundle.BundleV20MediaType,
		},
		{
			name:          "conflicting mediaType and media_type fails closed",
			bundleBytes:   []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","media_type":"application/vnd.dev.sigstore.bundle.v2.0+json"}`),
			wantErr:       true,
			wantErrSubstr: "both mediaType and media_type",
		},
		{
			name:          "bundle v0.3 uses v0.3 media type and artifactType",
			bundleBytes:   []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{}}`),
			wantMediaType: bundle.BundleV03MediaType,
		},
		{
			name:          "legacy parameter-form v0.3 normalizes to OCI-safe v0.3 media type",
			bundleBytes:   []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","verificationMaterial":{}}`),
			wantMediaType: bundle.BundleV03MediaType,
		},
		{
			name:          "missing mediaType defaults to v0.3",
			bundleBytes:   []byte(`{"payload":"test"}`),
			wantMediaType: bundle.BundleV03MediaType,
		},
		{
			name:          "v0.1 bundle rejected",
			bundleBytes:   []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.1"}`),
			wantErr:       true,
			wantErrSubstr: "unsupported bundle media type",
		},
		{
			name:          "unsupported mediaType fails closed",
			bundleBytes:   []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v9.9+json"}`),
			wantErr:       true,
			wantErrSubstr: "unsupported bundle media type",
		},
		{
			name:          "non-string mediaType fails closed",
			bundleBytes:   []byte(`{"mediaType":123}`),
			wantErr:       true,
			wantErrSubstr: "invalid bundle mediaType field",
		},
		{
			name:          "empty string mediaType fails closed",
			bundleBytes:   []byte(`{"mediaType":""}`),
			wantErr:       true,
			wantErrSubstr: "invalid bundle mediaType field",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var capturedManifest remote.Taggable
			remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
				capturedManifest = manifest
				return nil
			}

			err := WriteAttestationNewBundleFormat(digest, tc.bundleBytes, predicateType)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErrSubstr, err)
				}
				if capturedManifest != nil {
					t.Fatal("expected remotePut not to be called on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("WriteAttestationNewBundleFormat: %v", err)
			}
			refManifest, ok := capturedManifest.(referrerManifest)
			if !ok {
				t.Fatalf("expected referrerManifest, got %T", capturedManifest)
			}
			if refManifest.ArtifactType != tc.wantMediaType {
				t.Errorf("manifest ArtifactType = %q, want %q", refManifest.ArtifactType, tc.wantMediaType)
			}
			if refManifest.Config.ArtifactType != tc.wantMediaType {
				t.Errorf("config ArtifactType = %q, want %q", refManifest.Config.ArtifactType, tc.wantMediaType)
			}
			rawJSON, err := refManifest.RawManifest()
			if err != nil {
				t.Fatalf("RawManifest: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(rawJSON, &decoded); err != nil {
				t.Fatalf("json.Unmarshal(RawManifest): %v", err)
			}
			if decoded["artifactType"] != tc.wantMediaType {
				t.Errorf("RawManifest artifactType = %v, want %q", decoded["artifactType"], tc.wantMediaType)
			}
			if len(refManifest.Layers) != 1 {
				t.Fatalf("expected 1 layer, got %d", len(refManifest.Layers))
			}
			if string(refManifest.Layers[0].MediaType) != tc.wantMediaType {
				t.Errorf("layer MediaType = %q, want %q", refManifest.Layers[0].MediaType, tc.wantMediaType)
			}
		})
	}
}

func TestWriteAttestationsReferrer(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Create a test signed entity with attestations
	i, err := random.Image(300, 1)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	// Add an attestation
	att, err := cosignstatic.NewAttestation([]byte("test-attestation"))
	if err != nil {
		t.Fatalf("static.NewAttestation() = %v", err)
	}
	si, err = mutate.AttachAttestationToImage(si, att)
	if err != nil {
		t.Fatalf("AttachAttestationToImage() = %v", err)
	}

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err = WriteAttestationsReferrer(digest, si)
	if err != nil {
		t.Fatalf("WriteAttestationsReferrer() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Error("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Errorf("Expected referrerManifest, got %T", capturedManifest)
		return
	}

	// Verify the artifact type is set to in-toto payload type
	if refManifest.ArtifactType != ctypes.IntotoPayloadType {
		t.Errorf("Expected ArtifactType to be %s, got %s", ctypes.IntotoPayloadType, refManifest.ArtifactType)
	}

	// Verify annotations include created timestamp
	if _, exists := refManifest.Annotations["org.opencontainers.image.created"]; !exists {
		t.Error("Expected created annotation to be set")
	}

	// Verify we have at least one layer
	if len(refManifest.Layers) == 0 {
		t.Fatal("Expected at least one layer in manifest")
	}
	// Verify each layer has the org.opencontainers.image.title annotation
	for i, layer := range refManifest.Layers {
		if layer.Annotations == nil {
			t.Fatalf("Expected layer %d to have annotations, but Annotations is nil", i)
		}
		title, ok := layer.Annotations["org.opencontainers.image.title"]
		if !ok {
			t.Errorf("Expected layer %d to have 'org.opencontainers.image.title' annotation, but it was not found", i)
		}
		// Verify the title format matches {algorithm}-{hex}.sigstore.json
		expectedTitle := fmt.Sprintf("%s-%s.sigstore.json", layer.Digest.Algorithm, layer.Digest.Hex)
		if title != expectedTitle {
			t.Errorf("Expected layer %d title to be %s, got %s", i, expectedTitle, title)
		}
	}
}

func TestWriteAttestationsReferrerPreservesAnnotations(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Create a test signed entity with attestations that have annotations
	i, err := random.Image(300, 1)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	// Create attestation with certificate chain and custom annotations
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n")
	chainPEM := []byte("-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----\n")
	att, err := cosignstatic.NewAttestation([]byte("test-attestation"),
		cosignstatic.WithCertChain(certPEM, chainPEM),
		cosignstatic.WithAnnotations(map[string]string{
			"predicateType": "https://cosign.sigstore.dev/attestation/v1",
		}),
	)
	if err != nil {
		t.Fatalf("static.NewAttestation() = %v", err)
	}
	si, err = mutate.AttachAttestationToImage(si, att)
	if err != nil {
		t.Fatalf("AttachAttestationToImage() = %v", err)
	}

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err = WriteAttestationsReferrer(digest, si)
	if err != nil {
		t.Fatalf("WriteAttestationsReferrer() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Fatal("Expected manifest to be uploaded, but none was captured")
	}

	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Fatalf("Expected referrerManifest, got %T", capturedManifest)
	}

	if len(refManifest.Layers) == 0 {
		t.Fatal("Expected at least one layer in manifest")
	}

	// Verify per-layer annotations are preserved (this is the bug fix)
	layerAnnotations := refManifest.Layers[0].Annotations
	if layerAnnotations == nil {
		t.Fatal("Expected layer annotations to be preserved, got nil")
	}

	expectedKeys := []string{
		"dev.sigstore.cosign/certificate",
		"dev.sigstore.cosign/chain",
		"predicateType",
		"org.opencontainers.image.title",
	}
	for _, key := range expectedKeys {
		if _, exists := layerAnnotations[key]; !exists {
			t.Errorf("Expected layer annotation %q to be present", key)
		}
	}
}

func TestWriteReferrer(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Create a test layer
	testLayer := static.NewLayer([]byte("test-data"), "application/octet-stream")
	layers := []v1.Layer{testLayer}
	annotations := map[string]string{
		"test.annotation": "test-value",
	}
	artifactType := "test.artifact.type"

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err := WriteReferrer(digest, artifactType, layers, annotations)
	if err != nil {
		t.Fatalf("WriteReferrer() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Error("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Errorf("Expected referrerManifest, got %T", capturedManifest)
		return
	}

	// Verify the artifact type is set correctly
	if refManifest.ArtifactType != artifactType {
		t.Errorf("Expected ArtifactType to be %s, got %s", artifactType, refManifest.ArtifactType)
	}

	// Verify annotations are passed through
	if refManifest.Annotations["test.annotation"] != "test-value" {
		t.Errorf("Expected annotation to be 'test-value', got %s", refManifest.Annotations["test.annotation"])
	}

	// Verify we have the expected number of layers
	if len(refManifest.Layers) != 1 {
		t.Errorf("Expected 1 layer, got %d", len(refManifest.Layers))
	}

	// Verify the layer has the org.opencontainers.image.title annotation
	if len(refManifest.Layers) == 0 {
		t.Fatal("Expected at least one layer in manifest")
	}
	layer := refManifest.Layers[0]
	if layer.Annotations == nil {
		t.Fatal("Expected layer to have annotations, but Annotations is nil")
	}
	title, ok := layer.Annotations["org.opencontainers.image.title"]
	if !ok {
		t.Error("Expected layer to have 'org.opencontainers.image.title' annotation, but it was not found")
	}
	// Verify the title format matches {algorithm}-{hex}.sigstore.json
	expectedTitle := fmt.Sprintf("%s-%s.sigstore.json", layer.Digest.Algorithm, layer.Digest.Hex)
	if title != expectedTitle {
		t.Errorf("Expected layer title to be %s, got %s", expectedTitle, title)
	}

	// Verify the subject is set
	if refManifest.Subject == nil {
		t.Error("Expected Subject to be set")
	}

	// Verify config descriptor
	if refManifest.Config.ArtifactType != artifactType {
		t.Errorf("Expected Config.ArtifactType to be %s, got %s", artifactType, refManifest.Config.ArtifactType)
	}
}

func TestWriteReferrerErrorHandling(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	t.Cleanup(func() {
		remoteHead = origHead
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)
	layers := []v1.Layer{}
	annotations := map[string]string{}

	// Mock remoteHead to return an error
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return nil, fmt.Errorf("remote head failed")
	}

	err := WriteReferrer(digest, "test.type", layers, annotations)
	if err == nil {
		t.Error("Expected error from WriteReferrer when remoteHead fails")
	}
	if !strings.Contains(err.Error(), "remote head failed") {
		t.Errorf("Expected error to contain 'remote head failed', got %v", err)
	}
}

func TestWriteSignaturesExperimentalOCI(t *testing.T) {
	// Save original functions
	origHead := remoteHead
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteHead = origHead
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	digest := name.MustParseReference("gcr.io/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").(name.Digest)

	// Create a test signed entity with signatures
	i, err := random.Image(300, 1)
	if err != nil {
		t.Fatalf("random.Image() = %v", err)
	}
	si := signed.Image(i)

	// Add a signature
	sig, err := cosignstatic.NewSignature(nil, "test-sig")
	if err != nil {
		t.Fatalf("static.NewSignature() = %v", err)
	}
	si, err = mutate.AttachSignatureToImage(si, sig)
	if err != nil {
		t.Fatalf("AttachSignatureToImage() = %v", err)
	}

	// Mock remoteHead to return a descriptor
	remoteHead = func(name.Reference, ...remote.Option) (*v1.Descriptor, error) {
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}

	// Mock remoteWriteLayer to succeed
	remoteWriteLayer = func(name.Repository, v1.Layer, ...remote.Option) error {
		return nil
	}

	// Mock remotePut to capture the manifest
	var capturedManifest remote.Taggable
	remotePut = func(_ name.Reference, manifest remote.Taggable, _ ...remote.Option) error {
		capturedManifest = manifest
		return nil
	}

	err = WriteSignaturesExperimentalOCI(digest, si)
	if err != nil {
		t.Fatalf("WriteSignaturesExperimentalOCI() = %v", err)
	}

	// Verify that a manifest was uploaded
	if capturedManifest == nil {
		t.Fatal("Expected manifest to be uploaded, but none was captured")
	}

	// Verify it's a referrerManifest (not a taggableManifest)
	refManifest, ok := capturedManifest.(referrerManifest)
	if !ok {
		t.Fatalf("Expected referrerManifest, got %T", capturedManifest)
	}

	// Verify the top-level artifactType is set to the cosign signature type
	const wantArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"
	if refManifest.ArtifactType != wantArtifactType {
		t.Errorf("ArtifactType = %q, want %q", refManifest.ArtifactType, wantArtifactType)
	}

	// Verify the subject is set
	if refManifest.Subject == nil {
		t.Error("Expected Subject to be set")
	}

	// Verify the manifest JSON serialization includes the top-level artifactType field
	manifestBytes, err := refManifest.RawManifest()
	if err != nil {
		t.Fatalf("RawManifest() = %v", err)
	}
	if !strings.Contains(string(manifestBytes), `"artifactType"`) {
		t.Errorf("Expected manifest JSON to contain artifactType field, got: %s", string(manifestBytes))
	}

	// Verify WithTargetRepository and WithNameOptions(name.Insecure) preserve the HTTP scheme
	// on both the subject HEAD request and the target repository layer/manifest uploads.
	httpDigest := name.MustParseReference("registry.local:5000/test/image@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", name.Insecure).(name.Digest)
	targetRepo, err := name.NewRepository("registry.local:5000/target/repo", name.Insecure)
	if err != nil {
		t.Fatalf("name.NewRepository() = %v", err)
	}
	var headRef name.Reference
	remoteHead = func(ref name.Reference, _ ...remote.Option) (*v1.Descriptor, error) {
		headRef = ref
		return &v1.Descriptor{
			MediaType: types.DockerManifestSchema2,
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "abcdef1234567890"},
			Size:      100,
		}, nil
	}
	var layerRepos []string
	remoteWriteLayer = func(repo name.Repository, _ v1.Layer, _ ...remote.Option) error {
		layerRepos = append(layerRepos, repo.Name())
		return nil
	}
	var putRef name.Reference
	remotePut = func(ref name.Reference, _ remote.Taggable, _ ...remote.Option) error {
		putRef = ref
		return nil
	}
	if err := WriteSignaturesExperimentalOCI(httpDigest, si, WithTargetRepository(targetRepo), WithNameOptions(name.Insecure)); err != nil {
		t.Fatalf("WriteSignaturesExperimentalOCI(WithTargetRepository) = %v", err)
	}
	if headRef == nil || headRef.Context().Scheme() != "http" {
		t.Errorf("remoteHead ref = %v (scheme %q), want http scheme", headRef, headRef.Context().Scheme())
	}
	for _, gotRepo := range layerRepos {
		if gotRepo != targetRepo.Name() {
			t.Errorf("remoteWriteLayer repo = %q, want %q", gotRepo, targetRepo.Name())
		}
	}
	if putRef == nil || putRef.Context().Name() != targetRepo.Name() {
		t.Errorf("remotePut ref = %v, want repo %q", putRef, targetRepo.Name())
	}
	if putRef.Context().Scheme() != "http" {
		t.Errorf("remotePut scheme = %q, want http", putRef.Context().Scheme())
	}
}

// stubSignedImageIndex is a SignedImageIndex with no image, signatures, or attestations,
// so WriteSignedImageIndexImages only exercises the bundle-referrer path.
type stubSignedImageIndex struct{}

func (stubSignedImageIndex) MediaType() (types.MediaType, error) { return empty.Index.MediaType() }
func (stubSignedImageIndex) Digest() (v1.Hash, error)            { return empty.Index.Digest() }
func (stubSignedImageIndex) Size() (int64, error)                { return empty.Index.Size() }
func (stubSignedImageIndex) IndexManifest() (*v1.IndexManifest, error) {
	return empty.Index.IndexManifest()
}
func (stubSignedImageIndex) RawManifest() ([]byte, error)      { return empty.Index.RawManifest() }
func (stubSignedImageIndex) Image(h v1.Hash) (v1.Image, error) { return empty.Index.Image(h) }
func (stubSignedImageIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	return empty.Index.ImageIndex(h)
}
func (stubSignedImageIndex) SignedImageIndex(v1.Hash) (oci.SignedImageIndex, error) {
	return nil, nil
}
func (stubSignedImageIndex) SignedImage(v1.Hash) (oci.SignedImage, error) { return nil, nil }
func (stubSignedImageIndex) Signatures() (oci.Signatures, error)          { return nil, nil }
func (stubSignedImageIndex) Attestations() (oci.Signatures, error)        { return nil, nil }
func (stubSignedImageIndex) Attachment(string) (oci.File, error)          { return nil, nil }

func TestWriteSignedImageIndexImages_BundleUploadOrder(t *testing.T) {
	origWriteLayer := remoteWriteLayer
	origPut := remotePut
	t.Cleanup(func() {
		remoteWriteLayer = origWriteLayer
		remotePut = origPut
	})

	subjectDigest := v1.Hash{Algorithm: "sha256", Hex: "ef637aabc052029acfd192d8ed6674a5249a8783e551c08db71e321ca11b421d"}
	bundleBytes := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)
	bundleLayer := static.NewLayer(bundleBytes, types.MediaType(bundle.BundleV03MediaType))
	layerDigest, err := bundleLayer.Digest()
	if err != nil {
		t.Fatalf("bundleLayer.Digest() = %v", err)
	}

	manifest := &v1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: v1.Descriptor{
			MediaType: types.MediaType("application/vnd.oci.empty.v1+json"),
			Digest:    v1.Hash{Algorithm: "sha256", Hex: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
			Size:      2,
		},
		Layers: []v1.Descriptor{{
			MediaType: types.MediaType(bundle.BundleV03MediaType),
			Digest:    layerDigest,
			Size:      int64(len(bundleBytes)),
		}},
		Subject: &v1.Descriptor{Digest: subjectDigest},
		Annotations: map[string]string{
			BundlePredicateType: "https://sigstore.dev/cosign/sign/v1",
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal() = %v", err)
	}
	manifestDigest, _, err := v1.SHA256(strings.NewReader(string(manifestBytes)))
	if err != nil {
		t.Fatalf("v1.SHA256() = %v", err)
	}

	dir := t.TempDir()
	blobDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() = %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, layerDigest.Hex), bundleBytes, 0o644); err != nil {
		t.Fatalf("WriteFile(layer) = %v", err)
	}
	if err := os.WriteFile(filepath.Join(blobDir, manifestDigest.Hex), manifestBytes, 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) = %v", err)
	}

	var callOrder []string
	remoteWriteLayer = func(_ name.Repository, _ v1.Layer, _ ...remote.Option) error {
		callOrder = append(callOrder, "layer")
		return nil
	}
	remotePut = func(_ name.Reference, _ remote.Taggable, _ ...remote.Option) error {
		callOrder = append(callOrder, "manifest")
		return nil
	}

	ref, err := name.NewDigest("gcr.io/test/image@sha256:ef637aabc052029acfd192d8ed6674a5249a8783e551c08db71e321ca11b421d")
	if err != nil {
		t.Fatalf("name.NewDigest() = %v", err)
	}
	if err := WriteSignedImageIndexImages(ref, stubSignedImageIndex{}, dir); err != nil {
		t.Fatalf("WriteSignedImageIndexImages() = %v", err)
	}

	// Expect config layer + bundle layer, then manifest.
	want := []string{"layer", "layer", "manifest"}
	if len(callOrder) != len(want) {
		t.Fatalf("call order = %v, want %v", callOrder, want)
	}
	for i, step := range want {
		if callOrder[i] != step {
			t.Fatalf("call order = %v, want %v", callOrder, want)
		}
	}
}

func TestWriteSignedImageIndexImages_PreservesBundleV2MediaType(t *testing.T) {
	subjectDigest := v1.Hash{Algorithm: "sha256", Hex: "ef637aabc052029acfd192d8ed6674a5249a8783e551c08db71e321ca11b421d"}
	v2Bytes := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v2.0+json"}`)
	layerDigest, err := static.NewLayer(v2Bytes, types.MediaType(bundle.BundleV20MediaType)).Digest()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		manifestArtType string
		layerMediaType  types.MediaType
		layerDigest     v1.Hash
		symlinkEscape   bool
		wantErr         bool
	}{
		{"explicit v2 artifactType and layer mediaType", bundle.BundleV20MediaType, types.MediaType(bundle.BundleV20MediaType), layerDigest, false, false},
		{"fallback detection from v2 bundle JSON when omitted", "", "", layerDigest, false, false},
		{"rejects unsupported layer digest algorithm", bundle.BundleV20MediaType, types.MediaType(bundle.BundleV20MediaType), v1.Hash{Algorithm: "sha512", Hex: strings.Repeat("a", 128)}, false, true},
		{"rejects symlink escaping blobs dir", bundle.BundleV20MediaType, types.MediaType(bundle.BundleV20MediaType), layerDigest, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origWriteLayer, origPut := remoteWriteLayer, remotePut
			t.Cleanup(func() { remoteWriteLayer, remotePut = origWriteLayer, origPut })

			manifest := &v1.Manifest{
				SchemaVersion: 2,
				MediaType:     types.OCIManifestSchema1,
				ArtifactType:  tc.manifestArtType,
				Config: v1.Descriptor{
					MediaType: types.MediaType("application/vnd.oci.empty.v1+json"),
					Digest:    v1.Hash{Algorithm: "sha256", Hex: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
					Size:      2,
				},
				Layers:      []v1.Descriptor{{MediaType: tc.layerMediaType, Digest: tc.layerDigest, Size: int64(len(v2Bytes))}},
				Subject:     &v1.Descriptor{Digest: subjectDigest},
				Annotations: map[string]string{BundlePredicateType: "https://sigstore.dev/cosign/sign/v1"},
			}
			manifestBytes, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			manifestDigest, _, err := v1.SHA256(strings.NewReader(string(manifestBytes)))
			if err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			blobDir := filepath.Join(dir, "blobs", "sha256")
			if err := os.MkdirAll(blobDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.symlinkEscape {
				outside := filepath.Join(t.TempDir(), "secret")
				if err := os.WriteFile(outside, v2Bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(blobDir, layerDigest.Hex)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(blobDir, layerDigest.Hex), v2Bytes, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("COSIGN_MAX_ATTACHMENT_SIZE", "4096")
			if err := os.Mkdir(filepath.Join(blobDir, "subdir"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blobDir, strings.Repeat("f", 64)), make([]byte, 5000), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blobDir, manifestDigest.Hex), manifestBytes, 0o600); err != nil {
				t.Fatal(err)
			}

			var uploadedLayers []v1.Layer
			var uploadedManifest remote.Taggable
			remoteWriteLayer = func(_ name.Repository, l v1.Layer, _ ...remote.Option) error {
				uploadedLayers = append(uploadedLayers, l)
				return nil
			}
			remotePut = func(_ name.Reference, m remote.Taggable, _ ...remote.Option) error {
				uploadedManifest = m
				return nil
			}

			ref, err := name.NewDigest("gcr.io/test/image@" + subjectDigest.String())
			if err != nil {
				t.Fatal(err)
			}
			err = WriteSignedImageIndexImages(ref, stubSignedImageIndex{}, dir)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("WriteSignedImageIndexImages() = %v", err)
			}
			if len(uploadedLayers) != 2 {
				t.Fatalf("uploaded %d layers, want 2", len(uploadedLayers))
			}
			if gotMT, err := uploadedLayers[1].MediaType(); err != nil || string(gotMT) != bundle.BundleV20MediaType {
				t.Errorf("uploaded bundle layer MediaType = %q (err=%v), want %q", gotMT, err, bundle.BundleV20MediaType)
			}
			rawManifest, err := uploadedManifest.RawManifest()
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				ArtifactType string          `json:"artifactType"`
				Layers       []v1.Descriptor `json:"layers"`
			}
			if err := json.Unmarshal(rawManifest, &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed.ArtifactType != bundle.BundleV20MediaType {
				t.Errorf("manifest ArtifactType = %q, want %q", parsed.ArtifactType, bundle.BundleV20MediaType)
			}
			if len(parsed.Layers) != 1 || string(parsed.Layers[0].MediaType) != bundle.BundleV20MediaType {
				t.Errorf("manifest Layers = %v, want MediaType %q", parsed.Layers, bundle.BundleV20MediaType)
			}
		})
	}
}
