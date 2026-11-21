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
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	payloadsize "github.com/sigstore/cosign/v3/internal/pkg/cosign/payload/size"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestParseAndLoadBundle(t *testing.T) {
	digest := sha256.Sum256([]byte("hello"))
	mkV1 := func(mt string) []byte {
		b, err := protojson.Marshal(&protobundle.Bundle{
			MediaType:            mt,
			VerificationMaterial: &protobundle.VerificationMaterial{Content: &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{Hint: "t"}}},
			Content:              &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: digest[:]}, Signature: []byte("sig")}},
		})
		require.NoError(t, err)
		return b
	}
	v2Bytes, err := protojson.Marshal(&bundleV2.Bundle{
		MediaType:            BundleV20MediaType,
		VerificationMaterial: &bundleV2.VerificationMaterial{Content: &bundleV2.VerificationMaterial_TransparencyLogProof{TransparencyLogProof: &bundleV2.TransparencyLogProof{Proof: []byte("p")}}},
		Payload:              &bundleV2.Payload{PayloadType: "application/vnd.in-toto+json", Payload: []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)},
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		name           string
		data           []byte
		wantV1, wantV2 bool
		wantErr        string
	}{
		{"v0.3", mkV1(BundleV03MediaType), true, false, ""},
		{"legacy v0.3", mkV1("application/vnd.dev.sigstore.bundle+json;version=0.3"), true, false, ""},
		{"v0.2", mkV1("application/vnd.dev.sigstore.bundle+json;version=0.2"), true, false, ""},
		{"v0.1", mkV1("application/vnd.dev.sigstore.bundle+json;version=0.1"), true, false, ""},
		{"v2.0", v2Bytes, false, true, ""},
		{"invalid JSON", []byte("not-json"), false, false, "parsing bundle JSON"},
		{"null JSON", []byte("null"), false, false, "missing mediaType"},
		{"missing mediaType", []byte(`{}`), false, false, "missing mediaType"},
		{"case-variant", []byte(`{"MediaType":"application/vnd.dev.sigstore.bundle.v2.0+json"}`), false, false, "missing mediaType"},
		{"snake_case v2.0", []byte(`{"media_type":"application/vnd.dev.sigstore.bundle.v2.0+json","verification_material":{"transparency_log_proof":{"proof":"cA=="}}}`), false, true, ""},
		{"conflicting keys", []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v2.0+json","media_type":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), false, false, "both mediaType and media_type"},
		{"null mediaType", []byte(`{"mediaType":null}`), false, false, "invalid bundle mediaType"},
		{"empty mediaType", []byte(`{"mediaType":""}`), false, false, "invalid bundle mediaType"},
		{"non-string mediaType", []byte(`{"mediaType":123}`), false, false, "invalid bundle mediaType"},
		{"unsupported v1.0", []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v1.0+json"}`), false, false, "unsupported bundle media type"},
		{"unsupported v2.1", []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v2.1+json"}`), false, false, "unsupported bundle media type"},
		{"unsupported v0.4", []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.4+json"}`), false, false, "validating v1 bundle"},
		{"v2 missing material", []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v2.0+json"}`), false, false, "validating v2 bundle"},
		{"v2 unknown field", []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v2.0+json","unknownField":1}`), false, false, "unmarshaling v2 bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loaded, err := ParseBundle(tc.data)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.True(t, loaded.IsV1() == tc.wantV1 && loaded.IsV2() == tc.wantV2)
			marshaled, err := loaded.MarshalJSON()
			require.NoError(t, err)
			reparsed, err := ParseBundle(marshaled)
			require.NoError(t, err)
			require.True(t, reparsed.IsV1() == tc.wantV1 && reparsed.IsV2() == tc.wantV2)
		})
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.sigstore.json")
	require.NoError(t, os.WriteFile(p, v2Bytes, 0o600))
	loaded, err := LoadBundleFromPath(p)
	require.NoError(t, err)
	require.True(t, loaded.IsV2())
	_, err = LoadBundleFromPath("")
	require.ErrorContains(t, err, "must not be empty")
	_, err = LoadBundleFromPath(filepath.Join(dir, "missing.json"))
	require.Error(t, err)

	t.Setenv(env.VariableMaxAttachmentSize.String(), "64")
	big := filepath.Join(dir, "big.json")
	require.NoError(t, os.WriteFile(big, []byte(strings.Repeat("a", 128)), 0o600))
	var maxErr *payloadsize.MaxLayerSizeExceeded
	_, err = LoadBundleFromPath(big)
	require.ErrorAs(t, err, &maxErr)

	var nilLoaded *LoadedBundle
	dual := &LoadedBundle{V1: &sgbundle.Bundle{}, V2: &sgbundle.BundleV2{}}
	require.False(t, nilLoaded.IsV1() || nilLoaded.IsV2() || dual.IsV1() || dual.IsV2())
	for _, bad := range []*LoadedBundle{nilLoaded, {}, dual} {
		_, err := bad.MarshalJSON()
		require.Error(t, err)
	}
}
