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

package cli

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAttachAndCleanBundleV2Referrer(t *testing.T) {
	ctx := t.Context()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	img, err := random.Image(128, 1)
	require.NoError(t, err)
	imgDigest, err := img.Digest()
	require.NoError(t, err)
	tagRef, err := name.NewTag(fmt.Sprintf("%s/test/pqc:latest", u.Host), name.Insecure)
	require.NoError(t, err)
	require.NoError(t, remote.Write(tagRef, img, remote.WithTransport(srv.Client().Transport)))
	digestRef, err := name.NewDigest(fmt.Sprintf("%s/test/pqc@%s", u.Host, imgDigest.String()), name.Insecure)
	require.NoError(t, err)

	regOpts := options.RegistryOptions{
		AllowHTTPRegistry:  true,
		RegistryClientOpts: []remote.Option{remote.WithTransport(srv.Client().Transport)},
	}
	dir := t.TempDir()
	stmt := fmt.Appendf(nil, `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"pqc","digest":{"sha256":%q}}],"predicateType":"https://sigstore.dev/cosign/sign/v1","predicate":{}}`, imgDigest.Hex)
	v2Att, err := protojson.Marshal(&bundleV2.Bundle{
		MediaType: cbundle.BundleV20MediaType,
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TransparencyLogProof{TransparencyLogProof: &bundleV2.TransparencyLogProof{Proof: []byte("proof")}},
		},
		Payload: &bundleV2.Payload{PayloadType: "application/vnd.in-toto+json", Payload: stmt},
	})
	require.NoError(t, err)
	v2AttPath := filepath.Join(dir, "att.v2.json")
	require.NoError(t, os.WriteFile(v2AttPath, v2Att, 0o600))

	v2Detached, err := protojson.Marshal(&bundleV2.Bundle{
		MediaType: cbundle.BundleV20MediaType,
		VerificationMaterial: &bundleV2.VerificationMaterial{
			Content: &bundleV2.VerificationMaterial_TransparencyLogProof{TransparencyLogProof: &bundleV2.TransparencyLogProof{Proof: []byte("proof")}},
		},
	})
	require.NoError(t, err)
	v2DetachedPath := filepath.Join(dir, "detached.v2.json")
	require.NoError(t, os.WriteFile(v2DetachedPath, v2Detached, 0o600))

	require.Error(t, attach.BundleCmd(ctx, regOpts, []string{v2DetachedPath}, digestRef.String()))
	require.NoError(t, attach.BundleCmd(ctx, regOpts, []string{v2AttPath}, digestRef.String()))

	ociOpts := []ociremote.Option{ociremote.WithRemoteOptions(remote.WithTransport(srv.Client().Transport)), ociremote.WithNameOptions(name.Insecure)}
	bundles, _, err := cosign.GetAllBundles(ctx, digestRef, ociOpts, name.Insecure)
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	require.True(t, bundles[0].IsV2())

	require.NoError(t, CleanCmd(ctx, regOpts, options.CleanTypeReferrer, digestRef.String(), true))
	var noMatch *cosign.ErrNoMatchingAttestations
	_, _, err = cosign.GetAllBundles(ctx, digestRef, ociOpts, name.Insecure)
	require.ErrorAs(t, err, &noMatch)
}
