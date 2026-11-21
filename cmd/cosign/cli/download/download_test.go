//
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

package download

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/test"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestDownloadMixedV1AndV2Bundles(t *testing.T) {
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	must(err)

	img, err := random.Image(128, 1)
	must(err)
	imgDigest, err := img.Digest()
	must(err)
	tagRef, err := name.NewTag(fmt.Sprintf("%s/test/repo:latest", u.Host), name.Insecure)
	must(err)
	must(remote.Write(tagRef, img, remote.WithTransport(srv.Client().Transport)))
	digestRef, err := name.NewDigest(fmt.Sprintf("%s/test/repo@%s", u.Host, imgDigest.String()), name.Insecure)
	must(err)

	rootCert, rootKey, err := test.GenerateRootCa()
	must(err)
	leafCert, _, err := test.GenerateLeafCert("alice@example.com", "https://issuer.example", rootCert, rootKey)
	must(err)

	const predV1, predV2 = "https://example.com/pred/v1", "https://example.com/pred/v2"
	mkStmt := func(pred string) []byte {
		return []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"repo","digest":{"sha256":%q}}],"predicateType":%q,"predicate":{}}`, imgDigest.Hex, pred))
	}

	v1Bytes, err := protojson.Marshal(&protobundle.Bundle{
		MediaType: cbundle.BundleV03MediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leafCert.Raw}},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				PayloadType: "application/vnd.in-toto+json",
				Payload:     mkStmt(predV1),
				Signatures:  []*protodsse.Signature{{Sig: []byte("v1-sig")}},
			},
		},
	})
	must(err)

	mkV2 := func(proofBytes []byte, payload *bundleV2.Payload) []byte {
		b, err := protojson.Marshal(&bundleV2.Bundle{
			MediaType: cbundle.BundleV20MediaType,
			VerificationMaterial: &bundleV2.VerificationMaterial{
				Content: &bundleV2.VerificationMaterial_TransparencyLogProof{TransparencyLogProof: &bundleV2.TransparencyLogProof{Proof: proofBytes}},
			},
			Payload: payload,
		})
		must(err)
		return b
	}
	v2Bytes := mkV2([]byte("tlog-proof"), &bundleV2.Payload{PayloadType: "application/vnd.in-toto+json", Payload: mkStmt(predV2)})
	v2DetachedBytes := mkV2([]byte("detached-proof"), nil)

	ociOpts := []ociremote.Option{
		ociremote.WithRemoteOptions(remote.WithTransport(srv.Client().Transport)),
		ociremote.WithNameOptions(name.Insecure),
	}
	must(ociremote.WriteAttestationNewBundleFormat(digestRef, v1Bytes, predV1, ociOpts...))
	must(ociremote.WriteAttestationNewBundleFormat(digestRef, v2Bytes, predV2, ociOpts...))
	must(ociremote.WriteAttestationNewBundleFormat(digestRef, v2DetachedBytes, "https://sigstore.dev/cosign/sign/v1", ociOpts...))

	regOpts := options.RegistryOptions{
		AllowHTTPRegistry:  true,
		RegistryClientOpts: []remote.Option{remote.WithTransport(srv.Client().Transport)},
	}
	parseMediaTypes := func(t *testing.T, output string) []string {
		t.Helper()
		var mts []string
		for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
			if line == "" {
				continue
			}
			var obj struct {
				MediaType string `json:"mediaType"`
			}
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Fatalf("invalid JSON line %q: %v", line, err)
			}
			mts = append(mts, obj.MediaType)
		}
		return mts
	}

	t.Run("SignatureCmd downloads all v1 and v2 bundles", func(t *testing.T) {
		var out bytes.Buffer
		must(SignatureCmd(ctx, regOpts, digestRef.String(), &out))
		if mts := parseMediaTypes(t, out.String()); len(mts) != 3 {
			t.Fatalf("got %d bundles (%v), want 3", len(mts), mts)
		}
	})

	t.Run("AttestationCmd skips detached v2 bundle without predicate filter", func(t *testing.T) {
		var out bytes.Buffer
		must(AttestationCmd(ctx, regOpts, options.AttestationDownloadOptions{}, digestRef.String(), &out))
		if mts := parseMediaTypes(t, out.String()); len(mts) != 2 {
			t.Fatalf("got %d bundles (%v), want 2 envelope bundles", len(mts), mts)
		}
	})

	t.Run("AttestationCmd filters v1 and v2 bundles by predicate-type", func(t *testing.T) {
		for pred, wantMT := range map[string]string{predV1: cbundle.BundleV03MediaType, predV2: cbundle.BundleV20MediaType} {
			var out bytes.Buffer
			must(AttestationCmd(ctx, regOpts, options.AttestationDownloadOptions{PredicateType: pred}, digestRef.String(), &out))
			if mts := parseMediaTypes(t, out.String()); len(mts) != 1 || mts[0] != wantMT {
				t.Fatalf("pred=%s: got %v, want [%s]", pred, mts, wantMT)
			}
		}
	})

	t.Run("AttestationCmd errors when predicate-type matches nothing", func(t *testing.T) {
		var out bytes.Buffer
		if err := AttestationCmd(ctx, regOpts, options.AttestationDownloadOptions{PredicateType: "https://example.com/pred/missing"}, digestRef.String(), &out); err == nil {
			t.Fatal("expected error for unmatched predicate-type, got nil")
		}
	})
}
