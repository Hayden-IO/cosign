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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	payloadsize "github.com/sigstore/cosign/v3/internal/pkg/cosign/payload/size"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

const bundleMediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// LoadedBundle holds a parsed Sigstore bundle of either v1 (v0.1–v0.3) or v2 (v2.0) format.
// Exactly one of V1 or V2 is non-nil when returned by ParseBundle or LoadBundleFromPath.
type LoadedBundle struct {
	V1 *sgbundle.Bundle
	V2 *sgbundle.BundleV2
}

// IsV1 reports whether this LoadedBundle contains solely a v1 (v0.1–v0.3) Sigstore bundle.
func (b *LoadedBundle) IsV1() bool {
	return b != nil && b.V1 != nil && b.V2 == nil
}

// IsV2 reports whether this LoadedBundle contains solely a v2 (v2.0) Sigstore bundle.
func (b *LoadedBundle) IsV2() bool {
	return b != nil && b.V2 != nil && b.V1 == nil
}

// MarshalJSON serializes the underlying v1 or v2 bundle to protobuf JSON.
func (b *LoadedBundle) MarshalJSON() ([]byte, error) {
	switch {
	case b == nil:
		return nil, errors.New("empty loaded bundle")
	case b.V1 != nil && b.V2 != nil:
		return nil, errors.New("loaded bundle cannot contain both v1 and v2 bundles")
	case b.V1 != nil:
		return b.V1.MarshalJSON()
	case b.V2 != nil:
		return b.V2.MarshalJSON()
	default:
		return nil, errors.New("empty loaded bundle")
	}
}

func isV1BundleMediaType(mediaType string) bool {
	switch mediaType {
	case bundleMediaTypePrefix + "+json;version=0.1",
		bundleMediaTypePrefix + "+json;version=0.2",
		bundleMediaTypePrefix + "+json;version=0.3":
		return true
	}
	return strings.HasPrefix(mediaType, bundleMediaTypePrefix+".v0.") && strings.HasSuffix(mediaType, "+json")
}

// ParseBundle parses a JSON-encoded Sigstore v1 (v0.1–v0.3) or v2 (v2.0) bundle
// by inspecting its top-level mediaType field. Unknown or missing media types fail closed.
func ParseBundle(data []byte, opts ...sgbundle.Option) (*LoadedBundle, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing bundle JSON: %w", err)
	}
	mtRaw, hasCamel := raw["mediaType"]
	mtSnake, hasSnake := raw["media_type"]
	if hasCamel && hasSnake {
		return nil, errors.New("bundle contains both mediaType and media_type fields")
	}
	if !hasCamel && !hasSnake {
		return nil, errors.New("bundle missing mediaType field")
	}
	if !hasCamel {
		mtRaw = mtSnake
	}
	var mediaType string
	if err := json.Unmarshal(mtRaw, &mediaType); err != nil || mediaType == "" {
		return nil, errors.New("invalid bundle mediaType field")
	}

	switch {
	case mediaType == BundleV20MediaType:
		pb := &bundleV2.Bundle{}
		if err := protojson.Unmarshal(data, pb); err != nil {
			return nil, fmt.Errorf("unmarshaling v2 bundle: %w", err)
		}
		b2, err := sgbundle.NewBundleV2(pb)
		if err != nil {
			return nil, fmt.Errorf("validating v2 bundle: %w", err)
		}
		return &LoadedBundle{V2: b2}, nil
	case isV1BundleMediaType(mediaType):
		pb := &protobundle.Bundle{}
		if err := protojson.Unmarshal(data, pb); err != nil {
			return nil, fmt.Errorf("unmarshaling v1 bundle: %w", err)
		}
		b1, err := sgbundle.NewBundle(pb, opts...)
		if err != nil {
			return nil, fmt.Errorf("validating v1 bundle: %w", err)
		}
		return &LoadedBundle{V1: b1}, nil
	default:
		return nil, fmt.Errorf("unsupported bundle media type: %q", mediaType)
	}
}

// LoadBundleFromPath reads a Sigstore v1 or v2 bundle JSON file from path (capped at
// payloadsize.MaxSize) and parses it.
func LoadBundleFromPath(path string, opts ...sgbundle.Option) (*LoadedBundle, error) {
	if path == "" {
		return nil, errors.New("bundle path must not be empty")
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	maxSize := payloadsize.MaxSize()
	limit := min(maxSize, uint64(math.MaxInt64-1))
	contents, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(contents)) > maxSize {
		return nil, payloadsize.NewMaxLayerSizeExceeded(uint64(len(contents)), maxSize)
	}
	return ParseBundle(contents, opts...)
}
