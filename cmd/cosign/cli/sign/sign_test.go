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

package sign

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/types"
	bundleV2 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v2"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// TestSignCmdLocalKeyAndSk verifies the SignCmd returns an error
// if both a local key path and a sk are specified
func TestSignCmdLocalKeyAndSk(t *testing.T) {
	ro := &options.RootOptions{Timeout: options.DefaultTimeout}

	for _, ko := range []options.KeyOpts{
		// local and sk keys
		{
			KeyRef:   "testLocalPath",
			PassFunc: generate.GetPass,
			Sk:       true,
		},
	} {
		so := options.SignOptions{}
		err := SignCmd(t.Context(), ro, ko, so, nil)
		if (errors.Is(err, &options.KeyParseError{}) == false) {
			t.Fatal("expected KeyParseError")
		}
	}
}

func TestInTotoStatementHasPredicate(t *testing.T) {
	annoStruct, _ := structpb.NewStruct(map[string]any{})
	subject := intotov1.ResourceDescriptor{
		Digest:      map[string]string{"sha256": "deadbeef"},
		Annotations: annoStruct,
	}

	statement := &intotov1.Statement{
		Type:          intotov1.StatementTypeUri,
		Subject:       []*intotov1.ResourceDescriptor{&subject},
		PredicateType: types.CosignSignPredicateType,
		Predicate:     &structpb.Struct{},
	}

	payload, err := protojson.Marshal(statement)
	if err != nil {
		t.Fatalf("failed to marshal statement: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if _, ok := result["predicate"]; !ok {
		t.Error("in-toto statement must contain a 'predicate' field to comply with the in-toto specification")
	}

	if _, ok := result["_type"]; !ok {
		t.Error("in-toto statement must contain a '_type' field")
	}
	if _, ok := result["subject"]; !ok {
		t.Error("in-toto statement must contain a 'subject' field")
	}
	if _, ok := result["predicateType"]; !ok {
		t.Error("in-toto statement must contain a 'predicateType' field")
	}
}

func TestSignCmd_ExperimentalPQC(t *testing.T) {
	t.Run("nil SigningConfig fails closed with init hint", func(t *testing.T) {
		err := SignCmd(t.Context(), nil, options.KeyOpts{ExperimentalPQC: true}, options.SignOptions{}, nil)
		if err == nil || !strings.Contains(err.Error(), "cosign initialize --experimental-pqc-staging") {
			t.Fatalf("expected Rekor v3 init hint error, got: %v", err)
		}
	})

	sc := startTestRekorV3Server(t)
	algo, err := signature.GetAlgorithmDetails(v1.PublicKeyDetails_ML_DSA_44)
	if err != nil {
		t.Fatalf("GetAlgorithmDetails: %v", err)
	}
	keys, err := cosign.GenerateKeyPairWithAlgorithm(&algo, nil)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithAlgorithm: %v", err)
	}
	td := t.TempDir()
	keyPath := writeFile(t, td, string(keys.PrivateBytes), "mldsa44.key")
	imgDigest := "127.0.0.1:1/repo@sha256:0000000000000000000000000000000000000000000000000000000000000000"

	t.Run("signs image digest to local v2 bundle with nil RootOptions", func(t *testing.T) {
		outPath := filepath.Join(td, "sign-v2.sigstore.json")
		ko := options.KeyOpts{
			ExperimentalPQC:  true,
			KeyRef:           keyPath,
			SigningConfig:    sc,
			SkipConfirmation: true,
		}
		so := options.SignOptions{BundlePath: outPath, Upload: false}
		if err := SignCmd(t.Context(), nil, ko, so, []string{imgDigest}); err != nil {
			t.Fatalf("SignCmd: %v", err)
		}
		b, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read bundle: %v", err)
		}
		var pb bundleV2.Bundle
		if err := protojson.Unmarshal(b, &pb); err != nil {
			t.Fatalf("protojson.Unmarshal: %v", err)
		}
		if pb.GetMediaType() != cbundle.BundleV20MediaType {
			t.Errorf("MediaType = %q, want %q", pb.GetMediaType(), cbundle.BundleV20MediaType)
		}
	})

	t.Run("declining private repo tlog upload fails closed", func(t *testing.T) {
		ctx := ui.WithEnv(t.Context(), &ui.Env{Stdin: strings.NewReader("n\n"), Stderr: io.Discard})
		ko := options.KeyOpts{
			ExperimentalPQC:  true,
			KeyRef:           keyPath,
			SigningConfig:    sc,
			SkipConfirmation: false,
		}
		so := options.SignOptions{BundlePath: filepath.Join(td, "declined.json"), Upload: false}
		err := SignCmd(ctx, nil, ko, so, []string{imgDigest})
		if err == nil || !strings.Contains(err.Error(), "--experimental-pqc requires uploading to a Rekor v3 transparency log") {
			t.Fatalf("expected tlog required error on decline, got: %v", err)
		}
	})
}
