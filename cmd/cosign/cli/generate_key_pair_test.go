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
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/cosign"
)

func TestGenerateKeyPairCommandRejectsAlgorithmWithKMSAndRemoteTargets(t *testing.T) {
	testCases := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{
			name: "algorithm with kms",
			args: []string{"--algorithm=mldsa-44", "--kms=awskms:///alias/test"},
		},
		{
			name: "empty algorithm explicitly set with kms",
			args: []string{"--algorithm=", "--kms=awskms:///alias/test"},
		},
		{
			name: "algorithm with k8s target",
			args: []string{"--algorithm=mldsa-44", "k8s://default/cosign"},
		},
		{
			name: "algorithm with github target",
			args: []string{"--algorithm=mldsa-44", "github://owner/repo"},
		},
		{
			name: "algorithm with gitlab target",
			args: []string{"--algorithm=mldsa-44", "gitlab://owner/repo"},
		},
		{
			name: "COSIGN_ALGORITHM env with kms flag",
			env:  map[string]string{"COSIGN_ALGORITHM": "mldsa-44"},
			args: []string{"--kms=awskms:///alias/test"},
		},
		{
			name: "COSIGN_ALGORITHM env with k8s target",
			env:  map[string]string{"COSIGN_ALGORITHM": "mldsa-44"},
			args: []string{"k8s://default/cosign"},
		},
		{
			name: "COSIGN_KMS env with algorithm flag",
			env:  map[string]string{"COSIGN_KMS": "awskms:///alias/test"},
			args: []string{"--algorithm=mldsa-44"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cmd := GenerateKeyPair()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error for args %v, got nil", tc.args)
			}
			if !strings.Contains(err.Error(), "--algorithm is not supported") {
				t.Fatalf("expected --algorithm unsupported error, got: %v", err)
			}
		})
	}
}

func TestGenerateKeyPairCommandRejectsEmptyAndUnsupportedMLDSA(t *testing.T) {
	t.Run("explicit empty algorithm rejected", func(t *testing.T) {
		cmd := GenerateKeyPair()
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"--algorithm="})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for explicit empty --algorithm=")
		}
		if !strings.Contains(err.Error(), "invalid algorithm") {
			t.Fatalf("expected invalid algorithm error, got: %v", err)
		}
	})

	for _, alg := range []string{"mldsa-65", "mldsa-87"} {
		t.Run(alg+" rejected via Cobra", func(t *testing.T) {
			cmd := GenerateKeyPair()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"--algorithm=" + alg})
			err := cmd.Execute()
			if !errors.Is(err, cosign.ErrUnsupportedMLDSAParameters) {
				t.Fatalf("expected ErrUnsupportedMLDSAParameters, got: %v", err)
			}
		})
	}
}

func TestSignBlobRejectsMLDSASigningAlgorithm(t *testing.T) {
	for _, alg := range []string{"mldsa-44", "mldsa-65", "mldsa-87"} {
		t.Run(alg, func(t *testing.T) {
			cmd := SignBlob()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"--signing-algorithm=" + alg, "dummy-blob"})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error for sign-blob --signing-algorithm=%s, got nil", alg)
			}
			if !strings.Contains(err.Error(), "invalid signing algorithm") {
				t.Fatalf("expected invalid signing algorithm error, got: %v", err)
			}
		})
	}
}
