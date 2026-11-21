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
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func execSilent(cmd *cobra.Command, args ...string) error {
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestExperimentalPQCFlagExclusions(t *testing.T) {
	const testImg = "example.com/repo@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	commands := []struct {
		name     string
		build    func() *cobra.Command
		baseArgs []string
	}{
		{"sign", Sign, []string{testImg}},
		{"sign-blob", SignBlob, []string{"--bundle=out.json", "blob.txt"}},
		{"attest", Attest, []string{"--predicate=pred.json", testImg}},
		{"attest-blob", AttestBlob, []string{"--predicate=pred.json", "--bundle=out.json", "blob.txt"}},
	}

	for _, tc := range commands {
		t.Run(tc.name+" defaults --experimental-pqc to false", func(t *testing.T) {
			f := tc.build().Flags().Lookup("experimental-pqc")
			if f == nil || f.DefValue != "false" {
				t.Fatalf("expected --experimental-pqc default false on %s, got %v", tc.name, f)
			}
		})

		t.Run(tc.name+" rejects --experimental-pqc with --no-signing-config", func(t *testing.T) {
			err := execSilent(tc.build(), append([]string{"--experimental-pqc", "--no-signing-config"}, tc.baseArgs...)...)
			if err == nil || !strings.Contains(err.Error(), "experimental-pqc") || !strings.Contains(err.Error(), "no-signing-config") {
				t.Fatalf("expected mutual-exclusion error, got: %v", err)
			}
		})

		t.Run(tc.name+" rejects COSIGN_EXPERIMENTAL_PQC with --sk before TUF", func(t *testing.T) {
			t.Setenv("COSIGN_EXPERIMENTAL_PQC", "true")
			t.Setenv("TUF_ROOT", t.TempDir())
			err := execSilent(tc.build(), append([]string{"--sk"}, tc.baseArgs...)...)
			if err == nil || !strings.Contains(err.Error(), "--sk") {
				t.Fatalf("expected --sk incompatibility error before TUF, got: %v", err)
			}
		})

		t.Run(tc.name+" rejects COSIGN_EXPERIMENTAL_PQC with COSIGN_NO_SIGNING_CONFIG", func(t *testing.T) {
			t.Setenv("COSIGN_EXPERIMENTAL_PQC", "true")
			t.Setenv("COSIGN_NO_SIGNING_CONFIG", "true")
			err := execSilent(tc.build(), tc.baseArgs...)
			if err == nil || !strings.Contains(err.Error(), "experimental-pqc") || !strings.Contains(err.Error(), "no-signing-config") {
				t.Fatalf("expected mutual-exclusion error, got: %v", err)
			}
		})
	}

	t.Run("sign-blob rejects --signing-algorithm with --experimental-pqc", func(t *testing.T) {
		err := execSilent(SignBlob(), "--experimental-pqc", "--signing-algorithm=ecdsa-sha2-256-nistp256", "--bundle=out.json", "blob.txt")
		if err == nil || !strings.Contains(err.Error(), "--signing-algorithm is not supported with --experimental-pqc") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("sign-blob rejects COSIGN_SIGNING_ALGORITHM with COSIGN_EXPERIMENTAL_PQC", func(t *testing.T) {
		t.Setenv("COSIGN_EXPERIMENTAL_PQC", "true")
		t.Setenv("COSIGN_SIGNING_ALGORITHM", "ecdsa-sha2-256-nistp256")
		err := execSilent(SignBlob(), "--bundle=out.json", "blob.txt")
		if err == nil || !strings.Contains(err.Error(), "--signing-algorithm is not supported with --experimental-pqc") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
