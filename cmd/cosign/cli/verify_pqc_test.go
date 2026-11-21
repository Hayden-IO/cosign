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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestExperimentalPQCOnlyFlagRegisteredAndWired(t *testing.T) {
	dockerfileVerifyCmd, _, err := Dockerfile().Find([]string{"verify"})
	require.NoError(t, err)
	manifestVerifyCmd, _, err := Manifest().Find([]string{"verify"})
	require.NoError(t, err)

	for _, cmd := range []*cobra.Command{
		Verify(),
		VerifyAttestation(),
		VerifyBlob(),
		VerifyBlobAttestation(),
		dockerfileVerifyCmd,
		manifestVerifyCmd,
	} {
		t.Run("flag/"+cmd.CommandPath(), func(t *testing.T) {
			f := cmd.Flags().Lookup("experimental-pqc-only")
			require.NotNil(t, f, "expected --experimental-pqc-only flag")
			require.Equal(t, "false", f.DefValue)
			require.Contains(t, f.Usage, "EXPERIMENTAL")
			require.Contains(t, f.Usage, "breaking changes")
		})
	}

	// Verify end-to-end Cobra -> Exec wiring across all verify commands (flag + env var).
	dir := t.TempDir()
	dockerfilePath := filepath.Join(dir, "Dockerfile")
	require.NoError(t, os.WriteFile(dockerfilePath, []byte("FROM alpine:3.20\n"), 0o600))
	manifestPath := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(manifestPath, []byte("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    image: alpine:3.20\n"), 0o600))

	execCases := []struct {
		name    string
		newCmd  func() *cobra.Command
		args    []string
		wantErr string
	}{
		{"verify flag", Verify, []string{"--experimental-pqc-only", "--insecure-ignore-tlog", "example.com/img"}, "--insecure-ignore-tlog"},
		{"verify-attestation flag", VerifyAttestation, []string{"--experimental-pqc-only", "--use-signed-timestamps", "example.com/img"}, "--use-signed-timestamps"},
		{"verify-blob flag", VerifyBlob, []string{"--experimental-pqc-only", "--insecure-ignore-tlog", "--bundle", "b.json", "blob"}, "--insecure-ignore-tlog"},
		{"verify-blob-attestation flag", VerifyBlobAttestation, []string{"--experimental-pqc-only", "--use-signed-timestamps", "--bundle", "b.json", "blob"}, "--use-signed-timestamps"},
		{"dockerfile verify flag", Dockerfile, []string{"verify", "--experimental-pqc-only", "--insecure-ignore-tlog", dockerfilePath}, "--insecure-ignore-tlog"},
		{"manifest verify flag", Manifest, []string{"verify", "--experimental-pqc-only", "--insecure-ignore-tlog", manifestPath}, "--insecure-ignore-tlog"},
	}
	for _, tc := range execCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.newCmd()
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			require.ErrorContains(t, err, tc.wantErr)
		})
	}

	t.Run("COSIGN_EXPERIMENTAL_PQC_ONLY env binding", func(t *testing.T) {
		t.Setenv("COSIGN_EXPERIMENTAL_PQC_ONLY", "true")
		cmd := VerifyBlob()
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetArgs([]string{"--insecure-ignore-tlog", "--bundle", "b.json", "blob"})
		require.ErrorContains(t, cmd.Execute(), "--insecure-ignore-tlog")
	})
}
