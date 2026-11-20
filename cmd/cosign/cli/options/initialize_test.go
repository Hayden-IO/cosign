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

package options

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestInitializeOptionsMutualExclusion(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantErr        string
		wantStagingPQC bool
	}{
		{
			name:           "experimental-pqc-staging alone succeeds",
			args:           []string{"--experimental-pqc-staging"},
			wantStagingPQC: true,
		},
		{
			name: "staging alone succeeds",
			args: []string{"--staging"},
		},
		{
			name: "mirror and root together succeed",
			args: []string{"--mirror", "https://example.com", "--root", "root.json"},
		},
		{
			name:    "staging and experimental-pqc-staging conflict",
			args:    []string{"--staging", "--experimental-pqc-staging"},
			wantErr: "none of the others can be",
		},
		{
			name:    "mirror and experimental-pqc-staging conflict",
			args:    []string{"--mirror", "https://example.com", "--experimental-pqc-staging"},
			wantErr: "none of the others can be",
		},
		{
			name:    "root and experimental-pqc-staging conflict",
			args:    []string{"--root", "root.json", "--experimental-pqc-staging"},
			wantErr: "none of the others can be",
		},
		{
			name:    "root-checksum and experimental-pqc-staging conflict",
			args:    []string{"--root-checksum", "abc", "--experimental-pqc-staging"},
			wantErr: "none of the others can be",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &InitializeOptions{}
			cmd := &cobra.Command{
				Use:           "initialize",
				SilenceUsage:  true,
				SilenceErrors: true,
				RunE:          func(_ *cobra.Command, _ []string) error { return nil },
			}
			o.AddFlags(cmd)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantStagingPQC, o.ExperimentalPQCStaging)
			}
		})
	}
}
