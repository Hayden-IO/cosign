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

package options

import (
	"fmt"
	"strings"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/spf13/cobra"
)

// GenerateKeyPairOptions is the top level wrapper for the generate-key-pair command.
type GenerateKeyPairOptions struct {
	// KMS Key Management Service
	KMS             string
	OutputKeyPrefix string
	Algorithm       string
}

var _ Interface = (*GenerateKeyPairOptions)(nil)

// AddFlags implements Interface
func (o *GenerateKeyPairOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.KMS, "kms", "",
		"create key pair in KMS service to use for signing")
	cmd.Flags().StringVar(&o.OutputKeyPrefix, "output-key-prefix", "cosign",
		"name used for generated .pub and .key files (defaults to `cosign`)")
	cmd.Flags().StringVar(&o.Algorithm, "algorithm", "",
		fmt.Sprintf("key algorithm to generate (defaults to ecdsa-sha2-256-nistp256). Supported algorithms: %s. "+
			"Note: mldsa-44 is EXPERIMENTAL and only supported for transparent PQC signing; mldsa-65 and mldsa-87 will be supported in the future for non-transparent signatures",
			strings.Join(cosign.GetSupportedKeyPairAlgorithms(), ", ")))
}
