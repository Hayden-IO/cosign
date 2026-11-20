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

package generate

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	icos "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestReadPasswordFn_env(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "foo")
	b, err := readPasswordFn(true)()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff("foo", string(b)); diff != "" {
		t.Fatal(diff)
	}
}

func TestReadPasswordFn_envEmptyVal(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "")
	b, err := readPasswordFn(true)()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) > 0 {
		t.Fatalf("expected empty string; got %q", string(b))
	}
}

func TestGenerationOfKeys(t *testing.T) {
	var privateKeyName = "my-test.key"
	var publicKeyName = "my-test.pub"

	t.Setenv("COSIGN_PASSWORD", "test")

	// we pass in a custom name `my-test` because the GenerateKeyPairCmd
	// doesn't care where the value comes from, only that it has a value.
	// be default it's set to `cosign`, but this is done by the CLI flag
	// framework if there is no value set by the user when running the
	// command.
	if err := GenerateKeyPairCmd(context.Background(), "", "my-test", nil); err != nil {
		t.Fatalf("GenerateKeyPairCmd: %v", err)
	}

	checkIfFileExistsThenDelete(privateKeyName, t)
	checkIfFileExistsThenDelete(publicKeyName, t)
}

func TestGenerateKeyPairWithAlgorithm(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "test-pass")

	t.Run("default algorithm is ECDSA P-256", func(t *testing.T) {
		prefix := filepath.Join(t.TempDir(), "default")
		if err := KeyPairWithAlgorithmCmd(context.Background(), "", prefix, "", nil); err != nil {
			t.Fatalf("KeyPairWithAlgorithmCmd: %v", err)
		}
		pubBytes, err := os.ReadFile(prefix + ".pub")
		if err != nil {
			t.Fatalf("reading pub key: %v", err)
		}
		pub, err := cryptoutils.UnmarshalPEMToPublicKey(pubBytes)
		if err != nil {
			t.Fatalf("unmarshaling pub key: %v", err)
		}
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecdsaPub.Curve != elliptic.P256() {
			t.Fatalf("expected ECDSA P-256 public key, got %T", pub)
		}
	})

	t.Run("mldsa-44 generates encrypted ML-DSA-44 keypair", func(t *testing.T) {
		prefix := filepath.Join(t.TempDir(), "pqc")
		if err := KeyPairWithAlgorithmCmd(context.Background(), "", prefix, "mldsa-44", nil); err != nil {
			t.Fatalf("KeyPairWithAlgorithmCmd: %v", err)
		}

		privPath := prefix + ".key"
		pubPath := prefix + ".pub"
		if runtime.GOOS != "windows" {
			info, err := os.Stat(privPath)
			if err != nil {
				t.Fatalf("stat private key: %v", err)
			}
			if perm := info.Mode().Perm(); perm != 0600 {
				t.Fatalf("expected private key mode 0600, got %o", perm)
			}
		}

		privBytes, err := os.ReadFile(privPath)
		if err != nil {
			t.Fatalf("reading private key: %v", err)
		}
		sv, err := cosign.LoadPrivateKey(privBytes, []byte("test-pass"), nil)
		if err != nil {
			t.Fatalf("LoadPrivateKey: %v", err)
		}
		pub, err := sv.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		mldsaPub, ok := pub.(*mldsa.PublicKey)
		if !ok {
			t.Fatalf("expected *mldsa.PublicKey, got %T", pub)
		}
		if mldsaPub.Parameters() != mldsa.MLDSA44() {
			t.Fatalf("expected ML-DSA-44, got %s", mldsaPub.Parameters())
		}

		pubBytes, err := os.ReadFile(pubPath)
		if err != nil {
			t.Fatalf("reading pub key: %v", err)
		}
		parsedPub, err := cryptoutils.UnmarshalPEMToPublicKey(pubBytes)
		if err != nil {
			t.Fatalf("UnmarshalPEMToPublicKey: %v", err)
		}
		if !mldsaPub.Equal(parsedPub) {
			t.Fatal("public key file does not match decrypted private key")
		}
	})

	t.Run("ed25519 generates Ed25519 keypair", func(t *testing.T) {
		prefix := filepath.Join(t.TempDir(), "ed25519")
		if err := KeyPairWithAlgorithmCmd(context.Background(), "", prefix, "ed25519", nil); err != nil {
			t.Fatalf("KeyPairWithAlgorithmCmd: %v", err)
		}
		pubBytes, err := os.ReadFile(prefix + ".pub")
		if err != nil {
			t.Fatalf("reading pub key: %v", err)
		}
		pub, err := cryptoutils.UnmarshalPEMToPublicKey(pubBytes)
		if err != nil {
			t.Fatalf("unmarshaling pub key: %v", err)
		}
		if _, ok := pub.(ed25519.PublicKey); !ok {
			t.Fatalf("expected ed25519.PublicKey, got %T", pub)
		}
	})

	for _, algo := range []string{"mldsa-65", "mldsa-87"} {
		t.Run("rejects "+algo+" with future-support message", func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), algo)
			err := KeyPairWithAlgorithmCmd(context.Background(), "", prefix, algo, nil)
			if !errors.Is(err, cosign.ErrUnsupportedMLDSAParameters) {
				t.Fatalf("expected ErrUnsupportedMLDSAParameters, got %v", err)
			}
			if _, statErr := os.Stat(prefix + ".key"); !os.IsNotExist(statErr) {
				t.Fatalf("expected no private key file written on error")
			}
			if _, statErr := os.Stat(prefix + ".pub"); !os.IsNotExist(statErr) {
				t.Fatalf("expected no public key file written on error")
			}
		})
	}

	for _, algo := range []string{"bogus-alg", "rsa-sign-pss-2048-sha256"} {
		t.Run("rejects invalid algorithm "+algo, func(t *testing.T) {
			prefix := filepath.Join(t.TempDir(), "invalid")
			err := KeyPairWithAlgorithmCmd(context.Background(), "", prefix, algo, nil)
			if err == nil {
				t.Fatalf("expected error for algorithm %q", algo)
			}
		})
	}

	t.Run("rejects --algorithm with --kms and remote targets", func(t *testing.T) {
		cases := []struct {
			name string
			kms  string
			args []string
		}{
			{name: "kms", kms: "awskms:///alias/test"},
			{name: "k8s", args: []string{"k8s://default/cosign"}},
			{name: "github", args: []string{"github://owner/repo"}},
			{name: "gitlab", args: []string{"gitlab://owner/repo"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				prefix := filepath.Join(t.TempDir(), tc.name)
				err := KeyPairWithAlgorithmCmd(context.Background(), tc.kms, prefix, "mldsa-44", tc.args)
				if err == nil {
					t.Fatalf("expected error when combining --algorithm with %s", tc.name)
				}
			})
		}
	})
}

func checkIfFileExistsThenDelete(fileName string, t *testing.T) {
	fileExists, err := icos.FileExists(fileName)
	if err != nil {
		t.Fatalf("failed checking if %s exists: %v", fileName, err)
	}

	if !fileExists {
		t.Fatalf("key generation for key %s failed", fileName)
	}

	t.Logf("key generation for key %s succeeded", fileName)

	deleteKeyFile(fileName, t)
}

func deleteKeyFile(fileName string, t *testing.T) {
	t.Cleanup(func() {
		t.Logf("Removing keyfile %s...", fileName)
		os.Remove(fileName)
		t.Logf("Removed keyfile %s", fileName)
	})
}
