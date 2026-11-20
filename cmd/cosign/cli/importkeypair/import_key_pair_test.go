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

package importkeypair

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	icos "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign"
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

func TestImportOfKeys(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "test")

	privateKeyFileName := "my-private-key.pem"
	createTemporaryPrivateKeyForImporting(privateKeyFileName)

	// we pass in a custom outVal `my-test` because the ImportKeyPairCmd
	// doesn't care where the value comes from, only that it has a value.
	// be default it's set to `import-cosign`, but this is done by the CLI flag
	// framework if there is no value set by the user when running the
	// command.
	outputtedKeyPairFileName := "my-test"
	ImportKeyPairCmd(context.Background(), options.ImportKeyPairOptions{
		Key:              privateKeyFileName,
		OutputKeyPrefix:  outputtedKeyPairFileName,
		SkipConfirmation: false,
	}, nil)

	// removes temporary RSA private key used for test
	checkIfFileExistsThenDelete(privateKeyFileName, t)

	// checks if the outputted key pairs have been created based on
	// the imported RSA private key, and then deletes them as per test
	// cleanup
	checkIfFileExistsThenDelete(outputtedKeyPairFileName+".key", t)
	checkIfFileExistsThenDelete(outputtedKeyPairFileName+".pub", t)
}

func TestImportOfMLDSAKeys(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "mldsa-pass")
	td := t.TempDir()

	writePKCS8 := func(t *testing.T, name string, params mldsa.Parameters) (string, *mldsa.PrivateKey) {
		t.Helper()
		priv, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatalf("mldsa.GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		keyPath := filepath.Join(td, name)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: cosign.PrivateKeyPemType, Bytes: der})
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return keyPath, priv
	}

	t.Run("ML-DSA-44 imports via CLI", func(t *testing.T) {
		inPath, priv := writePKCS8(t, "mldsa44.pem", mldsa.MLDSA44())
		outPrefix := filepath.Join(td, "imported-mldsa44")
		err := ImportKeyPairCmd(context.Background(), options.ImportKeyPairOptions{
			Key:              inPath,
			OutputKeyPrefix:  outPrefix,
			SkipConfirmation: true,
		}, nil)
		if err != nil {
			t.Fatalf("ImportKeyPairCmd: %v", err)
		}

		privPath := outPrefix + ".key"
		if runtime.GOOS != "windows" {
			info, err := os.Stat(privPath)
			if err != nil {
				t.Fatalf("stat private key: %v", err)
			}
			if perm := info.Mode().Perm(); perm != 0600 {
				t.Fatalf("expected mode 0600, got %o", perm)
			}
		}

		privBytes, err := os.ReadFile(privPath)
		if err != nil {
			t.Fatalf("reading imported private key: %v", err)
		}
		sv, err := cosign.LoadPrivateKey(privBytes, []byte("mldsa-pass"), nil)
		if err != nil {
			t.Fatalf("LoadPrivateKey: %v", err)
		}
		pub, err := sv.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		if !priv.PublicKey().Equal(pub) {
			t.Fatal("imported public key does not match original ML-DSA-44 key")
		}
	})

	for _, tc := range []struct {
		name   string
		params mldsa.Parameters
	}{
		{name: "ML-DSA-65", params: mldsa.MLDSA65()},
		{name: "ML-DSA-87", params: mldsa.MLDSA87()},
	} {
		t.Run(tc.name+" rejected via CLI", func(t *testing.T) {
			inPath, _ := writePKCS8(t, tc.name+".pem", tc.params)
			outPrefix := filepath.Join(td, "imported-"+tc.name)
			err := ImportKeyPairCmd(context.Background(), options.ImportKeyPairOptions{
				Key:              inPath,
				OutputKeyPrefix:  outPrefix,
				SkipConfirmation: true,
			}, nil)
			if !errors.Is(err, cosign.ErrUnsupportedMLDSAParameters) {
				t.Fatalf("expected ErrUnsupportedMLDSAParameters, got %v", err)
			}
			if _, statErr := os.Stat(outPrefix + ".key"); !os.IsNotExist(statErr) {
				t.Fatalf("expected no output key file written on error")
			}
		})
	}
}

func createTemporaryPrivateKeyForImporting(privateKeyName string) {
	bitSize := 4096

	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		panic(err)
	}

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	// Write private key to file.
	if err := os.WriteFile(privateKeyName, keyPEM, 0700); err != nil {
		panic(err)
	}
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
