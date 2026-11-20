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

package cosign

import (
	"context"
	"crypto/mldsa"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestTrustedRootWithContextStopsRefresh(t *testing.T) {
	t.Setenv("TUF_ROOT", t.TempDir())
	refreshRunning := func() bool {
		buf := make([]byte, 1<<20)
		return strings.Contains(string(buf[:runtime.Stack(buf, true)]), "root.NewLiveTrustedRootFromTargetWithPeriod.func")
	}
	ctx, cancel := context.WithCancel(context.Background())

	trustedRoot, err := TrustedRootWithContext(ctx)
	require.NoError(t, err)
	require.NotNil(t, trustedRoot)
	require.True(t, refreshRunning())

	cancel()
	assert.Eventually(t, func() bool { return !refreshRunning() }, 5*time.Second, 10*time.Millisecond)
}

func TestStagingPQCRootAndTUFOpts(t *testing.T) {
	rootBytes := StagingPQCRoot()
	require.NotEmpty(t, rootBytes)

	// Cryptographically verify embedded PQC staging root with go-tuf/v2.
	rootMeta, err := metadata.Root().FromBytes(rootBytes)
	require.NoError(t, err)
	require.NoError(t, rootMeta.VerifyDelegate(metadata.ROOT, rootMeta))
	require.NotEmpty(t, rootMeta.Signed.Keys)
	for _, k := range rootMeta.Signed.Keys {
		assert.Equal(t, "ml-dsa", k.Type)
	}

	// Verify StagingPQCRoot returns a defensive copy.
	rootBytes[0] = 'X'
	assert.Equal(t, byte('{'), StagingPQCRoot()[0])

	t.Run("fallback to embedded root via TUF_MIRROR", func(t *testing.T) {
		t.Setenv("TUF_ROOT", t.TempDir())
		t.Setenv("TUF_MIRROR", StagingPQCMirror)
		t.Setenv("TUF_ROOT_JSON", "")
		opts, err := setTUFOpts()
		require.NoError(t, err)
		assert.Equal(t, StagingPQCMirror, opts.RepositoryBaseURL)
		assert.Equal(t, StagingPQCRoot(), opts.Root)
	})

	t.Run("trailing slash on StagingPQCMirror normalizes URL and uses embedded root", func(t *testing.T) {
		t.Setenv("TUF_ROOT", t.TempDir())
		t.Setenv("TUF_MIRROR", StagingPQCMirror+"/")
		t.Setenv("TUF_ROOT_JSON", "")
		opts, err := setTUFOpts()
		require.NoError(t, err)
		assert.Equal(t, StagingPQCMirror, opts.RepositoryBaseURL)
		assert.Equal(t, StagingPQCRoot(), opts.Root)
	})

	t.Run("remote.json resolves StagingPQCMirror and cached root takes precedence over embedded", func(t *testing.T) {
		tufDir := t.TempDir()
		t.Setenv("TUF_ROOT", tufDir)
		t.Setenv("TUF_MIRROR", "")
		t.Setenv("TUF_ROOT_JSON", "")

		remoteBytes, err := json.Marshal(map[string]string{"mirror": StagingPQCMirror})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(tufDir, "remote.json"), remoteBytes, 0o600))

		cachedDir := filepath.Join(tufDir, tuf.URLToPath(StagingPQCMirror))
		require.NoError(t, os.MkdirAll(cachedDir, 0o700))
		cachedRoot := []byte(`{"cached":true}`)
		require.NoError(t, os.WriteFile(filepath.Join(cachedDir, "root.json"), cachedRoot, 0o600))

		opts, err := setTUFOpts()
		require.NoError(t, err)
		assert.Equal(t, StagingPQCMirror, opts.RepositoryBaseURL)
		assert.Equal(t, cachedRoot, opts.Root)

		// Trailing slash in TUF_MIRROR must hit the exact same cached root (no rollback to embedded v1).
		t.Setenv("TUF_MIRROR", StagingPQCMirror+"/")
		opts, err = setTUFOpts()
		require.NoError(t, err)
		assert.Equal(t, StagingPQCMirror, opts.RepositoryBaseURL)
		assert.Equal(t, cachedRoot, opts.Root)
		t.Setenv("TUF_MIRROR", "")

		// TUF_ROOT_JSON overrides cached root.
		overridePath := filepath.Join(t.TempDir(), "override.json")
		overrideRoot := []byte(`{"override":true}`)
		require.NoError(t, os.WriteFile(overridePath, overrideRoot, 0o600))
		t.Setenv("TUF_ROOT_JSON", overridePath)

		opts, err = setTUFOpts()
		require.NoError(t, err)
		assert.Equal(t, overrideRoot, opts.Root)
	})

	t.Run("unknown custom mirror without cached root fails closed", func(t *testing.T) {
		t.Setenv("TUF_ROOT", t.TempDir())
		t.Setenv("TUF_MIRROR", "https://tuf.example.invalid")
		t.Setenv("TUF_ROOT_JSON", "")
		_, err := setTUFOpts()
		assert.ErrorContains(t, err, "could not find cached root.json")
	})
}

func TestVerifyTrustedMaterialPublicKeyVerifiers(t *testing.T) {
	empty := &verifyTrustedMaterial{}
	assert.Nil(t, empty.PublicKeyVerifiers())
	_, err := empty.PublicKeyVerifier("hint")
	assert.Error(t, err)

	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	v, err := signature.LoadDefaultVerifier(priv.Public())
	require.NoError(t, err)
	ek := root.NewExpiringKey(v, time.Time{}, time.Time{})
	tm := &verifyTrustedMaterial{
		keyTrustedMaterial: root.NewTrustedPublicKeyVerifiers(ek),
	}
	verifiers := tm.PublicKeyVerifiers()
	require.Len(t, verifiers, 1)
	assert.Equal(t, ek, verifiers[0])
}
