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

package initialize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/blob"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	tufroot "github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	tufv1 "github.com/sigstore/sigstore/pkg/tuf"
)

func DoInitialize(ctx context.Context, root, mirror string) error {
	return doInitialize(ctx, root, mirror, "", true)
}

func DoInitializeWithRootChecksum(ctx context.Context, root, mirror, rootChecksum string) error {
	return doInitialize(ctx, root, mirror, rootChecksum, false)
}

func DoInitializeStaging(ctx context.Context) error {
	return doInitialize(ctx, "", tuf.StagingMirror, "", true)
}

var (
	stagingPQCMirror = cosign.StagingPQCMirror
	stagingPQCRoot   = cosign.StagingPQCRoot
)

// DoInitializeStagingPQC initializes the local TUF root cache against the experimental PQC staging repository.
func DoInitializeStagingPQC(ctx context.Context) error {
	return doInitialize(ctx, "", stagingPQCMirror, "", true)
}

func doInitialize(ctx context.Context, root, mirror, rootChecksum string, forceSkipChecksumValidation bool) error {
	// Get the initial trusted root contents.
	var rootFileBytes []byte
	var err error
	if root != "" {
		if !forceSkipChecksumValidation {
			if rootChecksum == "" && (strings.HasPrefix(root, "http://") || strings.HasPrefix(root, "https://")) {
				fmt.Fprintln(os.Stderr, options.RootWithoutChecksumDeprecation)
			}
		}
		verifyChecksum := !forceSkipChecksumValidation && (rootChecksum != "")
		if verifyChecksum {
			rootFileBytes, err = blob.LoadFileOrURLWithChecksum(root, rootChecksum)
		} else {
			rootFileBytes, err = blob.LoadFileOrURL(root)
		}
		if err != nil {
			return err
		}
	}

	normalizedMirror := strings.TrimRight(mirror, "/")
	isStagingPQC := normalizedMirror != "" && normalizedMirror == strings.TrimRight(stagingPQCMirror, "/")

	opts := tuf.DefaultOptions()
	if root != "" {
		opts.Root = rootFileBytes
	}
	if mirror != "" {
		opts.RepositoryBaseURL = normalizedMirror
		if root == "" {
			switch {
			case normalizedMirror == strings.TrimRight(tuf.StagingMirror, "/"):
				opts.Root = tuf.StagingRoot()
			case isStagingPQC:
				opts.Root = stagingPQCRoot()
			}
		}
	}
	if tufCacheDir := env.Getenv(env.VariableTUFRootDir); tufCacheDir != "" { //nolint:forbidigo
		opts.CachePath = tufCacheDir
	}
	targetCachePath := filepath.Clean(opts.CachePath)

	// Leave a hint for where the current remote is. Adopted from sigstore/sigstore TUF client.
	remote := map[string]string{"mirror": opts.RepositoryBaseURL}
	remoteBytes, err := json.Marshal(remote)
	if err != nil {
		return err
	}

	parentDir := filepath.Dir(targetCachePath)
	if err := os.MkdirAll(parentDir, 0o700); err != nil {
		return fmt.Errorf("creating cache parent directory: %w", err)
	}
	stageDir, err := os.MkdirTemp(parentDir, ".cosign-tuf-init-*")
	if err != nil {
		return fmt.Errorf("creating staging cache directory: %w", err)
	}
	defer os.RemoveAll(stageDir)

	if err := os.WriteFile(filepath.Join(stageDir, "remote.json"), remoteBytes, 0o600); err != nil {
		return fmt.Errorf("storing remote: %w", err)
	}
	opts.CachePath = stageDir

	// Cache the signing config from the TUF repository
	_, scErr := tufroot.FetchSigningConfigWithOptions(opts)
	if scErr != nil && !isStagingPQC {
		ui.Warnf(ctx, "Could not fetch signing_config.json from the TUF mirror (encountered error: %v). It is recommended to use a signing config file rather than provide service URLs when signing.", scErr)
	}
	// Cache the trusted root from the TUF repository
	liveCtx, cancelLive := context.WithCancel(ctx)
	defer cancelLive()
	opts.Context = liveCtx
	trustedRoot, err := tufroot.NewLiveTrustedRoot(opts)
	if err != nil {
		if isStagingPQC {
			return fmt.Errorf("fetching trusted_root.json from PQC staging TUF mirror: %w", err)
		}
		ui.Warnf(ctx, "Could not fetch trusted_root.json from the TUF mirror (encountered error: %v), falling back to individual targets. It is recommended to update your TUF metadata repository to include trusted_root.json.", err)
	}
	if trustedRoot != nil {
		if isStagingPQC && scErr != nil {
			return fmt.Errorf("fetching signing_config.json from PQC staging TUF mirror: %w", scErr)
		}
		return replaceCacheDir(stageDir, targetCachePath)
	}

	// The mirror did not have a trusted_root.json, so initialize the legacy TUF targets.
	if err := os.RemoveAll(targetCachePath); err != nil {
		return fmt.Errorf("clearing cache directory: %w", err)
	}
	if err := os.MkdirAll(targetCachePath, 0o700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}
	if err := os.WriteFile(filepath.FromSlash(filepath.Join(targetCachePath, "remote.json")), remoteBytes, 0o600); err != nil {
		return fmt.Errorf("storing remote: %w", err)
	}
	if err := tufv1.Initialize(ctx, mirror, rootFileBytes); err != nil {
		return err
	}

	status, err := tufv1.GetRootStatus(ctx)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(status, "", "\t")
	if err != nil {
		return err
	}

	fmt.Println("Root status: \n", string(b))
	return nil
}

func replaceCacheDir(stageDir, targetDir string) error {
	var backupDir string
	if _, err := os.Lstat(targetDir); err == nil {
		backupDir = targetDir + ".bak-" + filepath.Base(stageDir)
		if err := os.Rename(targetDir, backupDir); err != nil {
			return fmt.Errorf("backing up existing cache directory: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspecting existing cache directory: %w", err)
	}
	if err := os.Rename(stageDir, targetDir); err != nil {
		if backupDir != "" {
			_ = os.Rename(backupDir, targetDir)
		}
		return fmt.Errorf("installing cache directory: %w", err)
	}
	if backupDir != "" {
		_ = os.RemoveAll(backupDir)
	}
	return nil
}
