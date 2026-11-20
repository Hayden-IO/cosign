## cosign generate-key-pair

Generates a key-pair

### Synopsis

Generates a key-pair for signing.

```
cosign generate-key-pair [flags]
```

### Examples

```
  cosign generate-key-pair [--kms KMSPATH | --algorithm ALGORITHM]

  # generate key-pair and write to cosign.key and cosign.pub files
  cosign generate-key-pair

  # generate an experimental ML-DSA-44 key-pair for transparent PQC signing
  cosign generate-key-pair --algorithm mldsa-44

  # generate key-pair and write to custom named my-name.key and my-name.pub files
  cosign generate-key-pair --output-key-prefix my-name

  # generate a key-pair in Azure Key Vault
  cosign generate-key-pair --kms azurekms://[VAULT_NAME][VAULT_URI]/[KEY]

  # generate a key-pair in AWS KMS
  cosign generate-key-pair --kms awskms://[ENDPOINT]/[ID/ALIAS/ARN]

  # generate a key-pair in Google Cloud KMS
  cosign generate-key-pair --kms gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]

  # generate a key-pair in Hashicorp Vault
  cosign generate-key-pair --kms hashivault://[KEY]

  # generate a key-pair in Kubernetes Secret
  cosign generate-key-pair k8s://[NAMESPACE]/[NAME]

  # generate a key-pair in GitHub
  cosign generate-key-pair github://[OWNER]/[PROJECT_NAME]

  # generate a key-pair in GitLab with project name
  cosign generate-key-pair gitlab://[OWNER]/[PROJECT_NAME]

  # generate a key-pair in GitLab with project id
  cosign generate-key-pair gitlab://[PROJECT_ID]

  # generate a key-pair in GitLab with group name (accessible to all projects in the group)
  cosign generate-key-pair gitlab://[GROUP_NAME]

  # generate a key-pair in GitLab with subgroup name
  cosign generate-key-pair gitlab://[GROUP_NAME]/[SUBGROUP_NAME]

CAVEATS:
  This command interactively prompts for a password. You can use
  the COSIGN_PASSWORD environment variable to provide one.
```

### Options

```
      --algorithm string           key algorithm to generate (defaults to ecdsa-sha2-256-nistp256). Supported algorithms: ecdsa-sha2-256-nistp256, ecdsa-sha2-384-nistp384, ecdsa-sha2-512-nistp521, ed25519, mldsa-44, rsa-sign-pkcs1-2048-sha256, rsa-sign-pkcs1-3072-sha256, rsa-sign-pkcs1-4096-sha256. Note: mldsa-44 is EXPERIMENTAL and only supported for transparent PQC signing; mldsa-65 and mldsa-87 will be supported in the future for non-transparent signatures
  -h, --help[=true|false]          help for generate-key-pair
      --kms string                 create key pair in KMS service to use for signing
      --output-key-prefix cosign   name used for generated .pub and .key files (defaults to cosign) (default "cosign")
```

### Options inherited from parent commands

```
      --output-file string     log output to a file
  -t, --timeout duration       timeout for commands (default 3m0s)
  -d, --verbose[=true|false]   log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry

