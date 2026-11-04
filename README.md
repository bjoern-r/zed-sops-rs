# SOPS for Zed

A Zed extension plus a standalone language server (`sops-ls`) for files encrypted with [SOPS](https://github.com/getsops/sops). Supports YAML, JSON/JSONC, dotenv and INI.

All cryptography is delegated to the `sops` binary, so whatever already works on your command line (age, PGP, AWS/GCP KMS, Azure Key Vault, HashiCorp Vault, key groups) works in the editor. Plaintext is passed to and from `sops` via pipes only; the server never writes decrypted content to a temp file.

## Features

**Hover to decrypt.** Hover any `ENC[...]` value to see its key path, its type and the decrypted value. Hovering the `sops:` block shows the metadata: sops version, last-modified date, recipients per key type, encryption rules (`unencrypted_suffix`, `encrypted_regex`, ...), and a count of encrypted vs. plaintext values.

**Inline decrypted values.** The code action *SOPS: Show decrypted values inline* toggles inlay hints with the plaintext next to every value. Off by default, since anyone looking at your screen can read them. Requires `"inlay_hints": { "enabled": true }` in Zed.

**Edit secrets in place.** *SOPS: Decrypt for editing* replaces the buffer with the plaintext. After editing, *SOPS: Re-encrypt* (or simply saving, see below) turns it back into ciphertext. Re-encryption drives `sops edit` non-interactively, so the existing data key, recipients and settings of the file are kept, and you only need a key that can decrypt the file: no `.sops.yaml` rule is required. *SOPS: Discard changes* restores the last ciphertext.

**Encrypt new files.** Plaintext files that match a `creation_rules` entry (with an explicit `path_regex`) in the nearest `.sops.yaml` get a warning and a quick fix, *SOPS: Encrypt file using .sops.yaml*.

**Diagnostics:**

| Code | Severity | Meaning |
|---|---|---|
| `decrypt-failed` | error | `sops decrypt` fails on open/save: MAC mismatch (tampering or hand edits), no usable key, KMS access denied, ... The message is sops' own error. |
| `malformed-ciphertext` | error | An `ENC[...]` token is structurally broken (bad IV/tag length, unknown type). |
| `plaintext-value` | warning | A value in an encrypted file is plaintext although sops' rules say it should be encrypted, so decryption will fail. Respects `unencrypted_suffix`, `encrypted_suffix`, `unencrypted_regex` and `encrypted_regex` from the file's metadata. |
| `decrypted-buffer` | warning/error | The buffer currently holds decrypted secrets. |
| `should-be-encrypted` | warning | The file matches a `.sops.yaml` creation rule but is not encrypted. |

**Maintenance actions.** *SOPS: Update keys from .sops.yaml* runs `sops updatekeys -y`, and *SOPS: Rotate data key* runs `sops rotate -i`. Both operate on the saved file, and Zed reloads it afterwards.

## Requirements

`sops` 3.9 or newer on your `PATH` (tested with 3.13.3), plus whatever key material it needs. The extension launches the server with your shell environment, so `SOPS_AGE_KEY_FILE`, `GNUPGHOME`, `AWS_PROFILE`, `VAULT_ADDR` etc. from your shell are visible to sops.

## Installation

Until it is published in the Zed extension registry:

1. Build the server and put it on your `PATH`:
   ```sh
   cargo install --path sops-ls
   ```
   Alternatively, set `GITHUB_REPO` in `src/lib.rs` to your fork, push a `v*` tag, and the release workflow builds binaries the extension downloads automatically.
2. In Zed, run `zed: install dev extension` and select this directory. Zed compiles the extension to WASM itself; you need a Rust toolchain installed via `rustup`.

## Building with Docker

Requires Docker with BuildKit (the default in current Docker).

```sh
# static sops-ls binary + extension.wasm into ./dist
docker buildx build --target artifacts --output type=local,dest=dist .

# unit + end-to-end tests against real sops and age
docker buildx build --target test .

# install the server
install -m 755 dist/sops-ls ~/.local/bin/sops-ls
```

`sops-ls` is built against musl and statically linked, so it runs on any Linux distribution. For an ARM64 binary add `--platform linux/arm64` (emulated via QEMU, so expect a slow build).

Zed compiles extensions itself when you run `zed: install dev extension`, so that step still needs `rustup` on the host. The `extension.wasm` built in Docker is for CI and for checking that the extension compiles.

## Saving decrypted buffers safely

While a buffer is decrypted, the server makes sure only ciphertext ends up on disk. There are three layers, from best to fallback.

**Recommended: run sops-ls as a formatter on save.** The server's formatting request returns the re-encrypted document, so the file is encrypted *before* it is written. For normal (non-decrypted) files it returns no edits and changes nothing. Add it after your usual formatter:

```json
{
  "languages": {
    "YAML": {
      "format_on_save": "on",
      "formatter": [
        { "language_server": { "name": "yaml-language-server" } },
        { "language_server": { "name": "sops-ls" } }
      ]
    }
  }
}
```

Alternatively, `"code_actions_on_format": { "source.sops.encrypt": true }` works too: when that kind is requested explicitly, the server returns the encryption as a direct edit.

**`willSaveWaitUntil`.** Also implemented, for clients that send it.

**Fallback: re-encrypt after save.** If neither of the above ran, the plaintext has already been written when the server sees the save. With `encryptOnSave` (default) it then immediately re-encrypts the file on disk with an atomic rename and Zed reloads it. Plaintext is on disk only for a moment, but it *is* on disk, so configure the formatter if that matters to you (e.g. on synced or backed-up directories).

The server remembers the last ciphertext of every file it has seen, so undoing back to plaintext after re-encrypting is protected the same way.

## Settings

```json
{
  "lsp": {
    "sops-ls": {
      "binary": { "path": "/optional/path/to/sops-ls" },
      "settings": {
        "sopsPath": "sops",
        "hoverDecrypt": true,
        "inlayHints": false,
        "encryptOnSave": true,
        "verifyOnOpen": true,
        "timeoutSecs": 30,
        "env": { "SOPS_AGE_KEY_FILE": "/home/me/.config/sops/age/keys.txt" }
      }
    }
  }
}
```

| Setting | Default | Description |
|---|---|---|
| `sopsPath` | `sops` from the worktree `PATH` | sops binary to use |
| `hoverDecrypt` | `true` | Decrypt values on hover |
| `inlayHints` | `false` | Initial state of the inline decrypted values |
| `encryptOnSave` | `true` | Re-encrypt decrypted buffers on save (fallback path above) |
| `verifyOnOpen` | `true` | Run `sops decrypt` on open/save to surface MAC and key errors |
| `timeoutSecs` | `30` | Kill sops after this long (e.g. a forgotten PIN prompt) |
| `env` | `{}` | Extra environment variables for sops |

To disable the server for a language: `"languages": { "JSON": { "language_servers": ["!sops-ls", "..."] } }`.

## dotenv files

The extension registers for the language named `Env`, which comes from a dotenv extension. If your `.env` files open as plain text, install one, or map the file type in your settings. The server recognises dotenv files by their name as well.

## How it works

- **Hover and inlay hints** run `sops decrypt --output-type json` on the buffer content and map each value's key path (from a position-aware YAML/JSON/dotenv/INI scan) into the result. Results are cached per content hash, and sops calls are serialised so you see at most one PIN prompt at a time.
- **Re-encryption** writes the *previous ciphertext* to a temp file and runs `sops edit` on it with `SOPS_EDITOR` pointing back at `sops-ls __sops-editor`, which copies the new plaintext from a pipe into sops' own temp file. A sentinel file stops sops from looping when it rejects the content, and plaintext is syntax-checked beforehand.
- **First-time encryption** pipes the plaintext into `sops encrypt --filename-override <path> --config <nearest .sops.yaml>`.

Note that re-encryption generates fresh IVs, so every value's ciphertext changes, just as with `sops edit` on the command line.

## Development

```sh
cd sops-ls
cargo test                                  # unit tests
tests/setup_fixtures.sh /tmp/e2e            # needs sops + age
SOPS_AGE_KEY_FILE=/tmp/e2e/key.txt python3 tests/e2e.py target/debug/sops-ls /tmp/e2e
```

The end-to-end test drives the server over stdio the way an editor does: hover, inlay hints, decrypt → edit → formatting/save re-encryption, MAC mismatch, creation-rule encryption, and the JSON/dotenv/INI formats.
