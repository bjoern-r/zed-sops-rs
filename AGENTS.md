# AGENTS.md

Handover notes for coding agents working on this repository. `README.md` describes the project for users; this file covers what you need to change it safely.

## What this is

A Zed extension for files encrypted with [SOPS](https://github.com/getsops/sops). It has two independent parts:

- **Zed extension, `/` (root crate `zed-sops`).** Rust compiled to `wasm32-wasip2` and run inside Zed. Its only job is to find or download the `sops-ls` binary, start it with the user's shell environment, and pass settings. No logic belongs here.
- **Language server, `/sops-ls`.** A native Rust binary that speaks LSP over stdio. All features live here. It performs **no cryptography**; every operation shells out to the `sops` CLI.

The two crates are separate Cargo workspaces (`sops-ls/Cargo.toml` contains an empty `[workspace]`). Do not merge them: Zed builds the root crate for WASM, and the server's dependencies (tokio, process spawning) don't compile there.

## Layout

```
extension.toml            Zed manifest: language server "sops-ls", languages + language_ids
Cargo.toml, src/lib.rs    Zed extension (binary resolution, settings, shell env)
sops-ls/src/main.rs       CLI entry: --version, hidden `__sops-editor` subcommand, LSP stdio
sops-ls/src/server.rs     LSP backend: state, diagnostics, hover, inlay hints, code actions, commands, save handling
sops-ls/src/scan.rs       Pure analysis: format detection, ENC[] tokens, key paths + byte spans, SOPS metadata, encryption rules
sops-ls/src/sops.rs       sops CLI wrapper: decrypt, re-encrypt via SOPS_EDITOR, encrypt_new, updatekeys/rotate
sops-ls/src/rules.rs      .sops.yaml lookup and creation_rules path_regex matching
sops-ls/src/text.rs       Byte offset <-> LSP Position (UTF-8 / UTF-16)
sops-ls/tests/e2e.py      End-to-end LSP client against real sops + age (28 checks)
sops-ls/tests/setup_fixtures.sh   Creates an age key, .sops.yaml and encrypted fixtures
Dockerfile, install.sh    Toolchain-free build and install (see "Docker" below)
.github/workflows/release.yml     Per-platform release binaries + e2e job
```

## Commands

Run from `sops-ls/` unless noted.

```sh
cargo build                      # server
cargo test                       # unit tests (scan, rules, text)
tests/setup_fixtures.sh /tmp/e2e # requires `sops` and `age` on PATH
SOPS_AGE_KEY_FILE=/tmp/e2e/key.txt python3 tests/e2e.py target/debug/sops-ls /tmp/e2e

# root: type-check the Zed extension (host target is enough for a check)
cargo check
# real WASM build (needs: rustup target add wasm32-wasip2)
cargo build --release --target wasm32-wasip2

# Docker (from repo root)
docker buildx build --target test .
docker buildx build --target artifacts --output type=local,dest=dist .
```

**Definition of done for any server change:** `cargo test` and `tests/e2e.py` both pass, and `cargo build` produces no warnings. When you add a feature, add an e2e check for it. `e2e.py` acts as the editor: it applies `workspace/applyEdit` and sends `didChange`/`didSave`, so most flows can be tested end to end.

## Versions it was built and tested with

| Component | Version | Notes |
|---|---|---|
| Rust | 1.91 | edition 2021, uses `std::sync::LazyLock` (1.80+) |
| `zed_extension_api` | 0.7.0 | |
| `tower-lsp-server` | 0.23 | Community fork of tower-lsp. Types come from **`ls_types`** (not `lsp_types`), `Uri` replaces `Url` (use `uri.to_file_path()`), and `LanguageServer` uses native `async fn` in the trait (no `#[async_trait]`). |
| `yaml-rust2` | 0.13 | `Marker::index()` is a **char** index, despite its doc comment saying bytes. `scan.rs` converts it, and the `yaml_paths_and_spans` test (non-ASCII key) covers this. |
| sops | 3.13.3 | requires ≥ 3.9 for `--filename-override` and stdin input |
| age | 1.2.1 | tests only |

## Architecture

### Document state (`server.rs`)

`State` lives behind a `std::sync::Mutex`.

- `docs`: open documents, synced with FULL text sync.
- `ciphertexts`: the last known ciphertext per URI. It is updated whenever a document's text is SOPS-encrypted, and kept after `didClose` on purpose.
- `decrypted`: the result of `sops decrypt --output-type json`, keyed by a hash of the document content, including errors.
- `inlay_override`: the runtime toggle for inlay hints.
- `settings`.

A document is in a **"decrypted session"** when its text is *not* encrypted but `ciphertexts` has an entry for it. This single definition covers *Decrypt for editing*, undoing back to plaintext, and reopening a file that is plaintext on disk. All save protection keys off `Snapshot.session`.

### Analysis (`scan.rs`)

`scan.rs` is pure and side-effect free, so keep it that way. `Analysis::new(text, fmt)` recomputes tokens, leaves and metadata on every request (no caching). That's fine for typical secret files; cache it only if profiling says so.

- **`Leaf`:** a scalar value with its key path (`Vec<Seg>`) and byte span. YAML uses the `yaml-rust2` event parser. JSON uses a hand-written tokenizer, because sops emits tab-indented JSON and that must not depend on YAML parsing quirks. Dotenv and INI are line based.
- **Metadata normalisation:** metadata is flattened to `Vec<String>` paths so YAML/JSON (`sops.age[0].recipient`), dotenv (`sops_age__list_0__map_recipient`) and INI (`[sops] age__list_0__map_recipient`) all become `["age","0","recipient"]`.
- **Hover and inlay mapping:** decrypted values are found by looking up the leaf's key path in the JSON tree that sops returns. sops can turn all four formats into JSON (verified); INI gets a `DEFAULT` section.

### sops integration (`sops.rs`)

- **Decrypt:** `sops decrypt --input-type T --output-type json|T`, with the buffer piped on stdin.
- **First-time encrypt:** `sops [--config C] encrypt --input-type T --output-type T --filename-override <real path>`, with the plaintext piped on stdin and cwd set to the file's directory.
- **Re-encrypt (`reencrypt`):** writes the *previous ciphertext* to a temp file and runs `sops edit` on it, with `SOPS_EDITOR`/`EDITOR` set to `'<this exe>' __sops-editor '<sentinel>'`. sops shlex-splits that string and appends its decrypted temp file path. sops forwards its stdin to the editor, so the new plaintext is piped into sops and `editor_main` copies it into the temp file. This keeps the data key and recipients, and it needs no `.sops.yaml` and no encryption-side key access.

Behaviour of `sops edit` that was verified against 3.13.3:

| Situation | Result |
|---|---|
| Content unchanged | exits **200** ("File has not changed"), which is treated as success |
| Content invalid | sops prompts "Press enter to return to the editor" and calls the editor **again**. With stdin at EOF this loops forever. The sentinel file makes the second editor run fail, so sops exits **201**. |
| Plaintext fails the YAML/JSON syntax check | rejected by `Format::validate` before sops is ever called |
| Changed unencrypted value / tampered file | `sops decrypt` reports "MAC mismatch" with exit 51 |

### Save protection

There are three layers, in this order:

1. **`textDocument/formatting`** returns the full ciphertext when the document is in a session, and `None` otherwise. Users configure `sops-ls` as the last formatter. A code action of kind `source.sops.encrypt` also returns an eager `edit` when that kind is explicitly requested via `context.only`, for Zed's `code_actions_on_format`.
2. **`willSaveWaitUntil`**: same edit, gated by `encryptOnSave`.
3. **`didSave` fallback**: if the saved text is still a session, the server re-encrypts it, writes the result atomically (temp file plus rename, keeping permissions) and relies on Zed to reload the clean buffer.

## Invariants: do not break these

- **The server never writes plaintext to disk.** Plaintext travels only through pipes. The only file it writes in `reencrypt` is ciphertext (sops' own edit temp file is sops' responsibility). `atomic_write` only ever receives ciphertext.
- **Never log or show plaintext.** That covers `log_message`, `show_message`, diagnostics and error strings. sops stderr is safe to show; decrypted values are not, except in hover and inlay hints, which the user explicitly asked for.
- **Serialise sops calls through `sops_lock`** (a tokio mutex). This prevents parallel PIN/pinentry prompts. Re-check the cache after acquiring it.
- **Never hold the `std::sync::Mutex` across `.await`.** Take a `Snapshot`, drop the guard, then do the async work.
- **Every sops call goes through `Sops::run`,** which applies `timeoutSecs` and `kill_on_drop`. A forgotten PIN prompt must not hang the server.
- **Keep the logic in `sops-ls`, not in `src/lib.rs`.** The extension must stay a thin launcher.
- **Respect the negotiated position encoding.** Use `LineIndex`; never compute LSP columns by hand.
- **Diagnostic codes are API.** Code actions match on them (`should-be-encrypted`) and the README documents them: `decrypt-failed`, `malformed-ciphertext`, `plaintext-value`, `decrypted-buffer`, `should-be-encrypted`.

## Verified vs. unverified

**Verified by tests in this environment:**
- All server behaviour covered by `e2e.py` and the unit tests, run against real sops 3.13.3 and age.
- The extension crate type-checks against `zed_extension_api` 0.7.0 (host target).

**Verified by reading Zed's source (`zed-industries/zed`, main branch, November 2026)** but not exercised in a running Zed:
- Zed builds Rust extensions for `wasm32-wasip2`.
- A `Cargo.toml` present makes `zed: install dev extension` always compile, which needs rustup.
- At startup Zed loads any `<data dir>/extensions/installed/<id>/` folder containing `extension.toml` and `extension.wasm`. It reads the API version from the wasm, and a symlinked folder counts as a dev extension. This is what `install.sh` relies on, but see the next section: the folder alone is not enough.
- Data dirs: `~/.local/share/zed` (Linux, or `$FLATPAK_XDG_DATA_HOME/zed`), `~/Library/Application Support/Zed` (macOS), `%LOCALAPPDATA%\Zed` (Windows).
- No extension with id `sops` exists in `zed-industries/extensions` as of writing.

**Verified on a real machine (Zed 1.27.0, Linux):**
- `install.sh` works and the extension shows up in the extension manager, but only with two fixes. (1) The installed `extension.toml` needs a `[lib] kind = "Rust"` / `version = "0.7.0"` section. Zed's own build step writes it, and without a `Cargo.toml` Zed cannot infer it, so the wasm is not loaded. `install.sh` appends it. The `version` must match the `zed_extension_api` version. (2) Zed caches installed extensions in `<data dir>/extensions/index.json` and did not re-scan on restart, so a folder dropped in later was silently ignored (the log only says "loading 8"). `install.sh` deletes the file to force a rebuild.
- The Docker `artifacts` output is flat (`dist/extension.toml`, `dist/extension.wasm`, `dist/sops-ls`), with no `zed-sops-rs/` subfolder.
- Hover shows decrypted values in a running Zed. Opening an encrypted file leaves the buffer as ciphertext by design; the user runs the *SOPS: Decrypt for editing* code action.

**Not verified at all. Check these before relying on them:**
- The extension has never been loaded in a running Zed instance, and the WASM build itself has never been run (no wasm target was available).
- Whether Zed sends `willSaveWaitUntil`.
- Whether a `formatter` *array* including `sops-ls` behaves as the README claims.
- Whether `code_actions_on_format` applies our eager edit.
- Whether `"Env"` is the right language name for dotenv files in Zed. The server also detects dotenv files by file name, but Zed only starts the server for languages listed in `extension.toml`.
- Whether Zed reliably reloads a clean buffer after the `didSave` fallback rewrites the file.
- The GitHub release workflow has never been run. The Dockerfile `artifacts` target and `install.sh` have been run on Linux (see above); the Docker `test` target and macOS install are untested.
- The `SOPS_EDITOR` quoting on Windows (single-quoted path under Go shlex).

## Placeholders to fill before release

- `GITHUB_REPO` in `src/lib.rs` and `repository` in `extension.toml` (both currently `OWNER/zed-sops`).
- `authors` in `extension.toml`.
- **Release asset naming:** `src/lib.rs` downloads `sops-ls-<target>.tar.gz` (`.zip` on Windows) with targets `{x86_64,aarch64}-{unknown-linux-gnu,apple-darwin}` and `x86_64-pc-windows-msvc`. `release.yml` must keep producing exactly these names. The archive must contain the binary at its root.

## Known limitations and ideas

- **Every ciphertext changes on re-encrypt.** Re-encryption gives every value fresh IVs, as `sops edit` does, so diffs are noisy. *Idea:* after re-encrypting, restore the old `ENC[...]` string for paths whose plaintext is unchanged. This is only valid if the MAC and the per-value AAD (the key path) still verify, so confirm with `sops decrypt` in a test before shipping it.
- **Encrypted comments** (`#ENC[...,type:comment]`) can't be shown in hover, because JSON output drops comments. Possible fix: decrypt in native format and match comment lines.
- **The sops "binary" format** (arbitrary files wrapped as `{"data": ..., "sops": ...}`) gets JSON treatment only; there is no special UX for it.
- **Configuration:** the server only reads `didChangeConfiguration.settings` and `initializationOptions`; it never pulls `workspace/configuration`.
- **`ciphertexts` grows without bound** over the server's lifetime (one entry per encrypted file ever opened). That's harmless for normal use; evict on file deletion if it matters.
- **Recipient display** shows one identifying field per key type (`vault_url`, `vault_address`); Azure key names and Vault key names are not shown.
- **`.sops.yaml` matching** checks `path_regex` against both the absolute path and the path relative to the config's directory, and ignores catch-all rules on purpose. sops itself also matches a rule's `path_regex` against `--filename-override`. Edge cases (Go vs. Rust regex syntax differences) aren't handled.
- **No document caching:** `Analysis` is recomputed per request.

## Conventions

- Keep user-facing strings prefixed `SOPS:` (code actions, messages) and diagnostics `source: "sops"`.
- Code action kinds: `source.sops.decrypt`, `source.sops.encrypt`, `source.sops.maintenance`, and `quickfix` for the creation-rule encryption.
- Command IDs: `sops.decrypt`, `sops.encrypt`, `sops.discard`, `sops.toggleInlayHints`, `sops.updateKeys`, `sops.rotate`. The first argument is always the document URI string.
- Settings are camelCase (`sopsPath`, `hoverDecrypt`, `inlayHints`, `encryptOnSave`, `verifyOnOpen`, `timeoutSecs`, `env`), accepted either bare or under a `"sops"` key. When you add a setting, update `Settings::default()`, the README table and this file.
- Error messages from sops pass through `clean_error`, which strips log decoration and update notices. Keep sops' own wording; users search for it.
