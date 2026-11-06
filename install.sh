#!/usr/bin/env bash
# Installs a prebuilt sops-ls + Zed extension without a Rust toolchain.
#   docker buildx build --target artifacts --output type=local,dest=dist .
#   ./install.sh            (then restart Zed)
set -euo pipefail
DIST=${DIST:-dist}
BIN_DIR=${BIN_DIR:-$HOME/.local/bin}

case "$(uname -s)" in
  Linux)  DATA="${FLATPAK_XDG_DATA_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}}/zed" ;;
  Darwin) DATA="$HOME/Library/Application Support/Zed" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
EXT_DIR="$DATA/extensions/installed/sops"

[ -f "$DIST/extension.wasm" ] || { echo "missing $DIST/; run the docker build first" >&2; exit 1; }

if [ "$(uname -s)" = Linux ]; then
  install -Dm755 "$DIST/sops-ls" "$BIN_DIR/sops-ls"
  echo "installed $BIN_DIR/sops-ls"
else
  echo "note: $DIST/sops-ls is a Linux binary; on macOS install sops-ls from a release or set lsp.sops-ls.binary.path"
fi

# Zed treats a symlinked folder as a dev extension (rebuilt with cargo on
# reinstall), so copy real files.
rm -rf "$EXT_DIR"
mkdir -p "$EXT_DIR"
cp "$DIST/extension.wasm" "$EXT_DIR/"
cp "$DIST/extension.toml" "$EXT_DIR/extension.toml"
# Zed's own build step adds [lib] to installed manifests. Without it Zed has
# no Cargo.toml to infer the extension is Rust and never loads the wasm.
grep -q '^\[lib\]' "$EXT_DIR/extension.toml" || \
  printf '\n[lib]\nkind = "Rust"\nversion = "0.7.0"\n' >> "$EXT_DIR/extension.toml"
# Force Zed to rebuild its extension index on next start.
rm -f "$DATA/extensions/index.json"
echo "installed Zed extension to $EXT_DIR, restart Zed to load it"
