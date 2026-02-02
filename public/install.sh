#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/axostichus/catboys.nu.git"
TMP_DIR="/tmp/catboys.nu-install"
INSTALL_DIR="$HOME/.local/bin"

trap 'rm -rf "$TMP_DIR"' EXIT

for cmd in git bun; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: $cmd is not installed." >&2
    echo "Please install it first:" >&2
    echo "  - git: https://git-scm.com/downloads" >&2
    echo "  - bun: https://bun.com" >&2
    exit 1
  fi
done

rm -rf "$TMP_DIR"
git clone --depth 1 "$REPO" "$TMP_DIR"
cd "$TMP_DIR"

echo "Building catboy..."
cd cli
bun install
bun build ./index.js --compile --outfile catboy

if [[ ! -x ./catboy ]]; then
  echo "Error: Build failed" >&2
  exit 1
fi

chmod +x catboy

mkdir -p "$INSTALL_DIR"
if [[ -f "$INSTALL_DIR/catboy" ]]; then
  read -p "catboy already exists at $INSTALL_DIR/catboy. Replace? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
fi

mv catboy "$INSTALL_DIR/catboy"
echo "catboy installed to $INSTALL_DIR/catboy"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  echo ""
  echo "Note: $INSTALL_DIR is not in your PATH"
  echo "Add this line to your shell config (~/.bashrc or ~/.zshrc):"
  echo ""
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo ""
fi

echo "Run 'catboy --help' to get started"
