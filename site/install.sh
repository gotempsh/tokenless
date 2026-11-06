#!/bin/sh
# SPDX-FileCopyrightText: 2026 tokenless contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

# Installs the tokenless binary from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/gotempsh/tokenless/main/site/install.sh | sh
#
# Settings (environment variables, all optional):
#   TOKENLESS_VERSION      release to install, e.g. v0.1.0 (default: the latest)
#   TOKENLESS_INSTALL_DIR  where to put the binary (default: /usr/local/bin when
#                          writable, otherwise ~/.local/bin)
#   TOKENLESS_REPO         GitHub repository to download from (default: gotempsh/tokenless)
#   TOKENLESS_DOWNLOAD_URL base URL holding the release files, for mirrors
#                          (default: the repository's GitHub release)
#
# The archive is checked against the release's SHA256SUMS before anything is
# installed. When cosign is on PATH, SHA256SUMS' signature is verified too.

set -eu

repo="${TOKENLESS_REPO:-gotempsh/tokenless}"
version="${TOKENLESS_VERSION:-latest}"

say() { printf '%s\n' "$*"; }
fail() {
  printf 'tokenless install: %s\n' "$*" >&2
  exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required but was not found"; }

target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64) arch=aarch64 ;;
    *) fail "no release is built for the $arch architecture; build it from source instead" ;;
  esac
  case "$os" in
    Linux) echo "$arch-unknown-linux-musl" ;;
    Darwin) echo "$arch-apple-darwin" ;;
    *) fail "no release is built for $os; build it from source instead" ;;
  esac
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  else
    fail "sha256sum or shasum is required to check the download"
  fi
}

install_dir() {
  if [ -n "${TOKENLESS_INSTALL_DIR:-}" ]; then
    echo "$TOKENLESS_INSTALL_DIR"
  elif [ -w /usr/local/bin ]; then
    echo /usr/local/bin
  else
    echo "$HOME/.local/bin"
  fi
}

main() {
  need curl
  need tar
  triple="$(target)"
  asset="tokenless-$triple.tar.gz"
  if [ -n "${TOKENLESS_DOWNLOAD_URL:-}" ]; then
    base="$TOKENLESS_DOWNLOAD_URL"
  elif [ "$version" = latest ]; then
    base="https://github.com/$repo/releases/latest/download"
  else
    base="https://github.com/$repo/releases/download/$version"
  fi

  # Only an explicit mirror may be plain HTTP; the checksum file comes from
  # the same place, so use one you trust.
  proto='=https'
  case "${TOKENLESS_DOWNLOAD_URL:-}" in http://*) proto='=http,https' ;; esac

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT INT TERM

  say "Downloading $asset ($version)"
  curl -fsSL --proto "$proto" --tlsv1.2 -o "$tmp/$asset" "$base/$asset" \
    || fail "could not download $base/$asset"
  curl -fsSL --proto "$proto" --tlsv1.2 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" \
    || fail "could not download $base/SHA256SUMS"

  if command -v cosign >/dev/null 2>&1; then
    curl -fsSL --proto "$proto" --tlsv1.2 -o "$tmp/SHA256SUMS.sigstore.json" "$base/SHA256SUMS.sigstore.json" \
      || fail "could not download $base/SHA256SUMS.sigstore.json"
    cosign verify-blob "$tmp/SHA256SUMS" \
      --bundle "$tmp/SHA256SUMS.sigstore.json" \
      --certificate-identity-regexp "^https://github.com/$repo/.github/workflows/release.yml@refs/tags/" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 \
      || fail "the signature on SHA256SUMS did not verify; not installing"
    say "Signature verified with cosign"
  fi

  expected="$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d ' ' -f 1)"
  [ -n "$expected" ] || fail "$asset is not listed in SHA256SUMS"
  actual="$(sha256 "$tmp/$asset")"
  [ "$expected" = "$actual" ] || fail "checksum mismatch for $asset; not installing"

  tar -xzf "$tmp/$asset" -C "$tmp"
  dir="$(install_dir)"
  mkdir -p "$dir" || fail "could not create $dir; set TOKENLESS_INSTALL_DIR to a writable directory"
  install -m 0755 "$tmp/tokenless-$triple/tokenless" "$dir/tokenless" 2>/dev/null \
    || { cp "$tmp/tokenless-$triple/tokenless" "$dir/tokenless" && chmod 0755 "$dir/tokenless"; } \
    || fail "could not write $dir/tokenless; set TOKENLESS_INSTALL_DIR to a writable directory"

  say "Installed $("$dir/tokenless" --version) to $dir/tokenless"
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) say "Add $dir to your PATH to run it as tokenless." ;;
  esac
  say "Start it with: tokenless serve --data-dir ./tokenless-data"
}

main "$@"
