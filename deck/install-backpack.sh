#!/bin/sh
# Install the backpack suite on a deck (or any Linux box).
#
#   ./install-backpack.sh            # fetch the latest prebuilt release
#   ./install-backpack.sh --source   # build from source instead (slow on a Pi)
#
# Prebuilt binaries are static musl builds — no runtime dependencies.
set -eu

REPO="squintdev/backpack"
PREFIX="${PREFIX:-/usr/local/bin}"
BINARIES="backpack veil scrub split keyring keyring-tui nostr canary stamp sats"

arch_target() {
    case "$(uname -m)" in
        aarch64) echo "aarch64-unknown-linux-musl" ;;
        armv7l)  echo "armv7-unknown-linux-musleabihf" ;;
        x86_64)  echo "x86_64-unknown-linux-musl" ;;
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac
}

install_release() {
    target="$(arch_target)"
    echo "fetching latest release for ${target}…"
    url=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
        grep -o "https://[^\"]*${target}\.tar\.gz" | head -1)
    [ -n "$url" ] || { echo "no release asset for ${target}" >&2; exit 1; }
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    curl -fsSL "$url" -o "$tmp/backpack.tar.gz"
    tar xzf "$tmp/backpack.tar.gz" -C "$tmp"
    for b in $BINARIES; do
        install -Dm755 "$tmp/$b" "$PREFIX/$b"
    done
    echo "installed to $PREFIX: $BINARIES"
}

install_source() {
    command -v cargo >/dev/null || {
        echo "rust not found — install rustup first (https://rustup.rs)" >&2
        exit 1
    }
    command -v cc >/dev/null || {
        echo "C compiler not found — needed for sats (pacman -S gcc)" >&2
        exit 1
    }
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    echo "cloning ${REPO}…"
    git clone --depth 1 "https://github.com/${REPO}" "$tmp/backpack"
    cd "$tmp/backpack"
    echo "building (this takes a while on a Pi)…"
    cargo build --release --workspace
    for b in $BINARIES; do
        install -Dm755 "target/release/$b" "$PREFIX/$b"
    done
    echo "installed to $PREFIX: $BINARIES"
}

case "${1:-}" in
    --source) install_source ;;
    "")       install_release ;;
    *) echo "usage: $0 [--source]" >&2; exit 1 ;;
esac

echo
echo "run 'backpack' to start, or 'backpack --keyring /path/to/usb/keyring.veil'"
echo "to use an identity carried on a USB drive."
