#!/usr/bin/env bash
# 交叉编译 Linux x86_64 / arm64 静态二进制并打包。
#
# 依赖（全部为预编译产物，无需 Homebrew 编译）：
#   1) zig 0.16.0 解压到 ~/.local/zig-x86_64-macos-0.16.0
#        curl -L https://ziglang.org/download/0.16.0/zig-x86_64-macos-0.16.0.tar.xz | tar -xJ -C ~/.local
#   2) cargo-zigbuild 0.23.4 放到 ~/.cargo/bin
#        https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.23.4/cargo-zigbuild-x86_64-apple-darwin.tar.xz
#   3) rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#
# 可用环境变量覆盖：ZIG_DIR、DIST_DIR
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
DIST_DIR="${DIST_DIR:-dist}"

if [ -z "${ZIG_DIR:-}" ]; then
  ZIG_DIR="$(ls -d "$HOME"/.local/zig-*-macos-* 2>/dev/null | sort | tail -1 || true)"
fi
if [ -n "${ZIG_DIR:-}" ]; then
  export PATH="$ZIG_DIR:$PATH"
  export ZIG="$ZIG_DIR/zig"
fi
export PATH="$HOME/.cargo/bin:$PATH"

command -v zig >/dev/null 2>&1 || { echo "错误：找不到 zig，请设置 ZIG_DIR" >&2; exit 1; }
command -v cargo-zigbuild >/dev/null 2>&1 || { echo "错误：找不到 cargo-zigbuild（应在 ~/.cargo/bin）" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

echo "ahpc version : $VERSION"
echo "zig version    : $(zig version)"
echo "output dir     : $DIST_DIR"
echo

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

build_one() {
  local target="$1" pkgarch="$2"
  local pkgname="ahpc-${VERSION}-linux-${pkgarch}"
  local pkgdir="$DIST_DIR/$pkgname"

  echo "==> $target"
  cargo zigbuild --release --target "$target"

  mkdir -p "$pkgdir"
  install -m 0755 "target/$target/release/ahpc" "$pkgdir/ahpc"
  install -m 0644 client.json "$pkgdir/client.json"

  ( cd "$DIST_DIR" && tar -czf "$pkgname.tar.gz" "$pkgname" )
  rm -rf "$pkgdir"
  ( cd "$DIST_DIR" && sha256 "$pkgname.tar.gz" > "$pkgname.tar.gz.sha256" )

  echo "    -> $DIST_DIR/$pkgname.tar.gz"
}

build_one "x86_64-unknown-linux-musl" "amd64"
build_one "aarch64-unknown-linux-musl" "arm64"

echo
echo "==> 产物"
ls -lh "$DIST_DIR"
