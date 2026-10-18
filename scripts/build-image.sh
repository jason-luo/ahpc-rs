#!/usr/bin/env bash
# 构建 myblog 的 linux/arm64 容器镜像（podman）。
#
# 镜像基于 scratch，只拷贝已交叉编译好的 aarch64 静态二进制，
# 因此构建过程不需要 qemu 模拟，也不需要任何基础镜像。
#
# 依赖：
#   - zig + cargo-zigbuild（见 scripts/build-release.sh 顶部说明）
#   - rustup target: aarch64-unknown-linux-musl
#   - podman
#
# 用法：
#   ./scripts/build-image.sh           # 构建镜像
#   ./scripts/build-image.sh --save    # 构建并导出 dist/*.tar.gz（供平台上传）
#
# 环境变量：
#   IMAGE   镜像标签，默认 myblog:1.0
#   ZIG_DIR zig 目录，默认自动查找 ~/.local/zig-*-macos-*
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
IMAGE="${IMAGE:-ahpc:$VERSION}"
TARGET="aarch64-unknown-linux-musl"
SAVE=0
[ "${1:-}" = "--save" ] && SAVE=1

# 工具路径
export PATH="/opt/podman/bin:$HOME/.cargo/bin:$PATH"
if [ -z "${ZIG_DIR:-}" ]; then
  ZIG_DIR="$(ls -d "$HOME"/.local/zig-*-macos-* 2>/dev/null | sort | tail -1 || true)"
fi
if [ -n "${ZIG_DIR:-}" ]; then
  export PATH="$ZIG_DIR:$PATH"
  export ZIG="$ZIG_DIR/zig"
fi

command -v cargo-zigbuild >/dev/null 2>&1 || { echo "错误：找不到 cargo-zigbuild" >&2; exit 1; }
command -v zig >/dev/null 2>&1 || { echo "错误：找不到 zig，请设置 ZIG_DIR" >&2; exit 1; }
command -v podman >/dev/null 2>&1 || { echo "错误：找不到 podman" >&2; exit 1; }

echo "镜像标签 : $IMAGE"
echo "目标平台 : linux/arm64"
echo "zig      : $(zig version)"
echo

echo "==> 交叉编译 $TARGET"
cargo zigbuild --release --target "$TARGET"

CONTEXT="$ROOT/dist/image-context"
rm -rf "$CONTEXT"
mkdir -p "$CONTEXT"
install -m 0755 "target/$TARGET/release/ahpc" "$CONTEXT/ahpc"
install -m 0755 "client.json" "$CONTEXT/client.json"

echo
echo "==> podman build"
podman build --platform linux/arm64 -f Dockerfile -t "$IMAGE" "$CONTEXT"
rm -rf "$CONTEXT"

echo
echo "==> 镜像"
podman images --filter "reference=$IMAGE"

if [ "$SAVE" = "1" ]; then
  NAME="$(echo "$IMAGE" | tr '/:' '__')"
  OUT="$ROOT/dist/${NAME}-arm64-image.tar"
  echo
  echo "==> 导出镜像（docker-archive，便于上传到运行平台）"
  podman save --format docker-archive -o "$OUT" "$IMAGE"
  gzip -f "$OUT"
  ls -lh "$OUT.gz"
  echo "提示：上传后在平台侧导入，例如  gunzip -c ${NAME}-arm64-image.tar.gz | podman load"
fi
