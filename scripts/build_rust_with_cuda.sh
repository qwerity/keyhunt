#!/usr/bin/env bash
# Полная сборка Rust + GPU (release): CUDA-библиотеки, затем cargo --features cuda --release.
# Запускать из корня проекта. Требует CUDA Toolkit.
#
# Использование:
#   ./scripts/build_rust_with_cuda.sh [cuda_ver] [arch]
#
# Примеры:
#   ./scripts/build_rust_with_cuda.sh              # CUDA auto, arch 86
#   ./scripts/build_rust_with_cuda.sh 12 86        # CUDA 12, arch 86  (RTX 30xx)
#   ./scripts/build_rust_with_cuda.sh 13 89        # CUDA 13, arch 89  (RTX 40xx)
#   ./scripts/build_rust_with_cuda.sh 13 120       # CUDA 13, arch 120 (RTX 50xx)
#   ./scripts/build_rust_with_cuda.sh auto 75      # auto-detect CUDA, arch 75

set -e
cd "$(dirname "$0")/.."

CUDA_VER="${1:-auto}"
ARCH="${2:-86}"

###############################################################################
# Resolve CUDA toolkit path
###############################################################################
resolve_cuda_path() {
  local ver="$1"

  if [[ "$ver" == "auto" ]]; then
    # Prefer CUDA_PATH/CUDA_HOME if already set
    for p in "$CUDA_PATH" "$CUDA_HOME"; do
      [[ -n "$p" && -x "$p/bin/nvcc" ]] && echo "$p" && return
    done
    # Fall back to nvcc in PATH
    local nvcc
    nvcc=$(command -v nvcc 2>/dev/null) || true
    if [[ -n "$nvcc" ]]; then
      local real
      real=$(realpath "$nvcc" 2>/dev/null || readlink -f "$nvcc" 2>/dev/null || echo "$nvcc")
      echo "$(cd "$(dirname "$(dirname "$real")")" && pwd)"
      return
    fi
    echo >&2 "ERROR: nvcc not found. Set CUDA_PATH or pass CUDA version (12/13)."
    exit 1
  fi

  # Explicit version: search /usr/local/cuda-<ver>*
  local best=""
  for d in /usr/local/cuda-${ver} /usr/local/cuda-${ver}.*/; do
    [[ -x "${d}/bin/nvcc" || -x "${d%/}/bin/nvcc" ]] && best="${d%/}"
  done
  [[ -n "$best" ]] && echo "$best" && return

  # Try /opt/cuda-<ver>
  for d in /opt/cuda-${ver} /opt/cuda-${ver}.*/; do
    [[ -x "${d}/bin/nvcc" || -x "${d%/}/bin/nvcc" ]] && best="${d%/}"
  done
  [[ -n "$best" ]] && echo "$best" && return

  echo >&2 "ERROR: CUDA $ver not found. Install it or check paths."
  echo >&2 "  Expected: /usr/local/cuda-${ver}* or /opt/cuda-${ver}*"
  exit 1
}

CUDA_ROOT=$(resolve_cuda_path "$CUDA_VER")
NVCC_BIN="$CUDA_ROOT/bin/nvcc"
DETECTED_VER=$("$NVCC_BIN" --version 2>/dev/null | grep -oP 'release \K[0-9]+\.[0-9]+' || echo "?")

echo "========================================"
echo "  CUDA:  $CUDA_ROOT  (nvcc $DETECTED_VER)"
echo "  ARCH:  $ARCH"
echo "========================================"

###############################################################################
# Each CUDA major version gets its own build dir to avoid cmake re-configure
###############################################################################
CUDA_MAJOR="${DETECTED_VER%%.*}"
BUILD_DIR="build-cuda${CUDA_MAJOR}"

echo "=== 1/2 CMake (CUDA + util)  [${BUILD_DIR}] ==="
cmake -B "$BUILD_DIR" \
  -DCMAKE_CUDA_COMPILER="$NVCC_BIN" \
  -DCMAKE_CUDA_ARCHITECTURES="$ARCH"

cmake --build "$BUILD_DIR" --target keyhunt_cuda_capi util -j "$(nproc 2>/dev/null || echo 4)"

echo "=== 2/2 Rust (cuda, release) ==="
export KEYHUNT_CUDA_LIB_DIR="$PWD/$BUILD_DIR/cuda"
export KEYHUNT_PROJECT_ROOT="$PWD"
export CUDA_PATH="$CUDA_ROOT"

# -L для cudart_static
RUSTFLAGS="${RUSTFLAGS:-}"
for _d in \
  "$CUDA_ROOT/targets/x86_64-linux/lib" "$CUDA_ROOT/lib64" "$CUDA_ROOT/lib"; do
  [[ -f "${_d}/libcudart_static.a" ]] && RUSTFLAGS="$RUSTFLAGS -L $_d" && echo "RUSTFLAGS -L $_d" && break
done
# -L для wallycore и secp256k1
[[ -d "$PWD/external/wallycore/lib" ]] && RUSTFLAGS="$RUSTFLAGS -L $PWD/external/wallycore/lib"
[[ -d /usr/lib/x86_64-linux-gnu ]]    && RUSTFLAGS="$RUSTFLAGS -L /usr/lib/x86_64-linux-gnu"
export RUSTFLAGS

if ! cargo build --release --manifest-path rust/Cargo.toml --features cuda --bin keyhunt-pvk 2>&1 | tee /tmp/keyhunt_rust_build.log; then
  echo "--- последние 40 строк (ошибка линковки) ---"
  tail -40 /tmp/keyhunt_rust_build.log
  exit 1
fi

cp -f "$BUILD_DIR/cuda/libnvinfer.so" rust/target/release/ 2>/dev/null || true

BIN_SUFFIX="cuda${CUDA_MAJOR}-sm${ARCH}"
BIN_SRC="rust/target/release/keyhunt-pvk"
BIN_DST="rust/target/release/keyhunt-pvk-${BIN_SUFFIX}"
cp -f "$BIN_SRC" "$BIN_DST"
echo ""
echo "OK: $BIN_DST  (CUDA $DETECTED_VER, arch $ARCH)"
echo "    Запуск: ./$BIN_DST"
