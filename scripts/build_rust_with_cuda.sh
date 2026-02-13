#!/usr/bin/env bash
# Полная сборка Rust + GPU (release): CUDA-библиотеки, затем cargo --features cuda --release.
# Запускать из корня проекта. Требует CUDA Toolkit.
#
# Использование:
#   ./scripts/build_rust_with_cuda.sh      # arch 86
#   ./scripts/build_rust_with_cuda.sh 75    # arch 75
#   ./scripts/build_rust_with_cuda.sh all   # все архитектуры

set -e
cd "$(dirname "$0")/.."

ARCH="${1:-86}"

echo "=== 1/2 CMake (CUDA + util) ==="
cmake -B build -DCMAKE_CUDA_ARCHITECTURES="$ARCH"
cmake --build build --target keyhunt_cuda_capi -j "$(nproc 2>/dev/null || echo 4)"
cmake --build build --target util -j "$(nproc 2>/dev/null || echo 4)"

echo "=== 2/2 Rust (cuda, release) ==="
export KEYHUNT_CUDA_LIB_DIR="$PWD/build/cuda"
export KEYHUNT_PROJECT_ROOT="$PWD"
# Чтобы линкер нашёл libcudart_static.a, задаём CUDA_PATH по nvcc (если ещё не задан)
if [ -z "${CUDA_PATH:-}" ] && [ -z "${CUDA_HOME:-}" ]; then
  NVCC=$(which nvcc 2>/dev/null)
  if [ -n "$NVCC" ]; then
    REAL=$(realpath "$NVCC" 2>/dev/null || readlink -f "$NVCC" 2>/dev/null || echo "$NVCC")
    export CUDA_PATH="$(cd "$(dirname "$(dirname "$REAL")")" 2>/dev/null && pwd)"
    [ -n "$CUDA_PATH" ] && echo "CUDA_PATH=$CUDA_PATH"
  fi
fi
# -L для cudart_static
for _d in \
  "$CUDA_PATH/targets/x86_64-linux/lib" "$CUDA_PATH/lib64" "$CUDA_PATH/lib" \
  "$CUDA_HOME/targets/x86_64-linux/lib" "$CUDA_HOME/lib64" "$CUDA_HOME/lib" \
  /usr/local/cuda/targets/x86_64-linux/lib /usr/local/cuda/lib64 \
  /usr/local/cuda-13.1/targets/x86_64-linux/lib /opt/cuda/lib64; do
  [ -n "$_d" ] && [ -f "${_d}/libcudart_static.a" ] && export RUSTFLAGS="${RUSTFLAGS:-} -L $_d" && echo "RUSTFLAGS -L $_d" && break
done
# -L для wallycore и secp256k1 (util)
[ -d "$PWD/external/wallycore/lib" ] && export RUSTFLAGS="${RUSTFLAGS:-} -L $PWD/external/wallycore/lib"
[ -d /usr/lib/x86_64-linux-gnu ] && export RUSTFLAGS="${RUSTFLAGS:-} -L /usr/lib/x86_64-linux-gnu"
if ! cargo build --release --manifest-path rust/Cargo.toml --features cuda --bin keyhunt-pvk 2>&1 | tee /tmp/keyhunt_rust_build.log; then
  echo "--- последние 40 строк (ошибка линковки) ---"
  tail -40 /tmp/keyhunt_rust_build.log
  exit 1
fi

echo "OK: rust/target/release/keyhunt-pvk"
