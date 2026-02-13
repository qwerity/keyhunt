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

echo "=== 1/2 CUDA (arch=$ARCH) ==="
cmake -B build -DCMAKE_CUDA_ARCHITECTURES="$ARCH"
cmake --build build --target keyhunt_cuda_capi -j "$(nproc 2>/dev/null || echo 4)"

echo "=== 2/2 Rust (cuda, release) ==="
export KEYHUNT_CUDA_LIB_DIR="$PWD/build/cuda"
cargo build --release --manifest-path rust/Cargo.toml --features cuda

echo "OK: rust/target/release/keyhunt-pvk"
