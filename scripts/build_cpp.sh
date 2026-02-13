#!/usr/bin/env bash
# Сборка C++ (legacy) бинарника cuda-keyhunt-pvk.
# Нужны: CMake, CUDA Toolkit, Boost, OpenSSL (в проекте), TBB (Linux).
# Бинарник: bin/cuda-keyhunt-pvk или bin/release/
#
# Использование:
#   ./scripts/build_cpp.sh           # arch 86
#   ./scripts/build_cpp.sh 75         # одна архитектура
#   ./scripts/build_cpp.sh all        # все архитектуры

set -e
cd "$(dirname "$0")/.."

ARCH="${1:-86}"
echo "CMAKE_CUDA_ARCHITECTURES=$ARCH"

cmake -B build -DCMAKE_CUDA_ARCHITECTURES="$ARCH"
cmake --build build --config=Release -j "$(nproc 2>/dev/null || echo 4)" --target cuda-keyhunt-pvk

echo "OK: bin/cuda-keyhunt-pvk (или bin/release/)"
