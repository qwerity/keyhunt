#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"
JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 14)

cmake -B build \
  -DKEYHUNT_DEBUG_LOGS=ON \
  -DCMAKE_CUDA_ARCHITECTURES="89;90;120" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build --config Release -j "$JOBS" --target cuda-keyhunt-pvk
