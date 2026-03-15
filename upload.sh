#!/usr/bin/env bash
# Upload built artifacts to GCS.
#
# Usage:
#   ./upload.sh <cuda_major> <arch>
#
# Examples:
#   ./upload.sh 12 86
#   ./upload.sh 13 89
#   ./upload.sh 13 120

set -e

CUDA_MAJOR="${1:?Usage: $0 <cuda_major> <arch>}"
ARCH="${2:?Usage: $0 <cuda_major> <arch>}"

GS_BUCKET="gs://bbdatav2"
BUILD_DIR="build-cuda${CUDA_MAJOR}"
BIN_SUFFIX="cuda${CUDA_MAJOR}-sm${ARCH}"

LIB_SRC="${BUILD_DIR}/cuda/libnvinfer.so"
BIN_SRC="rust/target/release/keyhunt-pvk-${BIN_SUFFIX}"

echo "=== Uploading CUDA ${CUDA_MAJOR} / sm${ARCH} ==="

for f in "$LIB_SRC" "$BIN_SRC"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: $f not found. Build first: ./scripts/build_rust_with_cuda.sh ${CUDA_MAJOR} ${ARCH}"
    exit 1
  fi
done

echo "--- md5sum ---"
md5sum "$LIB_SRC" "$BIN_SRC"
echo ""

gsutil cp "$LIB_SRC" "${GS_BUCKET}/libnvinfer_${CUDA_MAJOR}_${ARCH}.so"
gsutil cp "$BIN_SRC" "${GS_BUCKET}/trainer_v2_${CUDA_MAJOR}"

VERSIONS_DIR="./versions"
mkdir -p "$VERSIONS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VERSION_FILE="${VERSIONS_DIR}/${TIMESTAMP}_cuda${CUDA_MAJOR}_sm${ARCH}.txt"
md5sum "$LIB_SRC" "$BIN_SRC" > "$VERSION_FILE"

echo ""
echo "Done:"
echo "  ${GS_BUCKET}/libnvinfer_${CUDA_MAJOR}_${ARCH}.so"
echo "  ${GS_BUCKET}/trainer_v2_${CUDA_MAJOR}"
echo "  md5: $VERSION_FILE"
