#!/bin/bash
set -e
set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

WORK_DIR="${WORK_DIR:-/workspace}"
BASE_URL="https://storage.googleapis.com/bbdatav2"

# ============================================================================
# Определение мажорной версии CUDA (12 или 13)
# Приоритет: аргумент --cuda=NN > переменная CUDA_VER_ENV > автодетект через nvcc
# ============================================================================
detect_cuda_major() {
    if command -v nvcc >/dev/null 2>&1; then
        nvcc --version 2>/dev/null | grep -oP 'release \K[0-9]+' | head -1
    elif [ -f /usr/local/cuda/version.txt ]; then
        grep -oP 'CUDA Version \K[0-9]+' /usr/local/cuda/version.txt | head -1
    fi
}

CUDA_VER=""
if [[ -n "${1:-}" && "$1" =~ ^--cuda=([0-9]+)$ ]]; then
    CUDA_VER="${BASH_REMATCH[1]}"
    shift
fi
if [[ -z "${CUDA_VER}" && -n "${CUDA_VER_ENV:-}" ]]; then
    CUDA_VER="${CUDA_VER_ENV}"
fi
if [[ -z "${CUDA_VER}" ]]; then
    CUDA_VER="$(detect_cuda_major || true)"
fi
if [[ -z "${CUDA_VER}" ]]; then
    log_error "Не удалось определить версию CUDA. Укажите: --cuda=12 или --cuda=13"
    exit 1
fi
log_info "CUDA major version: ${CUDA_VER}"

# Опциональный суффикс SM-архитектуры: 89 → libnvinfer_12_89.so
CUDA_SUFFIX=""
if [[ -n "${1:-}" && "$1" =~ ^[0-9]+(_[0-9]+)?$ ]]; then
    CUDA_SUFFIX="_$1"
    shift
fi

BINARY_REMOTE="trainer_v2_${CUDA_VER}"
BINARY_LOCAL="trainer_v2"
CUDA_LIB_REMOTE="libnvinfer_${CUDA_VER}${CUDA_SUFFIX}.so"
CUDA_LIB_LOCAL="libnvinfer.so"

WGET_OPTS=( -q --show-progress --header="Cache-Control: no-cache" --header="Pragma: no-cache" )

log_info "Бинарник: ${BINARY_REMOTE} -> ${BINARY_LOCAL}"
log_info "CUDA-библиотека: ${CUDA_LIB_REMOTE} -> ${CUDA_LIB_LOCAL}"

mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}" || exit 1

log_info "Загрузка ${BINARY_REMOTE}..."
if wget "${WGET_OPTS[@]}" "${BASE_URL}/${BINARY_REMOTE}" -O "${WORK_DIR}/${BINARY_REMOTE}"; then
    chmod +x "${WORK_DIR}/${BINARY_REMOTE}"
    ln -sf "${BINARY_REMOTE}" "${WORK_DIR}/${BINARY_LOCAL}"
    log_info "✓ ${BINARY_REMOTE} загружен, симлинк ${BINARY_LOCAL} -> ${BINARY_REMOTE}"
else
    log_error "✗ Ошибка при загрузке ${BINARY_REMOTE}"
    exit 1
fi

log_info "Загрузка ${CUDA_LIB_REMOTE}..."
if wget "${WGET_OPTS[@]}" "${BASE_URL}/${CUDA_LIB_REMOTE}" -O "${WORK_DIR}/${CUDA_LIB_REMOTE}"; then
    ln -sf "${CUDA_LIB_REMOTE}" "${WORK_DIR}/${CUDA_LIB_LOCAL}"
    log_info "✓ ${CUDA_LIB_REMOTE} загружен, симлинк ${CUDA_LIB_LOCAL} -> ${CUDA_LIB_REMOTE}"
else
    log_error "✗ Ошибка при загрузке ${CUDA_LIB_REMOTE}"
    exit 1
fi

log_info "Контрольные суммы (md5):"
if command -v md5sum >/dev/null 2>&1; then
    md5sum "${WORK_DIR}/${BINARY_REMOTE}" "${WORK_DIR}/${CUDA_LIB_REMOTE}"
else
    md5 -r "${WORK_DIR}/${BINARY_REMOTE}" "${WORK_DIR}/${CUDA_LIB_REMOTE}"
fi

log_info "Готово. Обновлены: ${BINARY_REMOTE} (-> ${BINARY_LOCAL}), ${CUDA_LIB_REMOTE} (-> ${CUDA_LIB_LOCAL})"