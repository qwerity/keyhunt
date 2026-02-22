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

CUDA_SUFFIX=""
if [[ -n "${1:-}" && "$1" =~ ^[0-9]+$ ]]; then
    CUDA_SUFFIX="_$1"
    shift
fi

BINARY_FILE="trainer_v2"
CUDA_LIB_FILE="libecc_cuda${CUDA_SUFFIX}.so"

# Скачивать без кеша (заголовки для сервера/CDN)
WGET_OPTS="-q --show-progress --header=Cache-Control: no-cache --header=Pragma: no-cache"

if [[ -n "${CUDA_SUFFIX}" ]]; then
    log_info "Вариант CUDA-библиотеки: ${CUDA_LIB_FILE} (суффикс из аргумента)"
fi

mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}" || exit 1

log_info "Загрузка ${BINARY_FILE}..."
if wget $WGET_OPTS "${BASE_URL}/${BINARY_FILE}" -O "${WORK_DIR}/${BINARY_FILE}"; then
    chmod +x "${WORK_DIR}/${BINARY_FILE}"
    log_info "✓ ${BINARY_FILE} загружен"
else
    log_error "✗ Ошибка при загрузке ${BINARY_FILE}"
    exit 1
fi

log_info "Загрузка ${CUDA_LIB_FILE}..."
if wget $WGET_OPTS "${BASE_URL}/${CUDA_LIB_FILE}" -O "${WORK_DIR}/${CUDA_LIB_FILE}"; then
    log_info "✓ ${CUDA_LIB_FILE} загружен"
else
    log_error "✗ Ошибка при загрузке ${CUDA_LIB_FILE}"
    exit 1
fi

if [[ -n "${CUDA_SUFFIX}" ]]; then
    ln -sf "${CUDA_LIB_FILE}" "${WORK_DIR}/libecc_cuda.so"
    log_info "✓ Симлинк libecc_cuda.so -> ${CUDA_LIB_FILE}"
fi

log_info "Контрольные суммы (md5):"
if command -v md5sum >/dev/null 2>&1; then
    md5sum "${WORK_DIR}/${BINARY_FILE}" "${WORK_DIR}/${CUDA_LIB_FILE}"
else
    md5 -r "${WORK_DIR}/${BINARY_FILE}" "${WORK_DIR}/${CUDA_LIB_FILE}"
fi

log_info "Готово. Обновлены: ${BINARY_FILE}, ${CUDA_LIB_FILE}"