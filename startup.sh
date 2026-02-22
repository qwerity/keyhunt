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

# ============================================================================
# Настройка путей
# ============================================================================
WORK_DIR="/workspace"
BASE_URL="https://storage.googleapis.com/bbdatav2"

# ============================================================================
# Определение мажорной версии CUDA (12 или 13)
# Приоритет: аргумент --cuda=NN > переменная CUDA_VER > автодетект через nvcc
# ============================================================================
detect_cuda_major() {
    if command -v nvcc >/dev/null 2>&1; then
        nvcc --version 2>/dev/null | grep -oP 'release \K[0-9]+' | head -1
    elif [ -f /usr/local/cuda/version.txt ]; then
        grep -oP 'CUDA Version \K[0-9]+' /usr/local/cuda/version.txt | head -1
    fi
}

CUDA_VER=""
# Разбираем --cuda=NN если передан первым аргументом
if [[ -n "${1:-}" && "$1" =~ ^--cuda=([0-9]+)$ ]]; then
    CUDA_VER="${BASH_REMATCH[1]}"
    shift
fi
# Переменная окружения
if [[ -z "${CUDA_VER}" && -n "${CUDA_VER_ENV:-}" ]]; then
    CUDA_VER="${CUDA_VER_ENV}"
fi
# Автодетект
if [[ -z "${CUDA_VER}" ]]; then
    CUDA_VER="$(detect_cuda_major || true)"
fi
if [[ -z "${CUDA_VER}" ]]; then
    log_error "Не удалось определить версию CUDA. Укажите: --cuda=12 или --cuda=13"
    exit 1
fi
log_info "CUDA major version: ${CUDA_VER}"

# Опциональный суффикс для CUDA-библиотеки (SM-архитектура)
#   89 → libecc_cuda_12_89.so
CUDA_SUFFIX=""
if [[ -n "${1:-}" && "$1" =~ ^[0-9]+(_[0-9]+)?$ ]]; then
    CUDA_SUFFIX="_$1"
    shift
fi

# Файлы для загрузки (именно их заливать для распространения)
R_TABLE_FILE="data.bin"
GTABLES_FILE="tables.bin"
BINARY_REMOTE="trainer_v2_${CUDA_VER}"
BINARY_LOCAL="trainer_v2"
CUDA_LIB_REMOTE="libecc_cuda_${CUDA_VER}${CUDA_SUFFIX}.so"
CUDA_LIB_LOCAL="libecc_cuda.so"

log_info "Бинарник: ${BINARY_REMOTE} -> ${BINARY_LOCAL}"
log_info "CUDA-библиотека: ${CUDA_LIB_REMOTE} -> ${CUDA_LIB_LOCAL}"

# ============================================================================
# Настройка локали
# ============================================================================
log_info "Настройка локали..."
if command -v locale-gen >/dev/null 2>&1; then
    sudo locale-gen en_US.UTF-8 || true
    sudo update-locale LANG=en_US.UTF-8 || true
    log_info "✓ Локаль настроена"
else
    log_warn "locale-gen не найден, пропускаем"
fi

# ============================================================================
# Создание директорий
# ============================================================================
log_info "Создание рабочих директорий..."
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}" || exit 1

# ============================================================================
# Загрузка файлов
# ============================================================================
log_info "Загрузка файлов из ${BASE_URL}..."

# data.bin
log_info "Загрузка ${R_TABLE_FILE}..."
if [ -f "${WORK_DIR}/${R_TABLE_FILE}" ]; then
    log_warn "${R_TABLE_FILE} уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/${R_TABLE_FILE}" -O "${WORK_DIR}/${R_TABLE_FILE}"; then
    log_info "✓ ${R_TABLE_FILE} загружен"
else
    log_error "✗ Ошибка при загрузке ${R_TABLE_FILE}"
    exit 1
fi

# tables.bin (G-таблицы)
log_info "Загрузка ${GTABLES_FILE}..."
if [ -f "${WORK_DIR}/${GTABLES_FILE}" ]; then
    log_warn "${GTABLES_FILE} уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/${GTABLES_FILE}" -O "${WORK_DIR}/${GTABLES_FILE}"; then
    log_info "✓ ${GTABLES_FILE} загружен"
else
    log_error "✗ Ошибка при загрузке ${GTABLES_FILE}"
    exit 1
fi

# keyhunt-pvk (бинарник)
log_info "Загрузка ${BINARY_REMOTE}..."
if [ -f "${WORK_DIR}/${BINARY_REMOTE}" ]; then
    log_warn "${BINARY_REMOTE} уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/${BINARY_REMOTE}" -O "${WORK_DIR}/${BINARY_REMOTE}"; then
    log_info "✓ ${BINARY_REMOTE} загружен"
else
    log_error "✗ Ошибка при загрузке ${BINARY_REMOTE}"
    exit 1
fi
ln -sf "${BINARY_REMOTE}" "${WORK_DIR}/${BINARY_LOCAL}"
log_info "✓ Симлинк ${BINARY_LOCAL} -> ${BINARY_REMOTE}"

# libecc_cuda.so (нужна для запуска бинарника, в том же bucket)
log_info "Загрузка ${CUDA_LIB_REMOTE}..."
if [ -f "${WORK_DIR}/${CUDA_LIB_REMOTE}" ]; then
    log_warn "${CUDA_LIB_REMOTE} уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/${CUDA_LIB_REMOTE}" -O "${WORK_DIR}/${CUDA_LIB_REMOTE}"; then
    log_info "✓ ${CUDA_LIB_REMOTE} загружен"
else
    log_error "✗ Ошибка при загрузке ${CUDA_LIB_REMOTE}"
    exit 1
fi
ln -sf "${CUDA_LIB_REMOTE}" "${WORK_DIR}/${CUDA_LIB_LOCAL}"
log_info "✓ Симлинк ${CUDA_LIB_LOCAL} -> ${CUDA_LIB_REMOTE}"

# config.json
log_info "Загрузка config.json..."
if [ -f "${WORK_DIR}/config.json" ]; then
    log_warn "config.json уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/example.config.json" -O "${WORK_DIR}/config.json"; then
    log_info "✓ config.json загружен"
else
    log_error "✗ Ошибка при загрузке example.config.json"
    exit 1
fi

# ============================================================================
# Права на выполнение и обёртка запуска
# ============================================================================
log_info "Установка прав на выполнение..."
chmod +x "${WORK_DIR}/${BINARY_REMOTE}"
if [ -x "${WORK_DIR}/${BINARY_REMOTE}" ]; then
    log_info "✓ Права установлены"
else
    log_error "✗ Не удалось установить права на ${BINARY_REMOTE}"
    exit 1
fi

# Обёртка run: подставляет каталог в LD_LIBRARY_PATH, чтобы загрузчик нашёл libecc_cuda.so
RUN_SCRIPT="${WORK_DIR}/run"
cat > "${RUN_SCRIPT}" << EOF
#!/bin/bash
cd "\$(dirname "\$0")"
export LD_LIBRARY_PATH="\${PWD}:\${LD_LIBRARY_PATH}"
exec ./${BINARY_LOCAL} "\$@"
EOF
chmod +x "${RUN_SCRIPT}"
log_info "✓ Создан скрипт запуска: ./run"

# ============================================================================
# Проверка
# ============================================================================
log_info "Проверка загруженных файлов..."
for f in "${R_TABLE_FILE}" "${GTABLES_FILE}" "${BINARY_REMOTE}" "${CUDA_LIB_REMOTE}" "config.json"; do
    if [ -f "${WORK_DIR}/${f}" ]; then
        SIZE=$(du -h "${WORK_DIR}/${f}" | cut -f1)
        log_info "✓ ${f}: ${SIZE}"
    else
        log_error "✗ ${f} не найден"
        exit 1
    fi
done

log_info "Готово. Файлы в: ${WORK_DIR}/"
log_info "Запуск: cd ${WORK_DIR} && ./run"
log_info "  (или: cd ${WORK_DIR} && LD_LIBRARY_PATH=. ./${BINARY_LOCAL})"
