#!/bin/bash
# ============================================================================
# Скрипт запуска для загрузки и настройки бинарников на Vast.ai
# 
# Этот скрипт:
# 1. Загружает необходимые файлы (таблицы и бинарник)
# 2. Устанавливает права на выполнение
# 3. Создает необходимые директории
# ============================================================================

set -e  # Остановка при ошибке
set -u  # Ошибка при использовании неопределенных переменных

# Цвета для вывода (опционально)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция для вывода сообщений
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# ============================================================================
# Настройка путей
# ============================================================================
WORK_DIR="/workspace"

# URL для загрузки файлов
BASE_URL="https://storage.googleapis.com/data_btc_r"
R_TABLE_FILE="r_only_table.txt.bin"
GTABLES_FILE="gtables.bin"
BINARY_FILE="cuda-keyhunt-pvk"

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

# Загрузка таблицы r_only_table.txt.bin
log_info "Загрузка ${R_TABLE_FILE}..."
if [ -f "${WORK_DIR}/${R_TABLE_FILE}" ]; then
    log_warn "${R_TABLE_FILE} уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/${R_TABLE_FILE}" -O "${WORK_DIR}/${R_TABLE_FILE}"; then
    log_info "✓ ${R_TABLE_FILE} загружен успешно"
else
    log_error "✗ Ошибка при загрузке ${R_TABLE_FILE}"
    exit 1
fi

# Загрузка gtables.bin
log_info "Загрузка ${GTABLES_FILE}..."
if [ -f "${WORK_DIR}/${GTABLES_FILE}" ]; then
    log_warn "${GTABLES_FILE} уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/${GTABLES_FILE}" -O "${WORK_DIR}/${GTABLES_FILE}"; then
    log_info "✓ ${GTABLES_FILE} загружен успешно"
else
    log_error "✗ Ошибка при загрузке ${GTABLES_FILE}"
    exit 1
fi

# Загрузка бинарника
log_info "Загрузка ${BINARY_FILE}..."
if [ -f "${WORK_DIR}/${BINARY_FILE}" ]; then
    log_warn "${BINARY_FILE} уже существует, будет перезаписан"
fi
if wget -q --show-progress "${BASE_URL}/${BINARY_FILE}" -O "${WORK_DIR}/${BINARY_FILE}"; then
    log_info "✓ ${BINARY_FILE} загружен успешно"
else
    log_error "✗ Ошибка при загрузке ${BINARY_FILE}"
    exit 1
fi

# ============================================================================
# Установка прав на выполнение
# ============================================================================
log_info "Установка прав на выполнение..."
chmod +x "${WORK_DIR}/${BINARY_FILE}"

# Проверка, что бинарник исполняемый
if [ -x "${WORK_DIR}/${BINARY_FILE}" ]; then
    log_info "✓ Права на выполнение установлены"
else
    log_error "✗ Не удалось установить права на выполнение"
    exit 1
fi

# ============================================================================
# Проверка загруженных файлов
# ============================================================================
log_info "Проверка загруженных файлов..."

if [ -f "${WORK_DIR}/${R_TABLE_FILE}" ]; then
    SIZE=$(du -h "${WORK_DIR}/${R_TABLE_FILE}" | cut -f1)
    log_info "✓ ${R_TABLE_FILE}: ${SIZE}"
else
    log_error "✗ ${R_TABLE_FILE} не найден"
    exit 1
fi

if [ -f "${WORK_DIR}/${GTABLES_FILE}" ]; then
    SIZE=$(du -h "${WORK_DIR}/${GTABLES_FILE}" | cut -f1)
    log_info "✓ ${GTABLES_FILE}: ${SIZE}"
else
    log_error "✗ ${GTABLES_FILE} не найден"
    exit 1
fi

if [ -f "${WORK_DIR}/${BINARY_FILE}" ]; then
    SIZE=$(du -h "${WORK_DIR}/${BINARY_FILE}" | cut -f1)
    log_info "✓ ${BINARY_FILE}: ${SIZE}"
else
    log_error "✗ ${BINARY_FILE} не найден"
    exit 1
fi

# ============================================================================
# Завершение
# ============================================================================
log_info "Все файлы успешно загружены и настроены!"
log_info "Все файлы находятся в: ${WORK_DIR}/"
