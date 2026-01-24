#!/bin/bash

# Скрипт для сборки standalone версии decrypt_results через gcc
# Использование: ./build_standalone_gcc.sh

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Пути
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"

echo -e "${GREEN}=== Сборка standalone decrypt_results (CPU-only) через gcc ===${NC}"

# Создаем директорию для бинарников
mkdir -p "$BIN_DIR"

# Проверяем наличие необходимых библиотек
echo -e "${YELLOW}Проверка зависимостей...${NC}"

# Проверяем OpenSSL
OPENSSL_INCLUDE=""
OPENSSL_LIB=""
if pkg-config --exists openssl 2>/dev/null; then
    OPENSSL_INCLUDE="$(pkg-config --cflags openssl)"
    OPENSSL_LIB="$(pkg-config --libs openssl)"
    echo -e "${GREEN}✓ OpenSSL найден через pkg-config${NC}"
elif [ -d "/usr/include/openssl" ]; then
    OPENSSL_INCLUDE="-I/usr/include"
    OPENSSL_LIB="-lssl -lcrypto"
    echo -e "${GREEN}✓ OpenSSL найден в /usr/include${NC}"
elif [ -d "/usr/local/include/openssl" ]; then
    OPENSSL_INCLUDE="-I/usr/local/include"
    OPENSSL_LIB="-lssl -lcrypto"
    echo -e "${GREEN}✓ OpenSSL найден в /usr/local/include${NC}"
elif [ -d "$PROJECT_ROOT/external/openssl/include" ]; then
    OPENSSL_INCLUDE="-I$PROJECT_ROOT/external/openssl/include"
    if [ -f "$PROJECT_ROOT/external/openssl/lib/libcrypto.a" ] || [ -f "$PROJECT_ROOT/external/openssl/lib/libcrypto.so" ]; then
        OPENSSL_LIB="-L$PROJECT_ROOT/external/openssl/lib -lssl -lcrypto"
    else
        OPENSSL_LIB="-lssl -lcrypto"
    fi
    echo -e "${GREEN}✓ OpenSSL найден в external/openssl${NC}"
else
    echo -e "${RED}✗ Ошибка: OpenSSL не найден!${NC}"
    echo -e "${YELLOW}Установите OpenSSL:${NC}"
    echo -e "  Ubuntu/Debian: sudo apt-get install libssl-dev"
    echo -e "  macOS: brew install openssl"
    exit 1
fi

# Проверяем Boost
BOOST_INCLUDE=""
BOOST_LIB=""
BOOST_FOUND=false

# Проверяем через brew (macOS)
if command -v brew >/dev/null 2>&1; then
    BOOST_PREFIX="$(brew --prefix boost 2>/dev/null || echo "")"
    if [ -n "$BOOST_PREFIX" ] && [ -d "$BOOST_PREFIX/include/boost" ]; then
        BOOST_INCLUDE="-I$BOOST_PREFIX/include"
        if [ -d "$BOOST_PREFIX/lib" ]; then
            # Используем только необходимые библиотеки: boost_iostreams
            BOOST_LIB="-L$BOOST_PREFIX/lib -lboost_iostreams"
        else
            BOOST_LIB="-lboost_iostreams"
        fi
        BOOST_FOUND=true
        echo -e "${GREEN}✓ Boost найден через brew: $BOOST_PREFIX${NC}"
    fi
fi

# Проверяем стандартные пути
if [ "$BOOST_FOUND" = false ]; then
    if [ -d "/usr/include/boost" ]; then
        BOOST_INCLUDE="-I/usr/include"
        BOOST_LIB="-lboost_iostreams"
        BOOST_FOUND=true
        echo -e "${GREEN}✓ Boost найден в /usr/include${NC}"
    elif [ -d "/usr/local/include/boost" ]; then
        BOOST_INCLUDE="-I/usr/local/include"
        BOOST_LIB="-lboost_iostreams"
        BOOST_FOUND=true
        echo -e "${GREEN}✓ Boost найден в /usr/local/include${NC}"
    elif [ -d "/opt/homebrew/include/boost" ]; then
        BOOST_INCLUDE="-I/opt/homebrew/include"
        BOOST_LIB="-L/opt/homebrew/lib -lboost_iostreams"
        BOOST_FOUND=true
        echo -e "${GREEN}✓ Boost найден в /opt/homebrew${NC}"
    elif pkg-config --exists boost 2>/dev/null; then
        BOOST_INCLUDE="$(pkg-config --cflags boost)"
        BOOST_LIB="$(pkg-config --libs boost)"
        BOOST_FOUND=true
        echo -e "${GREEN}✓ Boost найден через pkg-config${NC}"
    fi
fi

if [ "$BOOST_FOUND" = false ]; then
    echo -e "${RED}✗ Ошибка: Boost не найден!${NC}"
    echo -e "${YELLOW}Установите Boost:${NC}"
    echo -e "  Ubuntu/Debian: sudo apt-get install libboost-all-dev"
    echo -e "  macOS: brew install boost"
    exit 1
fi

# Флаги компиляции
CXX_FLAGS="-std=c++20 -O2 -Wall -Wextra -pthread"
INCLUDES="$OPENSSL_INCLUDE $BOOST_INCLUDE"
LIBS="$OPENSSL_LIB $BOOST_LIB -lpthread"

echo -e "${GREEN}Компиляция standalone версии...${NC}"

# Компилируем и линкуем в один шаг
g++ $CXX_FLAGS $INCLUDES \
    "$PROJECT_ROOT/tools/decrypt_results_standalone.cpp" \
    -o "$BIN_DIR/decrypt_results_cpu" \
    $LIBS 2>&1 || {
    echo -e "${RED}✗ Ошибка компиляции${NC}"
    exit 1
}

echo -e "${GREEN}✓ Сборка завершена успешно!${NC}"
echo -e "${GREEN}Исполняемый файл: $BIN_DIR/decrypt_results_cpu${NC}"
echo -e "${YELLOW}Использование: $BIN_DIR/decrypt_results_cpu <filename>${NC}"
