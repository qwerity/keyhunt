# Сборка decrypt_results (CPU-only версия) через gcc

## Быстрая сборка

```bash
cd tools
./build_standalone_gcc.sh
```

Исполняемый файл будет создан в `../bin/decrypt_results_cpu`

## Ручная сборка

```bash
g++ -std=c++20 -O2 -Wall -Wextra -pthread \
    decrypt_results_standalone.cpp \
    -I/usr/include \
    -lssl -lcrypto \
    -lboost_iostreams \
    -o ../bin/decrypt_results_cpu
```

## Зависимости

- **OpenSSL** (libssl-dev)
  - Ubuntu/Debian: `sudo apt-get install libssl-dev`
  - macOS: `brew install openssl`
  
- **Boost iostreams** (часть libboost-all-dev)
  - Ubuntu/Debian: `sudo apt-get install libboost-all-dev`
  - macOS: `brew install boost`

## Использование

```bash
./bin/decrypt_results_cpu <encrypted_results_file>
```

## Отличия от оригинальной версии

- Не требует CUDA
- Не зависит от других файлов проекта
- Все необходимые функции включены в один файл
- Использует те же константы AES ключа и IV
