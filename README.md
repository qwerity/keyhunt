# cuda-keyhunt-pvk

Поиск ключей по hash160 на GPU (CUDA). Хост на **Rust** (рекомендуется) или C++; ядро — общее, вызывается через C API.

---

## Сборка

### Rust

**Нужно:** Rust (cargo). Для GPU — CUDA Toolkit и предварительная сборка CUDA-библиотек (см. ниже).

**Без GPU** (только проверить, что хост собирается):

```bash
cd rust && cargo build
```

Бинарник: `rust/target/debug/keyhunt-pvk`. Запуск закончится сообщением об отсутствии CUDA-устройств.

**С GPU:**

1. Собрать CUDA-библиотеки из корня проекта (один раз):

   **Linux / WSL:**

   ```bash
   cmake -B build -DCMAKE_CUDA_ARCHITECTURES=86
   cmake --build build --target keyhunt_cuda_capi
   ```

   **Windows:**
   ```bash
   cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_CUDA_ARCHITECTURES=86 -S . -B build
   cmake --build build --config=Release --target keyhunt_cuda_capi
   ```

2. Собрать Rust, указав папку с библиотеками:

   **Linux / WSL:**
   ```bash
   KEYHUNT_CUDA_LIB_DIR=$PWD/build/cuda cargo build --manifest-path rust/Cargo.toml --features cuda
   ```

   **Windows (из корня проекта):**
   ```bash
   set KEYHUNT_CUDA_LIB_DIR=%CD%\build\cuda\Release
   cargo build --manifest-path rust/Cargo.toml --features cuda
   ```

3. Бинарник: `rust/target/debug/keyhunt-pvk` (или `release` при `cargo build --release`).

---

### Утилиты (Rust)

В том же крейте собраны бинарники:

| Бинарник | Назначение |
|----------|------------|
| `decrypt_results` | Расшифровка `results.enc` (тот же формат/ключ, что при записи keyhunt). |
| `convert_hash160_to_binary` | Конвертация hex-файла (40 hex на hash) в .bin (20 байт на hash) для `hash160_targets`. |
| `gpu_info` | Вывод списка CUDA-устройств (нужна фича `gpu-info`, в runtime — CUDA-драйвер). |

**Сборка утилит** (из корня проекта):

```bash
./scripts/build_tools.sh
```

Или вручную:

```bash
cd rust
cargo build --release --bin decrypt_results --bin convert_hash160_to_binary
cargo build --release --bin gpu_info --features gpu-info
```

Примеры:

```bash
./rust/target/release/decrypt_results [results.enc]
./rust/target/release/convert_hash160_to_binary hashes.txt hashes.bin
./rust/target/release/gpu_info
```

---

### C++ (legacy)

**Нужно:** CMake, CUDA Toolkit, C++20, Boost (log, iostreams, regex), OpenSSL (есть в репозитории), на Linux — TBB.

**Linux / WSL:**

```bash
cmake -B build -DCMAKE_CUDA_ARCHITECTURES=86
cmake --build build --config=Release -j $(nproc) --target cuda-keyhunt-pvk
```

**Windows:**

```bash
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_CUDA_ARCHITECTURES=86 -S . -B build
cmake --build build --config=Release -j 14 --target cuda-keyhunt-pvk
```

Бинарник: `bin/cuda-keyhunt-pvk` (или `bin/release/`). Рядом положите `config.json`.

---

## Архитектура GPU и переиспользование ядра

`CMAKE_CUDA_ARCHITECTURES`: `86` (RTX 30xx), `75` (RTX 20xx), `120` (RTX 5090), или `all` для всех. Несколько через точку с запятой: `75;86`.

Узнать capability своей карты: собрать и запустить `gpu_info` (Rust) или таргет `gpu_info` (C++).

**Ядро CUDA** вынесено в C API (`cuda/keyhunt_capi.h` + `keyhunt_capi.cpp`), линкуется с `ecc_cuda`. Сейчас используется клюхантом (hash160, X-part, итерации). В будущем тот же/расширенный слой можно переиспользовать под другие проекты (mnemonic-hunter, другие сценарии) без дублирования ECC/hash160 — достаточно добавлять новые C API-функции или отдельные бинарники, вызывающие общее ядро. Подробнее: `docs/ARCHITECTURE.md`.

---

## Зависимости (C++ и CUDA)

- **Ubuntu:** `nvidia-cuda-toolkit`, `libtbb-dev`, `libboost-dev-all`
- **Windows:** Visual Studio 2019/2022, [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads), Boost (headers + system, log, iostreams, regex). OpenSSL уже в проекте.

---

## Конфиг и запуск

Рядом с бинарником должен лежать `config.json`. Пример: `example.config.json`. Ключи: `hash160_targets` (список файлов с целями), `server` (url, port, authorisationHeader), `pointsPerThread`, `blockSize`, `gridSize`, `forcePrivateXPart`, `specificXValues` и др.

---

## Дополнительно

**Опции CMake:** `BUILD_TESTS=ON`, `KEYHUNT_DEBUG_LOGS=ON` (подробный лог).

**Конвертация hex → binary для целей:** утилита `convert_hash160_to_binary` (см. «Утилиты (Rust)»).

**Vast.ai:** инстанс с нужным шаблоном, затем:
```bash
wget https://storage.googleapis.com/bbdatav2/startup.sh && chmod +x ./startup.sh && ./startup.sh
```
