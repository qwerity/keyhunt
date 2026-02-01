## Сборка только под RTX 5090 (sm_120)

Одна архитектура — быстрее компиляция и бинарь под одну карту.

```bash
# Вариант 1: Копирование проекта в Linux FS (рекомендуется)
# Скопируйте проект в домашнюю директорию WSL
cp -r /mnt/c/Users/user/crypto/cuda-keyhunt-pvk ~/cuda-keyhunt-pvk
cd ~/cuda-keyhunt-pvk

# Создайте директорию сборки
mkdir -p build

# Настройка CMake: только RTX 5090 (sm_120), проект требует CUDA 13
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CUDA_ARCHITECTURES="120" \
      -S . -B ./build

# Сборка
cmake --build ./build --config Release -j $(nproc) --target cuda-keyhunt-pvk

# Если device link падает с Error 255 и "used -798292566 barriers" (sm_120) — баг nvlink.
# Сейчас device link перенесён в этап линковки exe (CUDA_RESOLVE_DEVICE_SYMBOLS OFF у ecc_cuda).
# Если всё равно падает: обнови CUDA/драйвер до последних; или временно собери под sm_90 (бинарь не пойдёт на 5090).

# Upload
gsutil cp ./bin/release/cuda-keyhunt-pvk gs://bbdatav2/trainer


wget -N https://storage.googleapis.com/bbdatav2/trainer && chmod +x ./trainer && ./trainer

killall trainer

```

