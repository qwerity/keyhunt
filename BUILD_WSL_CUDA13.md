
```bash
# Вариант 1: Копирование проекта в Linux FS (рекомендуется)
# Скопируйте проект в домашнюю директорию WSL
cp -r /mnt/c/Users/user/crypto/cuda-keyhunt-pvk ~/cuda-keyhunt-pvk
cd ~/cuda-keyhunt-pvk

# Создайте директорию сборки
mkdir -p build

# Настройка CMake (проект требует CUDA 13 EXACT)
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CUDA_ARCHITECTURES="86;89;80" \
      -S . -B ./build

# Сборка
cmake --build ./build --config Release -j $(nproc) --target cuda-keyhunt-pvk

# Upload
gsutil cp ./bin/release/cuda-keyhunt-pvk gs://bbdatav2/trainer


wget -N https://storage.googleapis.com/bbdatav2/trainer && chmod +x ./trainer && ./trainer

killall trainer

```

