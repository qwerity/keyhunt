
```bash
# Вариант 1: Копирование проекта в Linux FS (рекомендуется)
# Скопируйте проект в домашнюю директорию WSL
cp -r /mnt/c/Users/user/crypto/cuda-keyhunt-pvk ~/cuda-keyhunt-pvk
cd ~/cuda-keyhunt-pvk

# Создайте директорию сборки
mkdir -p build

# Настройка CMake (проект требует CUDA 13 EXACT)
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CUDA_ARCHITECTURES="all" \
      -S . -B ./build

# Сборка
cmake --build ./build --config Release -j $(nproc) --target cuda-keyhunt-pvk

# Upload
gsutil cp ./cuda-keyhunt-pvk gs://data_btc_r

wget -N https://storage.googleapis.com/data_btc_r/cuda-keyhunt-pvk && chmod +x ./cuda-keyhunt-pvk && ./cuda-keyhunt-pvk
```

