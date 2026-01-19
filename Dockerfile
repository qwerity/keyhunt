# ============================================================================
# CUDA Runtime с инструментами разработки для Vast.ai
# Базовый образ: vastai/base-image (уже включает CUDA, Jupyter, SSH, dev tools)
# 
# ИСПОЛЬЗОВАНИЕ:
# 1. Сборка образа:
#    docker build -t cuda-runtime-devtools:latest .
#
# 2. Загрузка бинарников в образ:
#    docker run --gpus all -it --name temp-container cuda-runtime-devtools:latest /bin/bash
#    # В контейнере или через docker cp:
#    docker cp ./bin/release/your-binary temp-container:/app/bin/
#    docker commit temp-container cuda-runtime-devtools:latest
#    docker rm temp-container
#
# 3. Или монтирование бинарников при запуске:
#    docker run --gpus all -v $(pwd)/bin:/app/bin cuda-runtime-devtools:latest
#
# 4. Запуск с GPU поддержкой:
#    docker run --gpus all -it cuda-runtime-devtools:latest
#
# ИСПОЛЬЗОВАНИЕ НА VAST.AI:
# 1. Загрузите образ в DockerHub/GHCR (должен быть публичным):
#    docker tag cuda-runtime-devtools:latest yourusername/cuda-runtime-devtools:latest
#    docker push yourusername/cuda-runtime-devtools:latest
#
# 2. На Vast.ai:
#    - Docker Image: yourusername/cuda-runtime-devtools:latest
#    - Launch Mode: Jupyter (или Jupyter direct HTTPS)
#    - Environment Variables (опционально):
#      JUPYTER_DIR=/workspace
#      JUPYTER_PORT=8888
#
# 3. После запуска используйте Jupyter терминал для загрузки бинарников
#
# ПРИМЕЧАНИЕ: 
# - Базовый образ vastai/base-image:cuda-13.1.0-auto уже включает: CUDA 13.1, Jupyter, SSH, git, build tools
# - Здесь добавляем только: Boost, TBB, ZMQ runtime библиотеки
# - Бинарники нужно загружать отдельно через Jupyter терминал или SSH
# - Рабочая директория: /workspace
# ============================================================================

FROM docker.io/vastai/base-image:cuda-13.1.0-auto

# Установка только runtime библиотек (Boost, TBB, ZMQ)
# vastai/base-image:cuda-13.1.0-auto уже включает: CUDA 13.1, Python, Jupyter, SSH, git, build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libboost-system1.83.0 \
    libboost-filesystem1.83.0 \
    libboost-log1.83.0 \
    libboost-iostreams1.83.0 \
    libboost-regex1.83.0 \
    libtbb12 \
    libzmq5 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Если версии библиотек отличаются в вашей системе, используйте автоматическое определение:
# RUN apt-get update && \
#     apt-get install -y --no-install-recommends \
#     $(apt-cache depends libboost-system-dev libboost-filesystem-dev \
#                        libboost-log-dev libboost-iostreams-dev \
#                        libboost-regex-dev libtbb-dev | \
#      grep "Depends:" | grep -oE "lib[^ ]+" | sort -u) \
#     libzmq5 \
#     && apt-get clean && rm -rf /var/lib/apt/lists/*

# Переменные для Vast.ai совместимости (если не установлены в базовом образе)
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility

# Переменные для Jupyter (если не установлены в базовом образе)
ENV JUPYTER_DIR=/workspace
ENV JUPYTER_PORT=8888

# Создание директории для бинарников (workspace уже есть в базовом образе)
RUN mkdir -p /app/bin

# Установка PATH для удобного запуска бинарников
ENV PATH=/app/bin:${PATH}

# Рабочая директория (уже настроена в базовом образе)
WORKDIR /workspace
