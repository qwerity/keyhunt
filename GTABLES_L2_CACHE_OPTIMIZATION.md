# Оптимизация gtables для L2 кеша

## Текущее состояние

### Хранение gtables
- **Тип**: `thrust::udevice_vector<secp256k1_ge_storage>` в global memory
- **Размер**: 64 MB (1,048,576 записей × 64 байта)
- **Структура**: 
  - 16 чанков (`ECMULT_GEN_PREC_N = 16`)
  - 65,536 значений на чанк (`ECMULT_GEN_PREC_G = 65536`)
  - Каждая запись: `secp256k1_ge_storage` (64 байта, выровнено на 32 байта)

### Доступ к данным
- Доступ через `d_gTable_ptr` (указатель в device memory)
- Используется `__ldg()` для read-only cache оптимизации
- Паттерн доступа: `tableIndex = chunk * 65536 + (chunkValue - 1)`
- Каждый поток читает до 16 записей (по одной на чанк)

### Проблема
- L2 кеш на современных GPU (RTX 4090/5090): 4-8 MB
- Таблица: 64 MB - **не помещается полностью в L2**
- Доступ случайный внутри каждого чанка

## Реализованные оптимизации

### 1. `cudaMemAdviseSetReadMostly`
```cpp
cudaMemAdvise(d_gTableRawPtr, tableSizeBytes, cudaMemAdviseSetReadMostly, deviceId);
```
- Указывает GPU, что данные преимущественно читаются
- Позволяет более агрессивное кеширование в L2
- Улучшает производительность для read-only данных

### 2. `cudaMemAdviseSetAccessedBy`
```cpp
cudaMemAdvise(d_gTableRawPtr, tableSizeBytes, cudaMemAdviseSetAccessedBy, deviceId);
```
- Оптимизирует доступ с устройства
- Улучшает prefetching и кеширование

### 3. Persisting L2 Cache (для Ampere+)
- Для GPU с compute capability 8.0+ (RTX 30xx, A100, RTX 40xx, RTX 50xx)
- Резервирует до 4 MB L2 кеша специально для gtables
- Использует `cudaMemAdviseSetPreferredLocation`
- Значительно улучшает производительность на современных GPU

## Дополнительные возможности оптимизации

### 1. Shared Memory кеширование
Можно кешировать часто используемые чанки в shared memory:
```cpp
__shared__ secp256k1_ge_storage shared_chunk[ECMULT_GEN_PREC_G];
```
- Плюсы: очень быстрый доступ
- Минусы: ограниченный размер shared memory (48-164 KB на SM)
- Подходит для: кеширования одного активного чанка на блок

### 2. Уменьшение размера таблицы
- Использовать меньший window size (например, 15 бит вместо 16)
- Уменьшит размер с 64 MB до ~32 MB
- Но увеличит количество итераций в цикле

### 3. Сжатие данных
- Использовать compressed point format (33 байта вместо 64)
- Уменьшит размер до ~34 MB
- Но потребует декомпрессию при чтении

### 4. Texture Memory (устаревший подход)
- Texture memory автоматически кешируется
- Но deprecated в современных версиях CUDA
- `__ldg()` уже обеспечивает read-only cache

## Ожидаемый эффект

### На GPU без persisting L2 cache (Pascal, Turing)
- Улучшение: 5-15% за счет read-mostly hints
- L2 hit rate: ~10-20% (таблица слишком большая)

### На GPU с persisting L2 cache (Ampere, Ada, Blackwell)
- Улучшение: 15-30% за счет резервирования L2
- L2 hit rate: ~30-50% для часто используемых чанков
- Особенно эффективно при повторном доступе к одним и тем же чанкам

## Мониторинг производительности

Для проверки эффективности можно использовать:
```bash
nvprof --metrics l2_cache_hit_rate,global_hit_rate ./key_hunter
```

Или через Nsight Compute:
- L2 Cache Hit Rate
- Memory Throughput
- Global Memory Load Efficiency

## Рекомендации

1. ✅ **Реализовано**: Использовать `cudaMemAdvise` для оптимизации
2. ✅ **Реализовано**: Резервировать L2 cache на поддерживаемых GPU
3. ⚠️ **Рассмотреть**: Shared memory кеширование для критических путей
4. ⚠️ **Рассмотреть**: Профилирование для определения hot-spot чанков

## Файлы изменены

- `cuda/ecc.cu`: Добавлена оптимизация L2 кеша в `allocateGTableDeviceMemory()`
