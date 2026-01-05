# Рекомендации по оптимизации генерации публичных ключей

## Анализ текущей реализации

### ✅ Сильные стороны

1. **Предвычисленная таблица (precomputed table)**
   - Таблица `prec[128][4]` в constant memory
   - Window size = 2 бита (ECMULT_GEN_PREC_B = 2)
   - 128 итераций × 4 варианта = эффективная скалярная операция

2. **Оптимизации компилятора**
   - `#pragma unroll` для циклов
   - `__forceinline__` для критичных функций
   - Constant memory для таблицы предвычислений

3. **Эффективный доступ к памяти**
   - Используются `uint4` для векторных операций
   - Coalesced memory access через правильную индексацию

### ❌ Узкие места

#### 1. **Множественные SWAP32 операции** (критично!)
```cpp
// Строки 86-89: входной swap
for (uint32_t j = 0; j < 8; ++j)
{
    privateKey->v[j] = SWAP32(privateKey->v[j]);
}

// Строки 95-99: выходной swap
for (uint32_t j = 0; j < 8; ++j)
{
    newX->v[j] = SWAP32(newX->v[j]);
    newY->v[j] = SWAP32(newY->v[j]);
}
```

**Проблема**: 24 операции SWAP32 на каждый ключ (8 входных + 16 выходных)

**Решение**: 
- Хранить данные в формате, который ожидает secp256k1 (little-endian)
- Убрать все swap операции
- **Ожидаемый прирост**: 10-15% производительности

#### 2. **Промежуточные структуры**
```cpp
HDExtendedPrivateKey privateExKey;
HDExtendedPublicKey publicEXKey;
```

**Проблема**: Лишние копирования данных

**Решение**: Работать напрямую с `uint256_t` или использовать union

#### 3. **Window size = 2 бита**

**Текущее**: ECMULT_GEN_PREC_B = 2 → 128 итераций

**Варианты оптимизации**:
- Увеличить до 4 бит → 64 итерации (но таблица 16×64 вместо 4×128)
- Увеличить до 5 бит → 51 итерация (но таблица 32×51)

**Компромисс**: Больше таблица в constant memory, но меньше итераций

**Рекомендация**: Протестировать window size = 4 бита

#### 4. **КРИТИЧНО: Избыточные операции маскирования в secp256k1_ecmult_gen** ⚠️

**Проблема**: Текущая реализация обрабатывает ВСЕ варианты таблицы, даже если нужен только один!

**Текущий код** (`secp256k1.cu:940-962`):
```cpp
for (uint32_t j = 0; j < 128; ++j)  // ECMULT_GEN_PREC_N = 128
{
    const uint32_t bits = secp256k1_scalar_get_bits(gn, j * 2, 2);
    #pragma unroll
    for (uint32_t i = 0; i < 4; ++i)  // ECMULT_GEN_PREC_G = 4
    {
        // Маскирование для ВСЕХ 4 вариантов, даже если нужен только 1!
        uint32_t mask0 = (i == bits) + ~0u;
        uint32_t mask1 = ~mask0;
        // 16 операций маскирования для каждого i (8 для x, 8 для y)
        adds.x.n[0] = (adds.x.n[0] & mask0) | (prec[j][i].x.n[0] & mask1);
        // ... еще 15 операций
    }
}
```

**Вычислительная сложность**:
- 128 итераций × 4 варианта = **512 циклов маскирования**
- Каждый цикл: 16 операций (8 для x, 8 для y)
- **Итого: 512 × 16 = 8192 операции маскирования на одно скалярное умножение!**

**Почему это критично**: 
- Обрабатываются все 4 варианта, даже если нужен только один (bits = 0, 1, 2 или 3)
- В среднем ~50% битов приватного ключа = 0, но код все равно обрабатывает все варианты
- Это объясняет, почему CudaBrainSecp быстрее **на порядки**

**Решение**: Использовать прямой доступ к таблице (как в CudaBrainSecp)

## Уроки из CudaBrainSecp (быстрее на порядки)

### Анализ подхода CudaBrainSecp

**Ключевые преимущества их реализации**:

1. **Прямой доступ к таблице вместо маскирования**
   ```cpp
   // CudaBrainSecp: прямой доступ
   int index = (CHUNK_FIRST_ELEMENT[chunk] + (privKey[chunk] - 1)) * SIZE_GTABLE_POINT;
   memcpy(qx, gTableX + index, SIZE_GTABLE_POINT);
   
   // Текущая реализация: маскирование всех вариантов
   for (uint32_t i = 0; i < 4; ++i) {
       // 16 операций маскирования для каждого i
   }
   ```

2. **Пропуск нулевых chunks**
   ```cpp
   // CudaBrainSecp: пропускает нулевые chunks
   if (privKey[chunk] > 0) {
       _PointAddSecp256k1(qx, qy, qz, gx, gy);
   }
   
   // Текущая реализация: обрабатывает все 128 итераций всегда
   ```

3. **Меньше операций на ключ**
   - CudaBrainSecp: ~32-64 операций (только ненулевые chunks)
   - Текущая: 8192 операции маскирования + 128 операций сложения

4. **Меньше branch divergence**
   - CudaBrainSecp: обрабатывает только ненулевые chunks
   - Текущая: все потоки выполняют все операции

### Что взять из CudaBrainSecp

1. **Прямой доступ к таблице** (критично!)
   - Вместо маскирования всех вариантов, использовать прямой индекс
   - Убрать внутренний цикл `for (uint32_t i = 0; i < 4; ++i)`

2. **Пропуск нулевых битов**
   - Проверять `if (bits != 0)` перед добавлением точки
   - Это может сэкономить ~50% операций (если ~50% битов = 0)

3. **Chunk-based подход** (опционально)
   - Группировать биты в chunks
   - Обрабатывать только ненулевые chunks

## Конкретные рекомендации по оптимизации

### Приоритет 0 (КРИТИЧНО): Исправить secp256k1_ecmult_gen

**Текущий код** (`secp256k1.cu:928-966`):
```cpp
__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn)
{
    secp256k1_ge add;
    secp256k1_ge_storage adds;
    secp256k1_gej_set_infinity(r);

    #pragma unroll
    for (uint32_t j = 0; j < ECMULT_GEN_PREC_N; ++j)
    {
        const uint32_t bits = secp256k1_scalar_get_bits(gn, j * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        #pragma unroll
        for (uint32_t i = 0; i < ECMULT_GEN_PREC_G; ++i)  // ПРОБЛЕМА: обрабатывает все 4 варианта!
        {
            uint32_t mask0 = (i == bits) + ~0u;
            uint32_t mask1 = ~mask0;
            // 16 операций маскирования...
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
}
```

**Оптимизированный вариант** (прямой доступ):
```cpp
__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn)
{
    secp256k1_ge add;
    secp256k1_gej_set_infinity(r);

    #pragma unroll
    for (uint32_t j = 0; j < ECMULT_GEN_PREC_N; ++j)
    {
        const uint32_t bits = secp256k1_scalar_get_bits(gn, j * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        
        // ПРЯМОЙ ДОСТУП вместо маскирования всех вариантов!
        secp256k1_ge_from_storage(&add, &prec[j][bits]);
        
        // Пропуск нулевых битов (опционально, но дает прирост)
        if (bits != 0) {
            secp256k1_gej_add_ge(r, r, &add);
        }
    }
}
```

**Ожидаемый прирост**: **200-500%** (убирает 8192 лишних операции маскирования!)

### Приоритет 1: Убрать SWAP32 операции

**Текущий код** (`ecc_helper.cu:85-99`):
```cpp
/// TODO: optimize this
for (uint32_t j = 0; j < 8; ++j)
{
    privateKey->v[j] = SWAP32(privateKey->v[j]);
}
generatePublicFromPrivateKey(&privateExKey, &publicEXKey);
// ... еще swap для X и Y
```

**Оптимизированный вариант**:
1. Хранить приватные ключи в формате little-endian с самого начала
2. Убрать все swap операции
3. Если нужно - сделать swap только один раз при чтении/записи

### Приоритет 2: Оптимизировать структуру данных

**Вариант A**: Использовать union для избежания копирований
```cpp
union {
    uint256_t key;
    uint8_t bytes[32];
} privateKey;
```

**Вариант B**: Работать напрямую с байтами
```cpp
// Вместо создания HDExtendedPrivateKey, работать напрямую
uint8_t seckey[32];
// Копировать напрямую из privateKey
```

### Приоритет 3: Увеличить window size

**Изменения в `secp256k1_defines.cuh`**:
```cpp
// Было:
#define ECMULT_GEN_PREC_BITS 2
#define ECMULT_GEN_PREC_G (1 << ECMULT_GEN_PREC_B)  // 4
#define ECMULT_GEN_PREC_N (256 / ECMULT_GEN_PREC_B) // 128

// Станет (window size = 4):
#define ECMULT_GEN_PREC_BITS 4
#define ECMULT_GEN_PREC_G (1 << ECMULT_GEN_PREC_B)  // 16
#define ECMULT_GEN_PREC_N (256 / ECMULT_GEN_PREC_B) // 64
```

**Плюсы**: В 2 раза меньше итераций
**Минусы**: Таблица в 4 раза больше (но все еще помещается в constant memory)

### Приоритет 4: Оптимизация доступа к памяти

**Текущий код** использует правильную индексацию, но можно улучшить:
- Использовать `__ldg()` для чтения из global memory (кэширование)
- Рассмотреть использование shared memory для часто используемых данных

## Ожидаемый прирост производительности

| Оптимизация | Ожидаемый прирост | Сложность | Приоритет |
|------------|-------------------|-----------|-----------|
| **Исправить secp256k1_ecmult_gen** (прямой доступ) | **200-500%** | Средняя | **КРИТИЧНО** |
| Пропуск нулевых битов | 50-100% | Низкая | Высокий |
| Убрать SWAP32 | 10-15% | Низкая | Высокий |
| Увеличить window size до 4 | 15-25% | Высокая | Средний |
| Убрать промежуточные структуры | 5-8% | Средняя | Средний |
| Оптимизация доступа к памяти | 3-5% | Средняя | Низкий |
| **Итого (с критичной оптимизацией)** | **500-1000%** | | |

**Примечание**: Исправление `secp256k1_ecmult_gen` - это самая критичная оптимизация, которая может дать прирост **на порядки**, как в CudaBrainSecp!

## Дополнительные оптимизации из CudaBrainSecp

### 1. Использование pinned memory с WriteCombined
```cpp
// CudaBrainSecp использует:
cudaHostAlloc(&outputBufferCPU, COUNT_CUDA_THREADS, 
              cudaHostAllocWriteCombined | cudaHostAllocMapped);
```
**Преимущество**: Быстрее передача данных CPU ↔ GPU

### 2. Настройка кэша L1
```cpp
// CudaBrainSecp использует:
cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);
```
**Преимущество**: Больше L1 кэша для вычислений

### 3. Использование Jacobian координат
CudaBrainSecp использует Jacobian координаты (`qz[5]`) и конвертирует в конце.
**Преимущество**: Меньше операций модульной инверсии

## Дополнительные рекомендации

### 1. Профилирование
Использовать `nvprof` или `nsight compute` для точного определения узких мест:
```bash
nvprof --print-gpu-trace ./cuda-keyhunt-pvk
nvprof --metrics all ./cuda-keyhunt-pvk  # Для детального анализа
```

### 2. Использование PTX
Рассмотреть ручную оптимизацию критичных участков через inline PTX

### 3. Batch processing
Если возможно, обрабатывать несколько ключей одновременно в одном вызове ядра

### 4. Использование Tensor Cores (для новых GPU)
Для некоторых операций можно использовать Tensor Cores, но это требует значительной переработки

### 5. Сравнение с CudaBrainSecp
После оптимизации `secp256k1_ecmult_gen` производительность должна быть сопоставима с CudaBrainSecp

## Тестирование

После каждой оптимизации необходимо:
1. Проверить корректность результатов
2. Измерить производительность (MKey/s)
3. Проверить использование регистров и shared memory
4. Убедиться, что occupancy не упал

## Пример оптимизированного кода

### Критичная оптимизация: secp256k1_ecmult_gen

**До** (текущая реализация - медленная):
```cpp
__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn)
{
    secp256k1_ge add;
    secp256k1_ge_storage adds;
    secp256k1_gej_set_infinity(r);

    #pragma unroll
    for (uint32_t j = 0; j < ECMULT_GEN_PREC_N; ++j)
    {
        const uint32_t bits = secp256k1_scalar_get_bits(gn, j * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        #pragma unroll
        for (uint32_t i = 0; i < ECMULT_GEN_PREC_G; ++i)  // ПРОБЛЕМА!
        {
            uint32_t mask0 = (i == bits) + ~0u;
            uint32_t mask1 = ~mask0;
            // 16 операций маскирования для каждого i
            adds.x.n[0] = (adds.x.n[0] & mask0) | (prec[j][i].x.n[0] & mask1);
            // ... еще 15 операций
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
}
```

**После** (оптимизированная версия - быстрая):
```cpp
__device__ void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn)
{
    secp256k1_ge add;
    secp256k1_gej_set_infinity(r);

    #pragma unroll
    for (uint32_t j = 0; j < ECMULT_GEN_PREC_N; ++j)
    {
        const uint32_t bits = secp256k1_scalar_get_bits(gn, j * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        
        // ПРЯМОЙ ДОСТУП - убрали внутренний цикл и маскирование!
        secp256k1_ge_from_storage(&add, &prec[j][bits]);
        
        // Опционально: пропуск нулевых битов (экономит ~50% операций)
        if (bits != 0) {
            secp256k1_gej_add_ge(r, r, &add);
        }
    }
}
```

**Результат**: 
- Убрано 8192 операции маскирования на одно скалярное умножение
- Прямой доступ к нужному элементу таблицы
- Пропуск нулевых битов экономит дополнительные операции
- **Ожидаемый прирост: 200-500%**

