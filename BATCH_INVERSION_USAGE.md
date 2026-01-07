# Batch Inversion - Руководство по использованию

## Что такое Batch Inversion?

Batch inversion (пакетная инверсия) - это оптимизация, которая позволяет вычислять обратные значения нескольких элементов поля одновременно, используя трюк Монтгомери.

**Преимущества:**
- Вместо N инверсий: **1 инверсия + 2*(N-1) умножений**
- **Ожидаемый прирост скорости: 20-30%** при обработке 4-8 элементов одновременно
- Особенно эффективно при обработке нескольких точек эллиптической кривой

## Доступные функции

### 1. `secp256k1_fe_batch_inv` - Batch инверсия полей

```cpp
__device__ void secp256k1_fe_batch_inv(
    secp256k1_fe* results,      // Выходной массив обратных значений
    const secp256k1_fe* inputs,  // Входной массив элементов для инверсии
    int count                     // Количество элементов (max 16)
);
```

**Пример использования:**
```cpp
// Инвертировать 4 элемента одновременно
secp256k1_fe inputs[4], results[4];
// ... инициализация inputs ...
secp256k1_fe_batch_inv(results, inputs, 4);
// Теперь results[i] = 1 / inputs[i] для всех i
```

### 2. `secp256k1_ge_set_gej_batch` - Batch нормализация точек

```cpp
__device__ void secp256k1_ge_set_gej_batch(
    secp256k1_ge* results,       // Выходной массив точек в аффинных координатах
    secp256k1_gej* points,      // Входной массив точек в якобиановых координатах
    int count                     // Количество точек (max 16)
);
```

**Пример использования:**
```cpp
// Нормализовать 4 точки одновременно
secp256k1_gej points[4];
secp256k1_ge results[4];
// ... вычисление points в якобиановых координатах ...
secp256k1_ge_set_gej_batch(results, points, 4);
// Теперь results[i] содержит нормализованные точки
```

## Где применять для оптимизации

### 1. HD Wallet - Генерация нескольких публичных ключей

**Текущий код** (`hd_wallet_kernels.cuh`, строка 159-165):
```cpp
// "m/addr" - public keys
#pragma unroll
for (uint32_t i = 0; i < d_hdWalletAddressesToGenerate; ++i)
{
    outPrivateKey[i] = m_privateKeys_int[i];
    generatePublicFromPrivateKey(m_privateKeys_int + i, outPublicKeys + i);
}
```

**Оптимизированный вариант:**
```cpp
// Собрать все точки в якобиановых координатах
secp256k1_gej points[d_hdWalletAddressesToGenerate];
for (uint32_t i = 0; i < d_hdWalletAddressesToGenerate; ++i)
{
    outPrivateKey[i] = m_privateKeys_int[i];
    // Вычислить точки в якобиановых координатах (без нормализации)
    // ... код генерации точек ...
}

// Нормализовать все точки batch'ом
secp256k1_ge normalized_points[d_hdWalletAddressesToGenerate];
secp256k1_ge_set_gej_batch(normalized_points, points, d_hdWalletAddressesToGenerate);

// Сохранить результаты
for (uint32_t i = 0; i < d_hdWalletAddressesToGenerate; ++i)
{
    outPublicKeys[i] = normalized_points[i];
}
```

**Ожидаемый прирост:** 20-30% при генерации 4-8 адресов одновременно

### 2. Public Key Generation Kernel - Обработка нескольких ключей в потоке

**Текущий код** (`ecc_helper.cu`, строка 199-222):
```cpp
__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys)
{
    for(uint32_t i = 0; i < d_pointsPerThread; ++i)
    {
        // ... генерация публичного ключа ...
        generatePublicFromPrivateKey(&privateExKey, &publicEXKey);
        // ...
    }
}
```

**Оптимизированный вариант:**
```cpp
__global__ void publicKeyGenerationKernel(const uint256_t *privateKeys)
{
    // Если d_pointsPerThread <= 16, можно использовать batch normalization
    if (d_pointsPerThread <= 16)
    {
        secp256k1_gej points[d_pointsPerThread];
        
        // Вычислить все точки в якобиановых координатах
        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            // ... вычисление точек без нормализации ...
            // Сохранить в points[i]
        }
        
        // Нормализовать все точки batch'ом
        secp256k1_ge normalized[d_pointsPerThread];
        secp256k1_ge_set_gej_batch(normalized, points, d_pointsPerThread);
        
        // Сохранить результаты
        for(uint32_t i = 0; i < d_pointsPerThread; ++i)
        {
            // ... сохранить normalized[i] ...
        }
    }
    else
    {
        // Fallback к обычному методу для больших batch'ей
        // ...
    }
}
```

**Ожидаемый прирост:** 15-25% при обработке 4-8 ключей в одном потоке

### 3. Batch Point Addition - Сложение нескольких точек

Если нужно сложить несколько точек одновременно, можно использовать batch inversion для знаменателей:

```cpp
__device__ void secp256k1_gej_add_ge_batch(
    secp256k1_gej* results,
    const secp256k1_gej* a,
    const secp256k1_ge* points,
    int count)
{
    // Вычислить все знаменатели (x1 - x2) для каждой точки
    secp256k1_fe denominators[16];
    for (int i = 0; i < count; i++) {
        // Вычислить (a->x - points[i].x)
        // ...
    }
    
    // Batch inversion всех знаменателей
    secp256k1_fe inv_denominators[16];
    secp256k1_fe_batch_inv(inv_denominators, denominators, count);
    
    // Вычислить все результаты используя предвычисленные инверсии
    for (int i = 0; i < count; i++) {
        // Использовать inv_denominators[i] для вычисления results[i]
        // ...
    }
}
```

**Ожидаемый прирост:** 20-30% при сложении 4-8 точек одновременно

## Рекомендации по применению

### Когда использовать batch inversion:

1. ✅ **Обработка 4-16 элементов одновременно** - оптимальный диапазон
2. ✅ **Все элементы известны заранее** - можно собрать их в массив
3. ✅ **Обработка в одном потоке** - нет необходимости в синхронизации между потоками
4. ✅ **Критичный путь производительности** - где инверсии являются узким местом

### Когда НЕ использовать:

1. ❌ **Обработка 1-2 элементов** - overhead не оправдан
2. ❌ **Обработка >16 элементов** - нужно разбивать на батчи
3. ❌ **Элементы вычисляются последовательно** - нельзя собрать их заранее
4. ❌ **Разные потоки обрабатывают разные элементы** - нет возможности batch'а

## Измерение производительности

Для проверки эффективности оптимизации:

1. **До оптимизации:** Измерить время выполнения с обычными инверсиями
2. **После оптимизации:** Измерить время с batch inversion
3. **Сравнить:** Ожидаемый прирост 20-30% для 4-8 элементов

Пример измерения:
```cpp
cudaEvent_t start, stop;
cudaEventCreate(&start);
cudaEventCreate(&stop);

cudaEventRecord(start);
// ... код с batch inversion ...
cudaEventRecord(stop);
cudaEventSynchronize(stop);

float milliseconds = 0;
cudaEventElapsedTime(&milliseconds, start, stop);
printf("Time: %f ms\n", milliseconds);
```

## Ограничения

- **Максимальный размер batch:** 16 элементов (можно увеличить, изменив `MAX_BATCH_SIZE`)
- **Использование регистров:** Batch операции требуют больше регистров
- **Память:** Для больших batch'ей может потребоваться shared memory

## Следующие шаги

1. ✅ Batch inversion функция реализована
2. ✅ Batch нормализация точек реализована
3. 🔄 **Следующий шаг:** Применить в HD wallet кернелах
4. 🔄 **Следующий шаг:** Применить в public key generation kernel
5. 🔄 **Следующий шаг:** Измерить реальный прирост производительности

## Примеры кода

См. файлы:
- `cuda/secp256k1_v2/secp256k1.cu` - реализация функций
- `cuda/secp256k1_v2/secp256k1.cuh` - объявления функций
