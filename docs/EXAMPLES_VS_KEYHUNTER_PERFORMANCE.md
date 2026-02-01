# Почему examples быстрее key_hunter в ~2 раза

## Главная причина: арифметика поля (field arithmetic)

**Examples** считают точку на кривой в поле из **4 × uint64_t** (4 лимба по 64 бита). Одно умножение в поле = 4×4 = **16** 64-битных умножений + переносы, через PTX (`UMULLO`, `UMULHI`, `UADDO`, `UADDC`).

**Твой проект** использует **secp256k1_fe** = **10 × uint32_t** (10 лимбов по 26 бит, формат libsecp256k1). Одно умножение в поле = 10×10 = **100** 32-битных произведений + сдвиги/маски/нормализации (`secp256k1_fe_mul_inner`, `secp256k1_fe_sqr_inner`).

- Одна операция в поле в examples: **16** 64-битных mul.
- Одна операция в поле в проекте: **~100** 32-битных mul + нормализации.

Алгоритм один и тот же: GTable, 16 чанков по 16 бит, смешанное сложение Jacobian+Affine (8M+3S), batch-инверсия. Но **каждое полевое умножение/квадрат у тебя в 5–6 раз тяжелее**. Отсюда и ~2× по времени: почти всё время в `secp256k1_fe_mul` / `secp256k1_fe_sqr` внутри `secp256k1_gej_add_ge` и batch-нормализации.

**Чтобы реально приблизиться к скорости examples:** заменить secp256k1_fe/secp256k1_gej на **4-лимбовую арифметику** как в examples: координаты = `uint64_t[4]`, GTable в таком формате, сложение точек и batch Jacobian→Affine через `_ModMult` / `_PointAddMixedAffine` / `_BatchJacobianToAffine` из examples (GPUMath.h, GPUSecp.cu). Это большое изменение: другой формат GTable, другой ecmult_gen, конвертеры в байты для hash.

**Реализовано (4-limb путь):** В проекте добавлен путь на 4-лимбовой арифметике: `cuda/ec_4limb_math.cuh` (порт из examples/GPUMath.h), конвертация GTable из secp256k1_ge_storage в 4×uint64_t при загрузке/генерации, fused kernel переведён на 4-limb (приватный ключ → 16-битные чанки → PointMulti Jacobian → BatchJacobianToAffine → uint256_t → hash → check). Ожидается приближение к скорости examples за счёт меньшей стоимости полевых операций.

---

## Дополнительно: kernel fusion и память

В examples один слитый kernel (публичные ключи в global не пишутся). В key_hunter два kernel'а — лишний трафик. Это даёт дополнительный выигрыш у examples, но **основной выигрыш — от 4-лимбовой арифметики**, не от fusion.

## Краткий ответ (устаревший — см. выше)

В **examples** (GPUSecp Phase 2) один **слитый (fused) kernel** делает всё в регистрах и не пишет публичные ключи в глобальную память. В **key_hunter** два отдельных kernel’а: первый пишет все публичные ключи в global memory, второй их читает — это даёт большой объём лишнего трафика по шине и задержки между запусками.

## Сравнение архитектуры

### key_hunter (текущий проект)

1. **Два kernel’а на итерацию:**
   - `publicKeyGenerationKernel`: по приватным ключам считает публичные в Jacobian → batch Jacobian→Affine → **записывает X,Y в `d_publicKeysX`, `d_publicKeysY`** (64 байта на ключ).
   - `checkHashKernel`: **читает** X,Y из global memory → SHA256+RIPEMD160 → проверка по целям → при совпадении пишет в atomic list.

2. **Трафик памяти на одну итерацию (пример):**
   - Запись: `N_keys × 64` байт (X + Y).
   - Чтение: те же `N_keys × 64` байт в `checkHashKernel`.
   - Итого: **2 × N × 64** байт только на публичные ключи.

3. **Два запуска kernel’ов** → два прохода по данным, синхронизация между ними, возможные простои GPU.

### examples (GPUSecp Phase 2)

1. **Один слитый kernel** (`CudaKernelPhase2_Fused`):
   - Для каждого батча точек **в регистрах**: генерация ключей (SHA256 books/combo) → умножение точки в Jacobian (GTable, Mixed Jacobian–Affine) → **batch Jacobian→Affine (Montgomery)** → hash → проверка по отсортированному буферу (binary search) → **запись в global только при совпадении**.

2. **Трафик памяти:**
   - Публичные ключи в global **никогда не пишутся** (кроме результата при совпадении).
   - Читаются: GTable, входные данные, буфер хешей; пишутся только счётчики/результаты при match.

3. **Один запуск** → меньше накладных расходов и лучше утилизация GPU.

## Откуда берётся ускорение (~2×)

| Фактор | key_hunter | examples | Эффект |
|--------|------------|----------|--------|
| **Арифметика поля** | 10×uint32_t (secp256k1_fe), ~100 mul на одно полевое mul | 4×uint64_t, 16 mul + PTX | **~5–6× меньше работы — основная причина ~2×** |
| Количество kernel’ов | 2 | 1 | Меньше запусков и синхронизаций |
| Запись публичных ключей в global | Да, все ключи | Нет | Сильное снижение записи/чтения |
| Чтение публичных ключей из global | Да, все ключи | Нет | То же |
| Batch Jacobian→Affine | Есть (`secp256k1_ge_set_gej_batch`) | Есть (Montgomery) | Оба уже оптимизированы |
| Mixed Jacobian–Affine в сложении | Есть (`secp256k1_gej_add_ge`) | Есть | Оба уже оптимизированы |

**Главный выигрыш** — **4-лимбовая полевая арифметика** в examples (каждое полевое mul/sqr в разы дешевле). Второстепенный — один kernel и отсутствие записи публичных ключей в global.

## Что перенести в key_hunter

1. **Слияние двух kernel’ов в один (fused kernel)**  
   В одном kernel’е для каждого батча точек в потоке:
   - вычислить публичные ключи в Jacobian (как сейчас в `publicKeyGenerationKernel`);
   - сделать batch Jacobian→Affine в регистрах (как сейчас `secp256k1_ge_set_gej_batch`);
   - сразу по нормализованным (x,y) посчитать hash и вызвать `checkHash` / `setResultFound`;
   - **не писать** X,Y в `d_publicKeysX`/`d_publicKeysY` для основного пути поиска.

2. **Не трогать (уже хорошо):**
   - batch inversion в `secp256k1_ge_set_gej_batch` и mixed Jacobian–Affine в `secp256k1_gej_add_ge`;
   - текущую модель данных (приватные ключи, GTable, hash160 lookup/bloom/constant).

3. **Опционально для будущего:**
   - Если понадобится ещё выигрыш, можно смотреть на формат GTable и арифметику из examples (uint64_t[4], PTX, другой layout), но это уже большое изменение; сначала достаточно fusion.

## Итог

- **Почему examples быстрее в ~2 раза:** в examples поле кривой считается как 4×uint64_t (16 64-битных mul на одно полевое умножение), в проекте — secp256k1_fe = 10×uint32_t (~100 32-битных mul + нормализации). Каждое полевое mul/sqr в проекте в 5–6 раз тяжелее.
- **Как приблизиться к скорости examples:** заменить secp256k1_fe/secp256k1_gej на 4-лимбовую арифметику из examples (GPUMath.h, GPUSecp.cu): координаты uint64_t[4], GTable в таком формате, _ModMult/_PointAddMixedAffine/_BatchJacobianToAffine. Это большое изменение (формат GTable, ecmult_gen, конвертеры в байты для hash).kernel’ов; 
---

## Почему fused kernel изначально был не быстрее (или чуть медленнее)

1. **Occupancy считался под другой kernel.** В `init()` вызывался `cudaOccupancyMaxPotentialBlockSize(..., publicKeyGenerationKernel)` (55 регистров), а запускался fused kernel с **121 регистрами** → на SM помещалось ~2 блока вместо ~4, occupancy падал, проигрыш по скорости перекрывал выигрыш от отсутствия записи публичных ключей.

2. **Слишком много регистров в одном kernel.** Fused kernel инлайнил весь код hash+check → 121 регистр на поток.

**Что сделано:**

- **Occupancy для fused kernel:** в `computeResolutionForMaxOccupancy()` теперь используется `publicKeyAndCheckHash160FusedKernel` → подбираются block/grid под тот kernel, который реально запускается (меньший block, больше блоков при необходимости).
- **Снижение регистров:** логика hash+check вынесена в `__device__ __noinline__ void fusedHashAndCheck(...)` → fused kernel использует **42 регистра** вместо 121, occupancy снова нормальный.

После этих правок fused путь должен показывать прирост (или как минимум не проигрывать) по сравнению с двумя kernel'ами.

---

## Дополнительные оптимизации (после 4-limb)

Уже внедрено:
- **L1 cache:** `cudaDeviceSetCacheConfig(cudaFuncCachePreferL1)` в ECC init — выгодно при случайном доступе к GTable.
- **Стек:** `cudaDeviceSetLimit(cudaLimitStackSize, 32768)` — запас под глубокие фреймы kernel.
- **__ldg()** при чтении GTable в `ec4limb_PointMultiJacobianFast` — использование read-only cache.
- **Batch size 32** в fused kernel — меньше вызовов BatchJacobianToAffine (вдвое при том же pointsPerThread).

- **Hash (сделано):** в fused kernel используется device hash из examples: `cuda/gpu_hash160.cuh` — SHA256+RIPEMD160 с __byte_perm для сборки байт публичного ключа и макро-unroll (SHA256_RND, WMIX, RIPEMD160 R11–R52). Вызовы `gpuHash160Comp` / `gpuHash160Uncomp` вместо `sha256PublicKeyCompressed` + `ripemd160sha256`.

Идеи на будущее:
- **Prefetch:** асинхронная подгрузка следующей точки GTable во время вычислений текущей (сложнее, выигрыш не гарантирован).
- **Batch 64:** попробовать, если регистров хватает (риск: падение occupancy).
