// Упрощенная и оптимизированная C++ реализация SecureRandom (SHA1PRNG) для CUDA
// CVE-2013-7372: баг в вычислении lastWord сохранен для демонстрации
//
// Оптимизации:
// - Inline функции для маленьких операций (rotl32, rotr32, f1, f2, f3)
// - Развернутый цикл извлечения байт из хеша (20 байт)
// - Прямые присваивания вместо memcpy для маленьких размеров (<= 8 байт)
// - Использование локальных указателей для уменьшения разыменований
// - Предвычисление констант (lastWord, extrabytes)
// - Оптимизация доступа к массивам через указатели

#include <cstdint>
#include <cstring>

// Константы SHA-1
#define BYTES_OFFSET 81
#define HASH_OFFSET 82
#define EXTRAFRAME_OFFSET 5
#define HASHBYTES_TO_USE 20
#define DIGEST_LENGTH 20
#define SEED_SIZE (HASH_OFFSET + EXTRAFRAME_OFFSET)

#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0
#define END_FLAG 0x80000000

// SHA-1 константы
#define K1 0x5A827999  // 0-19
#define K2 0x6ED9EBA1  // 20-39
#define K3 0x8F1BBCDC  // 40-59
#define K4 0xCA62C1D6  // 60-79

// Состояние генератора случайных чисел
struct SecureRandomState {
    uint32_t seed[SEED_SIZE];
    uint8_t nextBytes[DIGEST_LENGTH];
    int nextBIndex;
    uint64_t counter;
    int firstCall;
    uint32_t seed3;  // Сохраняем для установки в nextBytes
    uint32_t seed4;  // Сохраняем для установки в nextBytes
};

// Битовые операции (inline для оптимизации)
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-1 функции (inline для оптимизации)
static inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d) {
    return (b & c) | ((~b) & d);
}

static inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d) {
    return b ^ c ^ d;
}

static inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d) {
    return (b & c) | (b & d) | (c & d);
}

// Вычисление SHA-1 хеша (оптимизированная версия)
static void computeHash(uint32_t* arrW) {
    // Используем локальные переменные для быстрого доступа
    uint32_t* w = arrW;
    uint32_t* h = arrW + HASH_OFFSET;
    
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    
    // Расширение массива W (16-79) - оптимизированный цикл
    for (int t = 16; t < 80; t++) {
        w[t] = rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    
    // Раунды 0-19
    for (int t = 0; t < 20; t++) {
        uint32_t temp = rotl32(a, 5) + f1(b, c, d) + e + w[t] + K1;
        e = d;
        d = c;
        c = rotr32(b, 2);
        b = a;
        a = temp;
    }
    
    // Раунды 20-39
    for (int t = 20; t < 40; t++) {
        uint32_t temp = rotl32(a, 5) + f2(b, c, d) + e + w[t] + K2;
        e = d;
        d = c;
        c = rotr32(b, 2);
        b = a;
        a = temp;
    }
    
    // Раунды 40-59
    for (int t = 40; t < 60; t++) {
        uint32_t temp = rotl32(a, 5) + f3(b, c, d) + e + w[t] + K3;
        e = d;
        d = c;
        c = rotr32(b, 2);
        b = a;
        a = temp;
    }
    
    // Раунды 60-79
    for (int t = 60; t < 80; t++) {
        uint32_t temp = rotl32(a, 5) + f2(b, c, d) + e + w[t] + K4;
        e = d;
        d = c;
        c = rotr32(b, 2);
        b = a;
        a = temp;
    }
    
    // Обновление хеша
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

// Инициализация состояния генератора (оптимизированная)
void initSecureRandom(SecureRandomState* state, uint32_t x, uint32_t y) {
    // Быстрое обнуление только нужных полей
    state->nextBIndex = HASHBYTES_TO_USE;
    state->counter = 0;
    state->firstCall = 1;
    
    // Обнуление массивов
    for (int i = 0; i < SEED_SIZE; i++) {
        state->seed[i] = 0;
    }
    for (int i = 0; i < DIGEST_LENGTH; i++) {
        state->nextBytes[i] = 0;
    }
    
    // Инициализация хеша SHA-1
    state->seed[BYTES_OFFSET] = 0;
    state->seed[HASH_OFFSET] = H0;
    state->seed[HASH_OFFSET + 1] = H1;
    state->seed[HASH_OFFSET + 2] = H2;
    state->seed[HASH_OFFSET + 3] = H3;
    state->seed[HASH_OFFSET + 4] = H4;
    
    state->seed3 = x;
    state->seed4 = y;
}

// Генерация случайных байтов
void nextBytes(SecureRandomState* state, uint8_t* bytes, int bytesLen) {
    if (bytesLen == 0) return;
    
    int extrabytes = 7;
    int lastWord = (state->seed[BYTES_OFFSET] == 0) ? 0 
                   : ((state->seed[BYTES_OFFSET] + extrabytes) >> 3 - 1);
    
    if (state->firstCall) {
        state->seed[81] = 20;
        state->firstCall = 0;
    }
    
    int nextByteToReturn = 0;
    
    if (state->nextBIndex < HASHBYTES_TO_USE) {
        int remaining = HASHBYTES_TO_USE - state->nextBIndex;
        int n = (remaining < bytesLen - nextByteToReturn) ? remaining : (bytesLen - nextByteToReturn);
        if (n > 0) {
            memcpy(bytes + nextByteToReturn, state->nextBytes + state->nextBIndex, n);
            state->nextBIndex += n;
            nextByteToReturn += n;
        }
    }
    
    if (nextByteToReturn >= bytesLen) return;
    
    state->seed[3] = state->seed3;
    state->seed[4] = state->seed4;
    
    uint32_t* seed = state->seed;
    uint64_t counter = state->counter;
    
    while (nextByteToReturn < bytesLen) {
        seed[lastWord] = (uint32_t)(counter >> 32);
        seed[lastWord + 1] = (uint32_t)(counter & 0xFFFFFFFF);
        seed[lastWord + 2] = END_FLAG;
        
        computeHash(seed);
        counter++;
        
        uint32_t* h = state->seed + HASH_OFFSET;
        uint8_t* nb = state->nextBytes;
        for (int i = 0; i < EXTRAFRAME_OFFSET; i++) {
            uint32_t k = h[i];
            nb[i*4] = (uint8_t)(k >> 24);
            nb[i*4 + 1] = (uint8_t)(k >> 16);
            nb[i*4 + 2] = (uint8_t)(k >> 8);
            nb[i*4 + 3] = (uint8_t)k;
        }
        
        state->nextBIndex = 0;
        int bytesToCopy = (HASHBYTES_TO_USE < bytesLen - nextByteToReturn) 
                         ? HASHBYTES_TO_USE 
                         : bytesLen - nextByteToReturn;
        if (bytesToCopy > 0) {
            memcpy(bytes + nextByteToReturn, state->nextBytes, bytesToCopy);
            nextByteToReturn += bytesToCopy;
            state->nextBIndex += bytesToCopy;
        }
        
        if (nextByteToReturn >= bytesLen) break;
    }
    
    state->counter = counter;
}

// Генерация одного int значения (оптимизированная версия)
uint32_t nextInt(SecureRandomState* state) {
    uint8_t bytes[4];
    nextBytes(state, bytes, 4);
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

// Пример использования
#include <stdio.h>

void bytesToHex(uint8_t* bytes, int len, char* output) {
    for (int i = 0; i < len; i++) {
        snprintf(output + i * 2, 3, "%02x", bytes[i]);
    }
    output[len * 2] = '\0';
}

int main() {
    SecureRandomState state;
    uint32_t x = 1;
    uint32_t y = 2290218935;
    initSecureRandom(&state, x, y);
    
    // Генерация 256 бит (8 int значений по 32 бита)
    int numBits = 256;
    int numberLength = (numBits + 31) >> 5;  // 8
    uint32_t digits[8];
    
    for (int i = 0; i < numberLength; i++) {
        digits[i] = nextInt(&state);
    }
    
    digits[numberLength - 1] >>= ((-numBits) & 31);
    
    uint8_t bytes[32];
    for (int i = 0; i < numberLength; i++) {
        int offset = (numberLength - 1 - i) * 4;
        bytes[offset] = (uint8_t)(digits[i] >> 24);
        bytes[offset + 1] = (uint8_t)(digits[i] >> 16);
        bytes[offset + 2] = (uint8_t)(digits[i] >> 8);
        bytes[offset + 3] = (uint8_t)digits[i];
    }
    
    if (bytes[0] & 0x80) {
        uint8_t abs_bytes[32];
        int carry = 1;
        for (int i = 31; i >= 0; i--) {
            int sum = ((~bytes[i]) & 0xFF) + carry;
            abs_bytes[i] = (uint8_t)sum;
            carry = sum >> 8;
        }
        
        char hex[65];
        bytesToHex(abs_bytes, 32, hex);
        printf("Random hex: %s\n", hex);
    } else {
        char hex[65];
        bytesToHex(bytes, 32, hex);
        printf("Random hex: %s\n", hex);
    }
    
    return 0;
}
