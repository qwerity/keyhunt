#!/usr/bin/env python3
"""
Преобразует значения из GPU (publicRFirst5) в формат для hash160Targets файла
"""

def swap32(value):
    """SWAP32: меняет порядок байтов внутри слова"""
    return ((value & 0x000000FF) << 24) | \
           ((value & 0x0000FF00) << 8) | \
           ((value & 0x00FF0000) >> 8) | \
           ((value & 0xFF000000) >> 24)


def main():
    # Значения из GPU (publicRFirst5[0..4])
    gpu_values = [0x28be01f5, 0x419a2de8, 0xcbff4aa8, 0x946eeb19, 0xe95a2535]
    
    print("=== GPU values (publicRFirst5[0..4]) ===")
    for i, val in enumerate(gpu_values):
        print(f"  GPU[{i}] = 0x{val:08x}")
    print()
    
    # Применяем SWAP32 к каждому слову
    swapped = [swap32(val) for val in gpu_values]
    
    print("=== After SWAP32 (format for file) ===")
    for i, val in enumerate(swapped):
        print(f"  swapped[{i}] = 0x{val:08x}")
    print()
    
    # Преобразуем в hex строку (40 символов)
    hex_result = ''.join(f'{val:08x}' for val in swapped)
    
    print("=== For hash160Targets file ===")
    print("Add this line to your hash160Targets file:")
    print(hex_result)
    print()
    
    # Проверка
    print("=== Verification ===")
    print("After hexToHash160 reads from file and SWAP32_HASH160 in CUDA:")
    for i in range(5):
        after_swap = swap32(swapped[i])
        match = "MATCH" if after_swap == gpu_values[i] else "MISMATCH"
        print(f"  d_TargetHash[0][{i}] = 0x{after_swap:08x} | GPU[{i}]: 0x{gpu_values[i]:08x} [{match}]")


if __name__ == "__main__":
    main()
