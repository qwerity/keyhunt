#!/usr/bin/env python3
"""
Преобразует hex строку x-координаты mod N в формат для targets файла
Показывает все шаги преобразования
"""

def swap32(value):
    """SWAP32: меняет порядок байтов внутри слова (big-endian <-> little-endian)"""
    return ((value & 0x000000FF) << 24) | \
           ((value & 0x0000FF00) << 8) | \
           ((value & 0x00FF0000) >> 8) | \
           ((value & 0xFF000000) >> 24)


def hex_to_uint256_words(hex_str):
    """
    Преобразует hex строку в формат uint256_t (как bytesToUint256 в CUDA)
    """
    # Убираем префикс 0x если есть
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    
    # Дополняем до 64 символов (32 байта)
    hex_str = hex_str.zfill(64)
    
    # Преобразуем hex строку в байты
    bytes_array = bytes.fromhex(hex_str)
    
    # Преобразуем байты в uint256_t формат
    # src[0..3] -> v[7], src[4..7] -> v[6], ..., src[28..31] -> v[0]
    v = [0] * 8
    for i in range(8):
        byte_idx = 7 - i  # Обратный порядок
        v[i] = (bytes_array[byte_idx * 4 + 0] << 24) | \
               (bytes_array[byte_idx * 4 + 1] << 16) | \
               (bytes_array[byte_idx * 4 + 2] << 8) | \
               (bytes_array[byte_idx * 4 + 3])
    
    return v


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python hex_to_hash160targets.py <hex_string>")
        print("Example: python hex_to_hash160targets.py 5f49b77aba1ec7591a48395be95a2535946eeb19cbff4aa8419a2de828be01f5")
        sys.exit(1)
    
    hex_key = sys.argv[1]
    
    print("=" * 70)
    print("STEP 1: Input hex string")
    print("=" * 70)
    print(f"Hex key: {hex_key}")
    print(f"Length: {len(hex_key)} characters ({len(hex_key) // 2} bytes)")
    print()
    
    # Шаг 2: Преобразуем в uint256_t формат
    print("=" * 70)
    print("STEP 2: Convert to uint256_t format (as bytesToUint256)")
    print("=" * 70)
    v = hex_to_uint256_words(hex_key)
    print("uint256_t representation (v[0..7]):")
    for i in range(8):
        print(f"  v[{i}] = 0x{v[i]:08x}")
    print()
    
    # Шаг 3: Берем первые 5 слов (publicRFirst5)
    print("=" * 70)
    print("STEP 3: Take first 5 words (publicRFirst5[0..4] = v[0..4])")
    print("=" * 70)
    first5 = v[0:5]
    for i, val in enumerate(first5):
        print(f"  publicRFirst5[{i}] = v[{i}] = 0x{val:08x}")
    print()
    print("These are the values used in checkHash() in CUDA kernel")
    print()
    
    # Шаг 4: Применяем SWAP32 для получения формата файла
    print("=" * 70)
    print("STEP 4: Apply SWAP32 to each word (for file format)")
    print("=" * 70)
    print("Why? Because in CUDA, SWAP32_HASH160 is applied when loading targets")
    print()
    swapped = [swap32(val) for val in first5]
    for i, (original, swapped_val) in enumerate(zip(first5, swapped)):
        print(f"  publicRFirst5[{i}] = 0x{original:08x} -> SWAP32 -> 0x{swapped_val:08x}")
    print()
    
    # Шаг 5: Преобразуем в hex строку для файла
    print("=" * 70)
    print("STEP 5: Convert to hex string for hash160Targets file")
    print("=" * 70)
    hex_result = ''.join(f'{val:08x}' for val in swapped)
    print(f"Result: {hex_result}")
    print(f"Length: {len(hex_result)} characters (20 bytes)")
    print()
    
    # Шаг 6: Проверка
    print("=" * 70)
    print("STEP 6: Verification")
    print("=" * 70)
    print("After loading from file and SWAP32_HASH160 in CUDA:")
    all_match = True
    for i in range(5):
        after_swap = swap32(swapped[i])
        match = after_swap == first5[i]
        status = "MATCH" if match else "MISMATCH"
        print(f"  File value[{i}] -> SWAP32 -> 0x{after_swap:08x} | Expected: 0x{first5[i]:08x} [{status}]")
        if not match:
            all_match = False
    print()
    
    if all_match:
        print("SUCCESS: All values will match in CUDA kernel!")
    else:
        print("ERROR: Values won't match!")
    print()
    
    # Финальный результат
    print("=" * 70)
    print("FINAL RESULT: Add this line to your hash160Targets file")
    print("=" * 70)
    print(hex_result)
    print()


if __name__ == "__main__":
    main()
