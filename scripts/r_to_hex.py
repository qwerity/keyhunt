#!/usr/bin/env python3
"""
Конвертирует число R (x-координата публичного ключа / N) в hex формат
"""

def r_to_hex(r_decimal):
    """
    Преобразует десятичное число R в hex строку
    
    Args:
        r_decimal: число в десятичной системе (int или str)
    
    Returns:
        hex строка (без префикса 0x)
    """
    # Преобразуем в int если это строка
    if isinstance(r_decimal, str):
        r_decimal = int(r_decimal)
    
    # Преобразуем в hex
    hex_str = hex(r_decimal)[2:]  # Убираем префикс '0x'
    
    # Дополняем нулями слева до 64 символов (32 байта = 256 бит)
    hex_str = hex_str.zfill(64)
    
    return hex_str


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python r_to_hex.py <decimal_number>")
        print("Example: python r_to_hex.py 43099966779434832891585375040423837271149972391332301589724116920548743578101")
        sys.exit(1)
    
    r_decimal = sys.argv[1]
    
    try:
        hex_result = r_to_hex(r_decimal)
        
        print(f"Input (decimal): {r_decimal}")
        print(f"Output (hex, 64 chars): {hex_result}")
        print(f"Length: {len(hex_result)} characters ({len(hex_result) // 2} bytes)")
        print()
        print("=== For use in convert_x_to_hash160_format ===")
        print(f"Run: ./convert_x_to_hash160_format {hex_result}")
        
    except ValueError as e:
        print(f"Error: Invalid number format: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
