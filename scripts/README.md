# Скрипты для работы с hash160Targets

## Python скрипты

### 1. `r_to_hex.py` - Конвертация числа R в hex
Преобразует десятичное число R (x-координата публичного ключа) в hex формат.

**Использование:**
```bash
python scripts/r_to_hex.py <decimal_number>
```

**Пример:**
```bash
python scripts/r_to_hex.py 43099966779434832891585375040423837271149972391332301589724116920548743578101
```

---

### 2. `hex_to_hash160targets.py` - Полное преобразование hex в формат для hash160Targets
Показывает все шаги преобразования hex строки x-координаты в формат для файла hash160Targets.

**Использование:**
```bash
python scripts/hex_to_hash160targets.py <hex_string>
```

**Пример:**
```bash
python scripts/hex_to_hash160targets.py 5f49b77aba1ec7591a48395be95a2535946eeb19cbff4aa8419a2de828be01f5
```

**Что делает:**
1. Преобразует hex строку в uint256_t формат
2. Берет первые 5 слов (publicRFirst5[0..4])
3. Применяет SWAP32 к каждому слову
4. Выводит готовую hex строку для файла hash160Targets

---

### 3. `gpu_to_file_format.py` - Преобразование значений из GPU в формат файла
Преобразует значения publicRFirst5 из CUDA debug вывода в формат для hash160Targets файла.

**Использование:**
```bash
python scripts/gpu_to_file_format.py
```

Или отредактируйте скрипт, чтобы указать свои значения GPU.

**Пример вывода:**
```
f501be28e82d9a41a84affcb19eb6e9435255ae9
```

---

### 4. `convert_debug_hash_to_file` (C++ утилита)
Преобразует значения hash[5] из CUDA debug вывода в формат для hash160Targets файла.

**Использование:**
```bash
./convert_debug_hash_to_file 0x28be01f5 0x419a2de8 0xcbff4aa8 0x946eeb19 0xe95a2535
```

---

## Формат файла hash160Targets

Файл должен содержать hex строки по 40 символов (20 байт), одна строка на hash160.

**Пример:**
```
f501be28e82d9a41a84affcb19eb6e9435255ae9
65c49a515584681366cdbac2ccfb985f4be1427a
```

**Важно:**
- Каждая строка должна быть ровно 40 hex символов
- Без префиксов (0x)
- Без разделителей
- Пустые строки игнорируются

---

## Полный workflow

1. **Если у вас есть десятичное число R:**
   ```bash
   python scripts/r_to_hex.py <decimal_R>
   python scripts/hex_to_hash160targets.py <полученный_hex>
   ```

2. **Если у вас есть hex строка x-координаты:**
   ```bash
   python scripts/hex_to_hash160targets.py <hex_string>
   ```

3. **Если у вас есть значения из CUDA debug вывода:**
   ```bash
   python scripts/gpu_to_file_format.py
   # или отредактируйте значения в скрипте
   ```

4. **Добавьте полученную hex строку в файл hash160Targets**
