#!/usr/bin/env python3
"""
КРИТИЧЕСКАЯ ПРОВЕРКА: Chip ID и криптография

Гипотезы:
1. d (приватный ключ) = H(Chip_ID || Master_Secret)
2. k (nonce) детерминистический = H(Chip_ID || Counter || Message)
3. k имеет bias, зависящий от Chip_ID
"""

import hashlib
import struct
import csv

ORDER = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

def inverse_mod(a, m):
    return pow(a, -1, m)

# Chip ID из лога
CHIP_ID = bytes.fromhex('0000e095650f2a54')

print("="*60)
print("АНАЛИЗ СВЯЗИ CHIP ID С КРИПТОГРАФИЕЙ")
print("="*60)
print(f"\nChip ID: {CHIP_ID.hex()}")
print(f"Chip ID (uint64 BE): {int.from_bytes(CHIP_ID, 'big')}")
print(f"Chip ID (uint64 LE): {int.from_bytes(CHIP_ID, 'little')}\n")

# Загружаем подписи
signatures = []
with open('hnp_capture.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        r = int(row['r_hex'], 16)
        s = int(row['s_hex'], 16)
        signatures.append({'r': r, 's': s})

print(f"Загружено {len(signatures)} подписей\n")

# Гипотеза 1: Приватный ключ зависит от Chip ID
print("="*60)
print("ГИПОТЕЗА 1: d = H(Chip_ID)")
print("="*60)

# Пробуем разные хеш-функции и форматы
for hash_func_name, hash_func in [('SHA256', hashlib.sha256), ('SHA1', hashlib.sha1)]:
    for endian in ['big', 'little']:
        # Хешируем Chip ID
        h = hash_func(CHIP_ID).digest()
        
        # Берем первые 24 байта (192 бита)
        d_candidate = int.from_bytes(h[:24], endian) % ORDER
        
        if d_candidate == 0:
            continue
        
        # Проверяем на первой подписи
        sig = signatures[0]
        # k = (s^-1) * (z + r*d) mod n
        # Но мы не знаем z... Пробуем с z=0
        
        s_inv = inverse_mod(sig['s'], ORDER)
        k_calc = (s_inv * sig['r'] * d_candidate) % ORDER
        
        # Проверяем разумность k
        if k_calc.bit_length() <= 192:
            print(f"  {hash_func_name} ({endian}): d={hex(d_candidate)[:30]}... k_bits={k_calc.bit_length()}")

# Гипотеза 2: Nonce k зависит от Chip ID + Counter
print(f"\n{'='*60}")
print("ГИПОТЕЗА 2: k = H(Chip_ID || Counter)")
print("="*60)

# Пробуем для первых нескольких подписей
for idx in range(min(5, len(signatures))):
    sig = signatures[idx]
    
    # Counter = packet_idx или просто idx
    for counter_val in [idx, idx+1]:
        counter_bytes = counter_val.to_bytes(8, 'big')
        
        # k = H(Chip_ID || Counter)
        h = hashlib.sha256(CHIP_ID + counter_bytes).digest()
        k_candidate = int.from_bytes(h[:24], 'big') % ORDER
        
        if k_candidate == 0:
            continue
        
        # r должно быть = (k*G).x, но мы не можем этого проверить без библиотеки EC
        # Вместо этого проверим: если R field == k (наивная гипотеза)
        if k_candidate == sig['r']:
            print(f"  ✓ Sig {idx}: R == H(Chip_ID || {counter_val})!")
            print(f"    k = {hex(k_candidate)[:40]}...")

# Гипотеза 3: k имеет структуру, зависящую от Ch ip ID
print(f"\n{'='*60}")
print("ГИПОТЕЗА 3: k = Chip_ID ⊕ Random или k[MSB] = Chip_ID[LSB]")
print("="*60)

# Проверяем, есть ли корреляция между битами R и Chip ID
chip_id_int = int.from_bytes(CHIP_ID, 'big')

correlations = 0
for sig in signatures[:20]:
    # XOR
    xor_result = sig['r'] ^ chip_id_int
    
    # Если XOR дает "случайное" число, то нет корреляции
    # Если XOR дает число с особой структурой (много нулей/единиц), то есть
    
    xor_bits = bin(xor_result)[2:]
    ones_count = xor_bits.count('1')
    zeros_count = xor_bits.count('0')
    
    # Ожидаемое соотношение ~50/50
    if abs(ones_count - zeros_count) > 30:  # Значительное отклонение
        correlations += 1

if correlations > 5:
    print(f"  ✓ Обнаружена корреляция в {correlations}/20 подписях!")
else:
    print(f"  ✗ Корреляция не обнаружена ({correlations}/20)")

# Гипотеза 4: Последние биты R зависят от Chip ID
print(f"\n{'='*60}")
print("ГИПОТЕЗА 4: R[LSB] содержит части Chip_ID")
print("="*60)

# Маски для проверки
chip_id_masks = [
    (0xFF, "last byte"),
    (0xFFFF, "last 2 bytes"),
    (0xFFFFFFFF, "last 4 bytes"),
]

for mask, desc in chip_id_masks:
    chip_id_masked = chip_id_int & mask
    matches = 0
    
    for sig in signatures[:50]:
        r_masked = sig['r'] & mask
        if r_masked == chip_id_masked:
            matches += 1
    
    if matches > 2:  # Больше чем случайность
        print(f"  {desc}: {matches}/50 совпадений (chip_id & mask = 0x{chip_id_masked:X})")

print(f"\n{'='*60}")
print("ВЫВОДЫ")
print("="*60)
print("Если ни одна гипотеза не подтвердилась:")
print("- Chip ID используется только как идентификатор")
print("- Приватный ключ и nonce НЕ зависят напрямую от Chip ID")
print("- u-blox использует независимый криптографически стойкий RNG")
