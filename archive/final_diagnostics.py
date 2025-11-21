#!/usr/bin/env python3
"""
ФИНАЛЬНАЯ ДИАГНОСТИКА:
Проверяем все возможные гипотезы одновременно
"""

import csv
import hashlib

ORDER = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

def inv_mod(k, p):
    if k == 0: raise ZeroDivisionError()
    if k < 0: k = p - (-k % p)
    s, old_s = 0, 1
    r, old_r = p, k
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % p

sigs = []
with open('hnp_capture.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        r_hex = row['r_hex']
        s_hex = row['s_hex']
        payload_hex = row['full_payload_hex']
        
        r = int(r_hex, 16)
        s = int(s_hex, 16)
        payload = bytes.fromhex(payload_hex)
        
        sigs.append({'r': r, 's': s, 'payload': payload})

print(f"Загружено {len(sigs)} подписей\n")

# Тест 1: R используется как nonce напрямую
print("="*60)
print("ТЕСТ 1: Checking if k = R (direct)")
print("="*60)
d_values = set()
for i, sig in enumerate(sigs[:50]):
    k = sig['r']
    r = sig['r']
    s = sig['s']
    # Пробуем разные z
    for z_variant in [0, 1, r, s]:
        try:
            r_inv = inv_mod(r, ORDER)
            d = (s * k - z_variant) * r_inv % ORDER
            d_values.add(d)
        except:
            pass

print(f"Уникальных значений d: {len(d_values)}")
if len(d_values) == 1:
    print(f"✓ Найден единственный ключ: {hex(list(d_values)[0])}")
elif len(d_values) < 10:
    print(f"Найдено {len(d_values)} возможных ключей (может быть ротация)")
else:
    print("✗ Слишком много вариантов, гипотеза неверна\n")

# Тест 2: Проверка, что подписи вообще валидны (есть ли связь r,s,z,d)
print("\n" + "="*60)
print("ТЕСТ 2: Signature sanity check")
print("="*60)

# Проверяем, что r и s не выходят за пределы
invalid_count = 0
for sig in sigs:
    if sig['r'] >= ORDER or sig['s'] >= ORDER or sig['r'] == 0 or sig['s'] == 0:
        invalid_count += 1

print(f"Невалидных подписей (r/s вне диапазона): {invalid_count}/{len(sigs)}")

# Тест 3: Проверяем уникальность R (нет ли повторов nonce)
print("\n" + "="*60)
print("ТЕСТ 3: Nonce reuse detection")
print("="*60)
r_values = [sig['r'] for sig in sigs]
unique_r = len(set(r_values))
print(f"Уникальных R: {unique_r}/{len(sigs)}")
if unique_r < len(sigs):
    print(f"✓ Найдены повторы! Можно извлечь ключ!")
    # Ищем повторы
    from collections import Counter
    r_counts = Counter(r_values)
    duplicates = [(r, count) for r, count in r_counts.items() if count > 1]
    print(f"  Количество дубликатов: {len(duplicates)}")
else:
    print("✗ Все R уникальны\n")

# Тест 4: Проверяем, есть ли линейная зависимость s = a*r + b
print("\n" + "="*60)
print("ТЕСТ 4: Linear relationship s = a*r + b")
print("="*60)

if len(sigs) >= 2:
    r1, s1 = sigs[0]['r'], sigs[0]['s']
    r2, s2 = sigs[1]['r'], sigs[1]['s']
    
    # s2 - s1 = a*(r2 - r1)
    try:
        delta_r_inv = inv_mod((r2 - r1) % ORDER, ORDER)
        a = ((s2 - s1) * delta_r_inv) % ORDER
        b = (s1 - a * r1) % ORDER
        
        # Проверяем на остальных
        matches = 0
        for sig in sigs[:20]:
            predicted_s = (a * sig['r'] + b) % ORDER
            if predicted_s == sig['s']:
                matches += 1
        
        print(f"Совпадений с линейной моделью: {matches}/20")
        if matches >= 18:
            print(f"✓ Сильная линейная зависимость!")
            print(f"  a = {hex(a)[:20]}...")
            print(f"  b = {hex(b)[:20]}...")
        else:
            print("✗ Нет линейной зависимости\n")
    except:
        print("✗ Ошибка вычисления\n")

print("\n" + "="*60)
print("ЗАКЛЮЧЕНИЕ")
print("="*60)
print("Если все тесты отрицательны, возможно:")
print("1. Это не стандартный ECDSA")
print("2. Нам нужно найти правильный способ вычисления z")
print("3. Подписи зашифрованы/обфусцированы")
