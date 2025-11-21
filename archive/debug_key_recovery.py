#!/usr/bin/env python3
"""
Детальная отладка восстановления ключа с выводом промежуточных значений
"""

import csv
import hashlib
from ecdsa.curves import NIST192p
from ecdsa import VerifyingKey, NIST192p as curve_module
from collections import Counter

CURVE = NIST192p
ORDER = CURVE.order
G = CURVE.generator

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    """Сворачивает 256-битный хеш в 192 бита"""
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def debug_signature(sig_num, r, s, z):
    """Детальная отладка одной подписи"""
    print(f"\n{'='*60}")
    print(f"Подпись #{sig_num}")
    print(f"{'='*60}")
    print(f"R = {hex(r)}")
    print(f"R длина: {r.bit_length()} бит")
    print(f"S = {hex(s)}")
    print(f"S длина: {s.bit_length()} бит")
    print(f"z = {hex(z)}")
    print(f"z длина: {z.bit_length()} бит")
    
    n = ORDER
    
    # Проверка валидности
    if r == 0 or r >= n:
        print("❌ R выходит за допустимый диапазон!")
        return None
    if s == 0 or s >= n:
        print("❌ S выходит за допустимый диапазон!")
        return None
    
    print("\nПроверка гипотезы: R содержит nonce k")
    
    k = r
    
    # Вычисляем координату точки R = k*G
    try:
        R_point = k * G
        r_coord = R_point.x()
        print(f"Точка R = k*G:")
        print(f"  R.x = {hex(r_coord)}")
        print(f"  R.y = {hex(R_point.y())}")
        
        # Стандартная ECDSA: s = k^-1 * (z + r*d)
        # Преобразуем: k*s = z + r*d
        # d = (k*s - z) * r^-1
        
        k_s = (k * s) % n
        print(f"\nВычисления:")
        print(f"  k*s mod n = {hex(k_s)}")
        print(f"  k*s - z = {hex((k_s - z) % n)}")
        
        r_inv = inverse_mod(r_coord, n)
        print(f"  r^-1 mod n = {hex(r_inv)}")
        
        d = ((k_s - z) * r_inv) % n
        print(f"\n✓ Кандидат приватного ключа:")
        print(f"  d = {hex(d)}")
        
        # Верификация: вычисляем публичный ключ
        Pub = d * G
        print(f"\nПубличный ключ (если d верен):")
        print(f"  Pub.x = {hex(Pub.x())}")
        print(f"  Pub.y = {hex(Pub.y())}")
        
        # Проверка уравнения подписи
        # s*k = z + r*d (mod n)
        left = (s * k) % n
        right = (z + r_coord * d) % n
        
        print(f"\nПроверка уравнения s*k = z + r*d:")
        print(f"  Левая часть  (s*k):     {hex(left)}")
        print(f"  Правая часть (z + r*d): {hex(right)}")
        print(f"  Совпадение: {left == right}")
        
        return d
        
    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return None

def main():
    print("Детальная отладка восстановления ключа")
    print("="*60)
    
    # Читаем подписи
    sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            if len(payload) < 108:
                continue
            
            # Извлекаем компоненты
            sha256_part = payload[4:36]
            session_id = payload[36:60]
            
            # Формируем сообщение для подписи
            msg_to_sign = sha256_part + session_id
            
           # Хешируем и сворачиваем
            z_hash = hashlib.sha256(msg_to_sign).digest()
            z_folded = fold_sha256_to_192(z_hash)
            z = int.from_bytes(z_folded, 'big')
            
            sigs.append({'r': r, 's': s, 'z': z, 'sha256': sha256_part.hex(), 'session': session_id.hex()})
    
    print(f"\nОбработано подписей: {len(sigs)}")
    
    # Детальный анализ первых 3 подписей
    candidates = []
    for i in range(min(3, len(sigs))):
        d = debug_signature(i, sigs[i]['r'], sigs[i]['s'], sigs[i]['z'])
        if d is not None:
            candidates.append(d)
    
    # Проверка консистентности
    print(f"\n{'='*60}")
    print("ИТОГОВЫЙ АНАЛИЗ")
    print(f"{'='*60}")
    
    if len(candidates) >= 2:
        if len(set(candidates)) == 1:
            print(f"✓ ВСЕ КАНДИДАТЫ СОВПАДАЮТ!")
            print(f"Приватный ключ: {hex(candidates[0])}")
        else:
            print(f"❌ Кандидаты различны:")
            for i, d in enumerate(candidates):
                print(f"  #{i}: {hex(d)}")
            
            # Проверяем, может разница небольшая
            diffs = []
            for i in range(len(candidates)-1):
                diff = abs(candidates[i] - candidates[i+1])
                diffs.append(diff)
                print(f"\nРазница #{i} и #{i+1}: {hex(diff)}")

if __name__ == "__main__":
    main()
