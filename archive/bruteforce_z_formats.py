#!/usr/bin/env python3
"""
Полный перебор вариантов формирования z для поиска единого приватного ключа
"""

import csv
import hashlib
from ecdsa.curves import NIST192p
from collections import Counter

CURVE = NIST192p
ORDER = CURVE.order
G = CURVE.generator

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def try_z_variant(sigs_data, z_calculator, variant_name):
    """
    Пытается восстановить ключ с данным способом вычисления z
    Возвращает (unique_keys_count, most_common_key, count) если успешно
    """
    keys = []
    
    for sig in sigs_data:
        r, s, payload = sig['r'], sig['s'], sig['payload']
        
        # Вычисляем z по заданному методу
        try:
            z = z_calculator(payload)
            if z is None:
                continue
        except Exception:
            continue
        
        # Восстанавливаем d
        k = r
        if k == 0 or k >= ORDER:
            continue
            
        try:
            R_point = k * G
            r_coord = R_point.x()
            
            k_s = (k * s) % ORDER
            r_inv = inverse_mod(r_coord, ORDER)
            d = ((k_s - z) * r_inv) % ORDER
            
            keys.append(d)
        except:
            continue
    
    if not keys:
        return None
    
    # Считаем уникальные ключи
    key_counter = Counter(keys)
    unique_count = len(key_counter)
    most_common = key_counter.most_common(1)[0]
    
    # Если все ключи одинаковые - SUCCESS!
    if unique_count == 1:
        print(f"\n{'='*60}")
        print(f"✓✓✓ SUCCESS! Найден единый ключ!")
        print(f"{'='*60}")
        print(f"Вариант: {variant_name}")
        print(f"Приватный ключ: {hex(most_common[0])}")
        print(f"Подтверждений: {most_common[1]}/{len(keys)}")
        return (unique_count, most_common[0], most_common[1])
    
    # Если большинство ключей одинаковые (>50%)
    elif most_common[1] > len(keys) * 0.5:
        print(f"\n~ Вариант '{variant_name}': ЧАСТИЧНОЕ совпадение")
        print(f"  Наиболее частый ключ: {hex(most_common[0])} ({most_common[1]}/{len(keys)} = {100*most_common[1]/len(keys):.1f}%)")
        print(f"  Уникальных ключей: {unique_count}")
        return (unique_count, most_common[0], most_common[1])
    
    return None

def main():
    print("Полный перебор вариантов формирования z")
    print("="*60)
    
    # Читаем данные
    sigs_data = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            payload = bytes.fromhex(row['full_payload_hex'])
            
            if len(payload) >= 108:
                sigs_data.append({'r': r, 's': s, 'payload': payload})
    
    print(f"Загружено подписей: {len(sigs_data)}\n")
    
    # Определяем варианты вычисления z
    variants = []
    
    # Вариант 1: SHA256_field напрямую (без повторного хеша), folded
    variants.append((
        lambda p: int.from_bytes(fold_sha256_to_192(p[4:36]), 'big'),
        "SHA256_field напрямую (folded)"
    ))
    
    # Вариант 2: SHA256_field как есть, без folding (truncated to 24 bytes)
    variants.append((
        lambda p: int.from_bytes(p[4:28], 'big'),  # First 24 bytes
        "SHA256_field первые 24 байта"
    ))
    
    # Вариант 3: Hash(SHA256_field + SessionID), folded (из README)
    variants.append((
        lambda p: int.from_bytes(fold_sha256_to_192(hashlib.sha256(p[4:36] + p[36:60]).digest()), 'big'),
        "Hash(SHA256 + SessionID) folded [README]"
    ))
    
    # Вариант 4: Hash(весь payload без подписи)
    variants.append((
        lambda p: int.from_bytes(fold_sha256_to_192(hashlib.sha256(p[0:60]).digest()), 'big'),
        "Hash(payload[0:60]) folded"
    ))
    
    # Вариант 5: Hash(только SessionID)
    variants.append((
        lambda p: int.from_bytes(fold_sha256_to_192(hashlib.sha256(p[36:60]).digest()), 'big'),
        "Hash(SessionID) folded"
    ))
    
    # Вариант 6: Hash(Version + PacketCount + SHA256_field)
    variants.append((
        lambda p: int.from_bytes(fold_sha256_to_192(hashlib.sha256(p[0:36]).digest()), 'big'),
        "Hash(Ver + PktCnt + SHA256) folded"
    ))
    
    # Вариант 7: Только packet count (возможно, это счетчик для детерминированного nonce)
    variants.append((
        lambda p: int.from_bytes(p[2:4], 'little'),
        "Packet Count как z"
    ))
    
    # Вариант 8: SHA256_field XOR SessionID (first 24 bytes each)
    def xor_variant(p):
        sha_part = p[4:28]
        session_part = p[36:60][:24]  # First 24 bytes
        result = bytes(a ^ b for a, b in zip(sha_part, session_part))
        return int.from_bytes(result, 'big')
    
    variants.append((xor_variant, "SHA256[0:24] XOR SessionID[0:24]"))
    
    # Вариант 9: Hash всего payload включая сигнатуру (возможно, круговая зависимость разрешена)
    variants.append((
        lambda p: int.from_bytes(fold_sha256_to_192(hashlib.sha256(p).digest()), 'big'),
        "Hash(полный payload) folded"
    ))
    
    # Вариант 10: SessionID напрямую (но он 24 байта, подходит!)
    variants.append((
        lambda p: int.from_bytes(p[36:60], 'big'),
        "SessionID напрямую"
    ))
    
    # Вариант 11: Hash(SHA256_field), БЕЗ SessionID
    variants.append((
        lambda p: int.from_bytes(fold_sha256_to_192(hashlib.sha256(p[4:36]).digest()), 'big'),
        "Hash(SHA256_field) folded"
    ))
    
    # Перебор
    results = []
    for calc, name in variants:
        result = try_z_variant(sigs_data, calc, name)
        if result:
            results.append((name, result))
    
    # Итоги
    print(f"\n{'='*60}")
    print("ИТОГИ ПЕРЕБОРА")
    print(f"{'='*60}")
    
    if not results:
        print("❌ Ни один вариант не дал консистентного ключа")
    else:
        print(f"Найдено вариантов с частичным/полным совпадением: {len(results)}\n")
        for name, (unique, key, count) in sorted(results, key=lambda x: x[1][0]):
            status = "✓ ИДЕАЛЬНО" if unique == 1 else "~ Частично"
            print(f"{status}: {name}")
            print(f"   Уникальных ключей: {unique}, Лучший: {hex(key)[:30]}...")

if __name__ == "__main__":
    main()
