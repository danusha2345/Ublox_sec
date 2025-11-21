#!/usr/bin/env python3
"""
Проверка гипотез о связи Chip ID с приватным ключом

Chip ID: 0xE095650F2A (40-bit unique identifier)
"""

import hashlib
import hmac
from ecdsa.curves import NIST192p
from collections import Counter

CURVE = NIST192p
ORDER = CURVE.order
G = CURVE.generator

# Chip ID из UBX-SEC-UNIQID
CHIP_ID = bytes.fromhex("E095650F2A")

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def hkdf_extract(salt, ikm):
    """HKDF-Extract step"""
    if salt is None:
        salt = bytes([0] * 32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    """HKDF-Expand step"""
    t = b""
    okm = b""
    counter = 1
    
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    
    return okm[:length]

def derive_key_variants(chip_id):
    """Генерирует различные варианты приватного ключа из Chip ID"""
    variants = {}
    
    # Вариант 1: Простой SHA256, folded
    h1 = hashlib.sha256(chip_id).digest()
    k1 = int.from_bytes(fold_sha256_to_192(h1), 'big') % ORDER
    variants["SHA256(chip_id) folded"] = k1
    
    # Вариант 2: SHA256, первые 24 байта
    h2 = hashlib.sha256(chip_id).digest()
    k2 = int.from_bytes(h2[:24], 'big') % ORDER
    variants["SHA256(chip_id) truncated"] = k2
    
    # Вариант 3: HMAC-SHA256 с доменным разделителем
    h3 = hmac.new(b"u-blox-ecdsa-key", chip_id, hashlib.sha256).digest()
    k3 = int.from_bytes(fold_sha256_to_192(h3), 'big') % ORDER
    variants["HMAC(key='u-blox-ecdsa-key', chip_id) folded"] = k3
    
    # Вариант 4: HMAC с другим ключом
    h4 = hmac.new(chip_id, b"private-key-derivation", hashlib.sha256).digest()
    k4 = int.from_bytes(fold_sha256_to_192(h4), 'big') % ORDER
    variants["HMAC(key=chip_id, 'private-key-derivation') folded"] = k4
    
    # Вариант 5: HKDF
    prk = hkdf_extract(None, chip_id)
    okm = hkdf_expand(prk, b"u-blox secp192r1 key", 24)
    k5 = int.from_bytes(okm, 'big') % ORDER
    variants["HKDF(chip_id, 'u-blox secp192r1 key')"] = k5
    
    # Вариант 6: Двойное хеширование
    h6 = hashlib.sha256(hashlib.sha256(chip_id).digest()).digest()
    k6 = int.from_bytes(fold_sha256_to_192(h6), 'big') % ORDER
    variants["SHA256(SHA256(chip_id)) folded"] = k6
    
    # Вариант 7: Chip ID напрямую как seed для PRNG-подобной схемы
    # Расширяем 5 байт до 24 через повторное хеширование с счетчиком
    seed = chip_id
    extended = b""
    for i in range(3):  # 3 * 8 = 24 bytes
        extended += hashlib.sha256(seed + bytes([i])).digest()[:8]
    k7 = int.from_bytes(extended[:24], 'big') % ORDER
    variants["Extended(chip_id) via counter"] = k7
    
    # Вариант 8: XOR chip_id с константой и хеш
    constant = b"\x5A" * 5  # Arbitrary constant
    xored = bytes(a ^ b for a, b in zip(chip_id, constant))
    h8 = hashlib.sha256(xored).digest()
    k8 = int.from_bytes(fold_sha256_to_192(h8), 'big') % ORDER
    variants["SHA256(chip_id XOR 0x5A5A5A5A5A) folded"] = k8
    
    return variants

def test_key_candidate(candidate_key, sigs_data):
    """Проверяет, дает ли кандидат ключа консистентные результаты"""
    
    # Вычисляем публичный ключ
    pub_key_point = candidate_key * G
    
    recovered_keys = []
    
    for sig in sigs_data[:10]:  # Первые 10 для теста
        r_field = sig['r']
        s = sig['s']
        payload = sig['payload']
        
        # z по методу README
        sha256_part = payload[4:36]
        session_id = payload[36:60]
        msg_to_sign = sha256_part + session_id
        z_hash = hashlib.sha256(msg_to_sign).digest()
        z_folded = fold_sha256_to_192(z_hash)
        z = int.from_bytes(z_folded, 'big')
        
        # Предполагаем k = r_field
        k = r_field
        
        # Вычисляем r_true
        R_point = k * G
        r_true = R_point.x()
        
        # Восстанавливаем d
        k_s = (k * s) % ORDER
        d = ((k_s - z) * inverse_mod(r_true, ORDER)) % ORDER
        
        recovered_keys.append(d)
    
    # Проверяем консистентность
    unique = len(set(recovered_keys))
    
    # Проверяем, совпадает ли хотя бы один с кандидатом
    matches = sum(1 for d in recovered_keys if d == candidate_key)
    
    return {
        'unique_keys': unique,
        'matches_with_candidate': matches,
        'most_common': Counter(recovered_keys).most_common(1)[0] if recovered_keys else None
    }

def main():
    print("="*60)
    print("АНАЛИЗ СВЯЗИ CHIP ID С ПРИВАТНЫМ КЛЮЧОМ")
    print("="*60)
    print(f"Chip ID: {CHIP_ID.hex().upper()}")
    print(f"Decimal: {int.from_bytes(CHIP_ID, 'big')}")
    print()
    
    # Генерируем варианты ключей
    key_variants = derive_key_variants(CHIP_ID)
    
    print("Сгенерированные варианты ключей:")
    print("-"*60)
    for name, key in key_variants.items():
        print(f"{name}:")
        print(f"  {hex(key)[:50]}...")
        
        # Вычисляем публичный ключ
        pub = key * G
        print(f"  Pub.x: {hex(pub.x())[:40]}...")
    print()
    
    # Загружаем подписи для теста
    import csv
    sigs_data = []
    try:
        with open("hnp_capture.csv", 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                r = int(row['r_hex'], 16)
                s = int(row['s_hex'], 16)
                payload = bytes.fromhex(row['full_payload_hex'])
                
                if len(payload) >= 108:
                    sigs_data.append({'r': r, 's': s, 'payload': payload})
        
        print(f"Загружено подписей для теста: {len(sigs_data)}")
        print()
        
        # Тестируем каждый вариант
        print("="*60)
        print("ПРОВЕРКА КАНДИДАТОВ")
        print("="*60)
        
        for name, key in key_variants.items():
            result = test_key_candidate(key, sigs_data)
            print(f"\n{name}:")
            print(f"  Уникальных ключей при восстановлении: {result['unique_keys']}")
            print(f"  Совпадений с кандидатом: {result['matches_with_candidate']}")
            
            if result['most_common']:
                most_common_key, count = result['most_common']
                print(f"  Наиболее частый: {hex(most_common_key)[:40]}... ({count} раз)")
                
                if result['unique_keys'] == 1:
                    print(f"  ✓✓✓ ВСЕ ВОССТАНОВЛЕННЫЕ КЛЮЧИ ОДИНАКОВЫЕ!")
                    if result['matches_with_candidate'] > 0:
                        print(f"  ✓✓✓ И СОВПАДАЮТ С КАНДИДАТОМ!")
                        print(f"\n{'='*60}")
                        print(f"SUCCESS! НАЙДЕН ПРИВАТНЫЙ КЛЮЧ!")
                        print(f"{'='*60}")
                        print(f"Метод: {name}")
                        print(f"Ключ: {hex(key)}")
                        return key
                        
    except FileNotFoundError:
        print("Файл hnp_capture.csv не найден. Пропускаем проверку.")
    
    print(f"\n{'='*60}")
    print("Ни один вариант не дал полного совпадения")
    print("="*60)

if __name__ == "__main__":
    main()
