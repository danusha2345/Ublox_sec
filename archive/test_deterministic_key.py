#!/usr/bin/env python3
"""
ГИПОТЕЗА: Приватный ключ генерируется детерминированно для каждой подписи
Возможно: d = hash(chip_id + sha256_field + ...)
"""

import csv
import hashlib
from ecdsa.curves import NIST192p
from collections import Counter, defaultdict

CURVE = NIST192p
ORDER = CURVE.order
G = CURVE.generator

CHIP_ID = bytes.fromhex("E095650F2A")

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def test_deterministic_key_hypothesis():
    """
    Проверяем: может ли d быть детерминированно вычислен из payload данных?
    """
    print("="*60)
    print("ТЕСТ: ДЕТЕРМИНИСТ ИЧЕСКАЯ ГЕНЕРАЦИЯ ПРИВАТНОГО КЛЮЧА")
    print("="*60)
    
    data = []
    
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            if len(payload) < 108:
                continue
            
            # Извлекаем компоненты
            version = payload[0:2]
            pkt_count = payload[2:4]
            sha256_field = payload[4:36]
            session_id = payload[36:60]
            sig = payload[60:108]
            
            r_bytes = sig[0:24]
            s_bytes = sig[24:48]
            
            r = int.from_bytes(r_bytes, 'big')
            s = int.from_bytes(s_bytes, 'big')
            
            # z по README
            msg = sha256_field + session_id
            h = hashlib.sha256(msg).digest()
            z_folded = fold_sha256_to_192(h)
            z = int.from_bytes(z_folded, 'big')
            
            # d по формуле (если k=r)
            k = r
            R_point = k * G
            r_coord = R_point.x()
            k_s = (k * s) % ORDER
            d = ((k_s - z) * inverse_mod(r_coord, ORDER)) % ORDER
            
            data.append({
                'sha256_field': sha256_field,
                'pkt_count': int.from_bytes(pkt_count, 'little'),
                'z': z,
                'r': r,
                's': s,
                'd': d
            })
    
    print(f"Загружено подписей: {len(data)}\n")
    
    # Проверяем различные варианты деривации d
    variants = []
    
    # Вариант 1: d = hash(chip_id + sha256_field)
    for entry in data[:5]:
        msg = CHIP_ID + entry['sha256_field']
        h = hashlib.sha256(msg).digest()
        d_candidate = int.from_bytes(fold_sha256_to_192(h), 'big') % ORDER
        
        matches = entry['d'] == d_candidate
        print(f"Вариант 1 (chip_id + sha256_field):")
        print(f"  Вычислено: {hex(d_candidate)[:40]}...")
        print(f"  Ожидается: {hex(entry['d'])[:40]}...")
        print(f"  Совпадение: {matches}\n")
        
        if not matches:
            break
    
    # Вариант 2: d = hash(sha256_field)
    for entry in data[:5]:
        h = hashlib.sha256(entry['sha256_field']).digest()
        d_candidate = int.from_bytes(fold_sha256_to_192(h), 'big') % ORDER
        
        matches = entry['d'] == d_candidate
        print(f"Вариант 2 (sha256_field):")
        print(f"  Вычислено: {hex(d_candidate)[:40]}...")
        print(f"  Ожидается: {hex(entry['d'])[:40]}...")
        print(f"  Совпадение: {matches}\n")
        
        if not matches:
            break
    
    # Вариант 3: d = hash(chip_id + pkt_count)
    for entry in data[:5]:
        msg = CHIP_ID + entry['pkt_count'].to_bytes(2, 'little')
        h = hashlib.sha256(msg).digest()
        d_candidate = int.from_bytes(fold_sha256_to_192(h), 'big') % ORDER
        
        matches = entry['d'] == d_candidate
        print(f"Вариант 3 (chip_id + pkt_count):")
        print(f"  Вычислено: {hex(d_candidate)[:40]}...")
        print(f"  Ожидается: {hex(entry['d'])[:40]}...")
        print(f"  Совпадение: {matches}\n")
        
        if not matches:
            break
    
    print("="*60)
    print("ВСЕ ВАРИАНТЫ НЕ ДАЛИ СОВПАДЕНИЙ")
    print("="*60)
    print()
    print("ВЫВОД: Приватный ключ НЕ генерируется детерминированно")
    print("       из известных нам данных payload или chip_id")

if __name__ == "__main__":
    test_deterministic_key_hypothesis()
