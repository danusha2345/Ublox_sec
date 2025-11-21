#!/usr/bin/env python3
"""
Правильная реализация согласно README для SEC-ECSIGN (0x27 0x04)

Структура payload (108 байт):
  +0x00  Version (2 bytes)
  +0x02  Packet Count (2 bytes)  
  +0x04  SHA256 (32 bytes)
  +0x24  Session ID (24 bytes)
  +0x3C  SECP192R1 Signature (48 bytes: 24 R + 24 S)

Подпись создается так:
1. Берем SHA256 field (32 байта) + SessionID (24 байта) = 56 байт
2. Хешируем: SHA256(56 байт)
3. Folding к 192 битам: для i in [0..7]: sha[i] ^= sha[i+24]
4. Подписываем folded hash
"""

import csv
import hashlib

ORDER = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

def inverse_mod(k, p):
    if k == 0: raise ZeroDivisionError()
    if k < 0: k = p - (-k % p)
    s, old_s = 0, 1
    r, old_r = p, k
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % p

def fold_sha256_to_192(digest):
    """Folding согласно README"""
    digest_bytes = bytearray(digest)
    folded = digest_bytes[:24]
    for i in range(8):
        folded[i] ^= digest_bytes[24 + i]
    return bytes(folded)

def main():
    print("Проверка с правильной структурой согласно README\n")
    
    signatures = []
    with open('hnp_capture.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            if len(payload) < 108:
                continue
            
            # Структура согласно README:
            # +0x04: SHA256 (32 bytes)
            # +0x24: SessionID (24 bytes)  
            # +0x3C: Signature (48 bytes)
            
            sha256_field = payload[4:36]   # 32 байта
            sessionId = payload[36:60]      # 24 байта
            
            # Подписываемые данные = SHA256_field + SessionID (56 байт)
            to_sign = sha256_field + sessionId
            
            # Хешируем
            final_hash = hashlib.sha256(to_sign).digest()
            
            # Folding к 192 битам
            z_bytes = fold_sha256_to_192(final_hash)
            z = int.from_bytes(z_bytes, 'big')
            
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            
            signatures.append({
                'r': r,
                's': s,
                'z': z,
                'sha256_field': sha256_field.hex(),
                'sessionId': sessionId.hex()
            })
    
    print(f"Загружено {len(signatures)} подписей\n")
    
    # Проверяем гипотезу R = k
    print("="*60)
    print("Проверка: R = k (nonce)")
    print("="*60)
    
    d_values = []
    for i, sig in enumerate(signatures[:20]):
        k = sig['r']
        r = sig['r']
        s = sig['s']
        z = sig['z']
        
        try:
            # d = (s*k - z) / r mod n
            r_inv = inverse_mod(r, ORDER)
            d = (s * k - z) * r_inv % ORDER
            d_values.append(d)
            
            if i < 5:
                print(f"Sig {i}: d = {hex(d)[:30]}...")
                print(f"  SessionID: {sig['sessionId']}")
        except Exception as e:
            print(f"Sig {i}: ERROR - {e}")
    
    # Проверяем уникальность d
    unique_d = set(d_values)
    print(f"\nУникальных значений d: {len(unique_d)}/{len(d_values)}")
    
    if len(unique_d) == 1:
        private_key = list(unique_d)[0]
        print(f"\n{'='*60}")
        print("✓✓✓ ПРИВАТНЫЙ КЛЮЧ НАЙДЕН! ✓✓✓")
        print(f"{'='*60}")
        print(f"d = {hex(private_key)}")
        print(f"{'='*60}")
    elif len(unique_d) < 10:
        print(f"\nНайдено {len(unique_d)} возможных ключей (ротация?)")
        for i, d in enumerate(sorted(unique_d)):
            print(f"  Key {i}: {hex(d)[:40]}...")
    else:
        print("\n✗ Гипотеза R=k неверна или z вычисляется иначе")

if __name__ == "__main__":
    main()
