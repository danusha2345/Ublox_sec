#!/usr/bin/env python3
"""
Восстановление ключа u-blox с учетом информации из README

Ключевое из README:
- Подписывается hash+sessionID (56 байт)
-  SHA256 от этих 56 байт сворачивается в 192 бита через XOR
- Подпись ECDSA на кривой SECP192R1

Структура payload UBX-SEC-ECSIGN (108 байт):
+0x00: Version (2 байта)
+0x02: Packet Count (2 байта)
+0x04: SHA256 Hash (32 байта) - хеш всех передаваемых данных кроме UBX-SEC-ECSIGN
+0x24: Session ID (24 байта)
+0x3C: Signature R+S (48 байт: 24+24)

Согласно README:
"8f945cdaf783fb218be375282b2d9b75eaa8faea47adcbc915d32611b31181a9 is the SHA256 of 56-bytes (+0x04 .. 0x3B)"

Т.е. подп исывается НЕ исходный хеш потока, а SHA256(SHA256_из_payload + SessionID)!
"""

import csv
import hashlib
from ecdsa.curves import NIST192p
from collections import Counter

CURVE = NIST192p
ORDER = CURVE.order

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    """Сворачивает 256-битный хеш в 192 бита"""
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def recover_key_correct_method():
    """
    Восстановление ключа с правильным пониманием формата
    
    Согласно README:
    1. msg_to_sign = sha256_from_payload (32 bytes) + session_id (24 bytes) = 56 bytes
    2. z_hash = SHA256(msg_to_sign)
    3. z_folded = fold_to_192(z_hash)
    4. signature = ECDSA_sign(z_folded)
    """
    print("Восстановление ключа (метод из README)")
    print("="*60)
    
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
            sha256_part = payload[4:36]   # 32 bytes
            session_id = payload[36:60]    # 24 bytes
            
            # Формируем сообщение для подписи (56 bytes total)
            msg_to_sign = sha256_part + session_id
            
            # Хешируем
            z_hash = hashlib.sha256(msg_to_sign).digest()
            
            # Сворачиваем в 192 бита
            z_folded = fold_sha256_to_192(z_hash)
            z = int.from_bytes(z_folded, 'big')
            
            sigs.append({'r': r, 's': s, 'z': z})
    
    print(f"Обработано подписей: {len(sigs)}")
    
    n = ORDER
    G = CURVE.generator
    
    # Гипотеза 1: R = k
    print("\nГипотеза 1: R = k (nonce)")
    candidates = []
    
    for i, sig in enumerate(sigs[:10]):
        k = sig['r']
        if k == 0 or k >= n:
            continue
        
        s = sig['s']
        z = sig['z']
        
        # Стандартная ECDSA: s = k^-1 * (z + r*d), где r = (k*G).x
        try:
            R_point = k * G
            r_coord = R_point.x()
            
            # d = r^-1 * (k*s - z)
            val = (k * s - z) % n
            d = (val * inverse_mod(r_coord, n)) % n
            
            candidates.append(d)
            if i < 5:
                print(f"  Sig #{i}: d = {hex(d)}")
        except Exception as e:
            print(f"  Sig #{i}: ошибка - {e}")
            continue
    
    if candidates:
        common = Counter(candidates).most_common(3)
        print(f"\nТоп-3 кандидатов:")
        for d_val, count in common:
            print(f"  {hex(d_val)}: {count} раз(а)")
        
        if common[0][1] > 1:
            print(f"\n{'='*60}")
            print(f"✓ УСПЕХ! Найден консистентный ключ!")
            print(f"Приватный ключ: {hex(common[0][0])}")
            print(f"Консистентность: {common[0][1]}/{len(candidates)}")
            return common[0][0]
    
    #  Гипотеза 2: R = (k*G).x, но R записан напрямую (не k)
    print("\n\nГипотеза 2: R = r (координата точки)")
    candidates2 = []
    
    for i, sig in enumerate(sigs[:10]):
        r = sig['r']
        s = sig['s']
        z = sig['z']
        
        if r == 0 or r >= n:
            continue
        
        # s*k = z + r*d
        # Нам неизвестен k, но мы можем попробовать перебрать малые k (если nonce маленький)
        # Но это сложно. Попробуем просто проверить формулу для верификации
        
        # Для верификации: R_verify = (z/s)*G + (r/s)*PublicKey
        # Но у нас нет публичного ключа
        
        continue
    
    print("\n\nГипотеза 3: Проверка других вариантов...")
    # Попробуем вариант "Lazy ECDSA": s = k^-1(z + k*d) => d = s - z/k
    candidates3 = []
    for i, sig in enumerate(sigs[:10]):
        k = sig['r']  # Assume R = k
        s = sig['s']
        z = sig['z']
        
        if k == 0 or k >= n:
            continue
        
        # d = s - z / k = (s*k - z) / k = s - z*k^-1
        d = (s - z * inverse_mod(k, n)) % n
        candidates3.append(d)
        if i < 5:
            print(f"  Sig #{i}: d = {hex(d)}")
    
    if candidates3:
        common3 = Counter(candidates3).most_common(1)
        print(f"\nНаиболее частый: {hex(common3[0][0])} ({common3[0][1]} раз)")
        if common3[0][1] > 1:
            print(f"\n✓ УСПЕХ (Lazy ECDSA)!")
            print(f"Приватный ключ: {hex(common3[0][0])}")
            return common3[0][0]
    
    print("\n✗ Восстановление не удалось")
    return None

if __name__ == "__main__":
    recover_key_correct_method()
