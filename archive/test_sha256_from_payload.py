#!/usr/bin/env python3
"""
КРИТИЧЕСКАЯ ГИПОТЕЗА:
Может быть, SHA256 field в SEC-SIGN - это вообще НЕ хеш сообщений?
Может это какой-то ID или метаданные?

Попробуем вычислить z по-другому:
1. Хешируем только UBX-NAV-PVT сообщения (навигационные данные)
2. Или хешируем что-то еще

Или может быть нам нужно проверить, что НАША формула z из README работает,
независимо от того, что в поле SHA256?
"""

import csv
import hashlib

ORDER = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

def inverse_mod(k, p):
    if k == 0: raise ZeroDivisionError("division by zero")
    if k < 0: k = p - (-k % p)
    s, old_s = 0, 1
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s % p

def fold_sha256_to_192(digest):
    """Folding согласно README"""
    digest_bytes = bytearray(digest)
    folded = digest_bytes[:24]
    for i in range(8):
        folded[i] ^= digest_bytes[24 + i]
    return bytes(folded)

def main():
    print("Проверяем консистентность приватного ключа")
    print("Используя SHA256 field из payload'а (не вычисляем сами)\n")
    
    signatures = []
    with open('hnp_capture.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            # SHA256 из payload (байты 6-37, но используем только первые 30)
            sha256_from_payload = payload[6:36]  # 30 байт
            
            # Добавляем SessionID (22 байта нулей)
            sessionId = bytes(22)
            
            # Объединяем для хеширования
            combined = sha256_from_payload + sessionId
            final_hash = hashlib.sha256(combined).digest()
            z_bytes = fold_sha256_to_192(final_hash)
            z = int.from_bytes(z_bytes, 'big')
            
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            
            signatures.append({'r': r, 's': s, 'z': z})
    
    print(f"Загружено {len(signatures)} подписей\n")
    
    # Пробуем найти приватный ключ из первых двух подписей
    sig1 = signatures[0]
    sig2 = signatures[1]
    
    # Предполагаем R=k
    k1 = sig1['r']
    k2 = sig2['r']
    
    # d = (s*k - z) / r
    for i, sig in enumerate(signatures[:10]):
        k = sig['r']
        r = sig['r']
        s = sig['s']
        z = sig['z']
        
        try:
            r_inv = inverse_mod(r, ORDER)
            d = (s * k - z) * r_inv % ORDER
            print(f"Sig {i}: d = {hex(d)[:20]}...")
        except:
            print(f"Sig {i}: ОШИБКА")
    
    print("\nЕсли все d разные - значит либо формула z неправильная,")
    print("либо R ≠ k, либо используется несколько ключей.")

if __name__ == "__main__":
    main()
