#!/usr/bin/env python3
"""
Проверка: может быть нам нужно использовать РАЗНЫЕ значения r, а не R из подписи?
В стандартной ECDSA: r = (k*G).x mod n

Попробуем вычислить r правильно и проверить, может именно это используется в формуле.
"""

import csv
import hashlib
from ecdsa.curves import NIST192p
from ecdsa import VerifyingKey, SigningKey
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

def test_with_example_from_readme():
    """Используем example из README для верификации нашего понимания"""
    print("Тест с примером из README")
    print("="*60)
    
    # Из README:
    I_hex = "9A477ACB44927A888BE375282B2D9B75EAA8FAEA47ADCBC9"
    Px_hex = "0FF6265F72208B39E725EBE28E2625F35617EEFC8AC86625"
    Py_hex = "352DC76DF0F328344C0962B30D20A197FEEB2002B400111A"
    R_hex = "43588CCB0644C06246FD4C47D8B1C3624948EE3EC7E09FA2"
    S_hex = "64A247E9E4D8DC74176C904B9DD07695A5F5AC50388 7BA4F".replace(" ", "")
    
    I = bytes.fromhex(I_hex)
    Px = int(Px_hex, 16)
    Py = int(Py_hex, 16)
    R_val = int(R_hex, 16)
    S_val = int(S_hex, 16)
    
    print(f"Input (z): {I_hex}")
    print(f"Public Key Px: {Px_hex}")
    print(f"Public Key Py: {Py_hex}")
    print(f"Signature R: {R_hex}")
    print(f"Signature S: {S_hex}")
    
    # Создаем публичный ключ
    try:
        from ecdsa import ellipticcurve
        curve = CURVE.curve
        public_point = ellipticcurve.Point(curve, Px, Py)
        vk = VerifyingKey.from_public_point(public_point, curve=CURVE)
        
        print(f"\n✓ Публичный ключ создан")
        
        # Пытаемся верифицировать
        # Сигнатура в формате bytes: R (24) + S (24)
        sig_bytes = R_val.to_bytes(24, 'big') + S_val.to_bytes(24, 'big')
        
        try:
            # ECDSA верификация требует хеш без префикса, просто данные
            verified = vk.verify_digest(sig_bytes, I, sigdecode=lambda sig, order: (
                int.from_bytes(sig[:24], 'big'),
                int.from_bytes(sig[24:], 'big')
            ))
            print(f"✓ Подпись верифицирована!")
        except Exception as e:
            print(f"✗ Верификация не удалась: {e}")
            
            # Попробуем ручную верификацию
            print(f"\nРучная верификация:")
            z = int.from_bytes(I, 'big')
            r = R_val
            s = S_val
            n = ORDER
            
            w = inverse_mod(s, n)
            u1 = (z * w) % n
            u2 = (r * w) % n
            
            point = u1 * G + u2 * public_point
            
            print(f"  z = {hex(z)}")
            print(f"  w = s^-1 = {hex(w)}")
            print(f"  u1 = z*w = {hex(u1)}")
            print(f"  u2 = r*w = {hex(u2)}")
            print(f"  Point = u1*G + u2*Pub:")
            print(f"    x = {hex(point.x())}")
            print(f"    y = {hex(point.y())}")
            print(f"  Ожидаемый r = {hex(r)}")
            print(f"  Совпадение: {point.x() == r}")
            
    except Exception as e:
        print(f"✗ Ошибка создания ключа: {e}")

def analyze_our_signatures_with_correct_r():
    """
    Пробуем использовать правильное r = (k*G).x вместо R из подписи
    """
    print(f"\n{'='*60}")
    print("Анализ наших подписей с правильным вычислением r")
    print(f"{'='*60}")
    
    sigs_data = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            R_from_sig = int(row['r_hex'], 16)
            S_from_sig = int(row['s_hex'], 16)
            payload = bytes.fromhex(row['full_payload_hex'])
            
            if len(payload) >= 108:
                sigs_data.append({
                    'R_field': R_from_sig,
                    'S': S_from_sig,
                    'payload': payload
                })
    
    print(f"Загружено подписей: {len(sigs_data)}")
    
    # Вычисляем z по методу README
    keys = []
    for sig in sigs_data[:5]:  # Первые 5 для теста
        R_field = sig['R_field']
        S = sig['S']
        payload = sig['payload']
        
        # z из README
        sha256_part = payload[4:36]
        session_id = payload[36:60]
        msg_to_sign = sha256_part + session_id
        z_hash = hashlib.sha256(msg_to_sign).digest()
        z_folded = fold_sha256_to_192(z_hash)
        z = int.from_bytes(z_folded, 'big')
        
        # Предполагаем k = R_field
        k = R_field
        
        # Вычисляем настоящее r = (k*G).x
        R_point = k * G
        r_true = R_point.x()
        
        print(f"\nПодпись:")
        print(f"  R из поля: {hex(R_field)[:30]}...")
        print(f"  r = (k*G).x: {hex(r_true)[:30]}...")
        print(f"  Совпадение: {R_field == r_true}")
        
        # Теперь используем r_true в формуле
        # s = k^-1 * (z + r*d)
        # k*s = z + r*d
        # d = (k*s - z) * r^-1
        
        k_s = (k * S) % ORDER
        d = ((k_s - z) * inverse_mod(r_true, ORDER)) % ORDER
        
        keys.append(d)
        print(f"  d (с r_true): {hex(d)[:30]}...")
    
    # Проверяем консистентность
    if len(set(keys)) == 1:
        print(f"\n✓✓✓ ВСЕ КЛЮЧИ ОДИНАКОВЫЕ!")
        print(f"Приватный ключ: {hex(keys[0])}")
    else:
        print(f"\n✗ Ключи различны: {len(set(keys))} уникальных")

if __name__ == "__main__":
    test_with_example_from_readme()
    analyze_our_signatures_with_correct_r()
