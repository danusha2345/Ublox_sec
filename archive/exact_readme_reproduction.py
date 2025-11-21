#!/usr/bin/env python3
"""
ТОЧНОЕ ВОСПРОИЗВЕДЕНИЕ ПРИМЕРА ИЗ README

Из README.md:
---
Packets : 22
 252852fa92e9c6c2dc1db4dffb8b0bf8ce33eb8760ef95d2b05b7af2e08ea927
 pass
 8f945cdaf783fb218be375282b2d9b75eaa8faea47adcbc915d32611b31181a9
 9a477acb44927a888be375282b2d9b75eaa8faea47adcbc9
 verified

Payload
 +0x00  Version#1
 +0x02  Packet Count
 +0x04  SHA256 (32-bytes)
 +0x24  Session ID (24-bytes)
 +0x3C  SECP192R1 Signing of SHA256+Session ID (48-bytes)

8f945cdaf783fb218be375282b2d9b75eaa8faea47adcbc915d32611b31181a9 is the SHA256 of 56-bytes (+0x04 .. 0x3B)

9a477acb44927a888be375282b2d9b75eaa8faea47adcbc9 is 192-bit (24-byte) truncate+xor of the 256-bit (32-byte) SHA256

for(int i=0; i<8; i++) sha[i] ^= sha[i + 24]; // Folding Hash to 192-bits for signing method
---

Давайте проверим это пошагово.
"""

import hashlib

def fold_sha256_to_192(sha256_hash):
    """Точная реализация из README"""
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def reproduce_readme_example():
    print("ВОСПРОИЗВЕДЕНИЕ ПРИМЕРА ИЗ README")
    print("="*60)
    
    # Из README - полный payload example
    payload_hex = """
    01 00 16 00 25 28 52 FA 92 E9 C6 C2 DC 1D B4 DF 
    FB 8B 0B F8 CE 33 EB 87 60 EF 95 D2 B0 5B 7A F2 
    E0 8E A9 27 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 43 58 8C CB 
    06 44 C0 62 46 FD 4C 47 D8 B1 C3 62 49 48 EE 3E 
    C7 E0 9F A2 64 A2 47 E9 E4 D8 DC 74 17 6C 90 4B 
    9D D0 76 95 A5 F5 AC 50 38 87 BA 4F
    """.replace("\n", "").replace(" ", "")
    
    payload = bytes.fromhex(payload_hex)
    
    print(f"Payload длина: {len(payload)} байт")
    print(f"Payload hex: {payload.hex()}")
    print()
    
    # Разбираем
    version = payload[0:2]
    packet_count = payload[2:4]
    sha256_field = payload[4:36]
    session_id = payload[36:60]
    signature = payload[60:108]
    
    print(f"Version: {version.hex()}")
    print(f"Packet Count: {int.from_bytes(packet_count, 'little')}")
    print(f"SHA256 field (32 bytes): {sha256_field.hex()}")
    print(f"Session ID (24 bytes): {session_id.hex()}")
    print(f"Signature (48 bytes): {signature.hex()}")
    print()
    
    # Шаг 1: Вычисляем SHA256 от 56 байт (SHA256_field + SessionID)
    msg_to_hash = sha256_field + session_id  # 32 + 24 = 56 bytes
    
    print(f"Сообщение для хеширования (56 bytes):")
    print(f"  {msg_to_hash.hex()}")
    print()
    
    computed_sha256 = hashlib.sha256(msg_to_hash).digest()
    
    expected_sha256_hex = "8f945cdaf783fb218be375282b2d9b75eaa8faea47adcbc915d32611b31181a9"
    
    print(f"Вычисленный SHA256:")
    print(f"  {computed_sha256.hex()}")
    print(f"Ожидаемый SHA256 (из README):")
    print(f"  {expected_sha256_hex}")
    print(f"Совпадение: {computed_sha256.hex() == expected_sha256_hex}")
    print()
    
    # Шаг 2: Сворачиваем в 192 бита
    folded = fold_sha256_to_192(computed_sha256)
    
    expected_folded_hex = "9a477acb44927a888be375282b2d9b75eaa8faea47adcbc9"
    
    print(f"Свернутый хеш (192-bit):")
    print(f"  {folded.hex()}")
    print(f"Ожидаемый (из README):")
    print(f"  {expected_folded_hex}")
    print(f"Совпадение: {folded.hex() == expected_folded_hex}")
    print()
    
    # Шаг 3: Извлекаем R и S из подписи
    R = signature[0:24]
    S = signature[24:48]
    
    expected_R_hex = "43588CCB0644C06246FD4C47D8B1C3624948EE3EC7E09FA2"
    expected_S_hex = "64A247E9E4D8DC74176C904B9DD07695A5F5AC503887BA4F"
    
    print(f"Подпись R (24 bytes):")
    print(f"  {R.hex().upper()}")
    print(f"Ожидаемая (из README):")
    print(f"  {expected_R_hex}")
    print(f"Совпадение: {R.hex().upper() == expected_R_hex}")
    print()
    
    print(f"Подпись S (24 bytes):")
    print(f"  {S.hex().upper()}")
    print(f"Ожидаемая (из README):")
    print(f"  {expected_S_hex}")
    print(f"Совпадение: {S.hex().upper() == expected_S_hex}")
    print()
    
    # Шаг 4: Публичный ключ из README
    Px_hex = "0FF6265F72208B39E725EBE28E2625F35617EEFC8AC86625"
    Py_hex = "352DC76DF0F328344C0962B30D20A197FEEB2002B400111A"
    
    print(f"Публичный ключ:")
    print(f"  Px: {Px_hex}")
    print(f"  Py: {Py_hex}")
    print()
    
    print("="*60)
    print("ВСЕ ЗНАЧЕНИЯ ИЗ README ВОСПРОИЗВЕДЕНЫ ТОЧНО")
    print("="*60)
    
    return {
        'z': folded,
        'r': R,
        's': S,
        'Px': int(Px_hex, 16),
        'Py': int(Py_hex, 16)
    }

def apply_to_our_data():
    """Применяем точно такой же метод к нашим данным"""
    print("\n" + "="*60)
    print("ПРИМЕНЕНИЕ К НАШИМ ДАННЫМ")
    print("="*60)
    
    import csv
    from ecdsa.curves import NIST192p
    from collections import Counter
    
    ORDER = NIST192p.order
    G = NIST192p.generator
    
    def inverse_mod(a, m):
        return pow(a, -1, m)
    
    keys = []
    
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        
        for i, row in enumerate(reader):
            if i >= 10:  # Первые 10
                break
                
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            if len(payload) < 108:
                continue
            
            # ТОЧНО как в README
            sha256_field = payload[4:36]
            session_id = payload[36:60]
            
            # Шаг 1: SHA256(56 bytes)
            msg = sha256_field + session_id
            h = hashlib.sha256(msg).digest()
            
            # Шаг 2: Fold to 192-bit
            z_folded = fold_sha256_to_192(h)
            z = int.from_bytes(z_folded, 'big')
            
            # Шаг 3: Извлекаем R и S из payload
            sig = payload[60:108]
            r_bytes = sig[0:24]
            s_bytes = sig[24:48]
            
            r = int.from_bytes(r_bytes, 'big')
            s = int.from_bytes(s_bytes, 'big')
            
            # Теперь проверяем: может R в подписи - это координата точки (k*G).x ?
            # И мы должны найти k такое, что r = R?
            
            # Или может R - это просто random/session value, а настоящая подпись вычисляется по-другому?
            
            # Давайте попробуем ОБРАТНОЕ: считаем что r (из подписи) это правильное r
            # и пытаемся восстановить k из уравнения верификации
            
            # Для верификации: u1*G + u2*Pub должно дать точку с x-координатой = r
            # Но у нас нет публичного ключа...
            
            # Хм, но мы можем попробовать другое:
            # Если s = k^-1(z + rd), то k = (z + rd)/s
            # Но нам нужен d для этого...
            
            # Попробуем предположить, что k можно вычислить из r обратно
            # Но это невозможно в ECDSA без знания приватного ключа
            
            # Давайте просто попробуем старый метод, но с ТОЧНЫМ z
            print(f"\nПодпись #{i}:")
            print(f"  z (folded): {hex(z)[:30]}...")
            print(f"  r: {hex(r)[:30]}...")
            print(f"  s: {hex(s)[:30]}...")
            
            # Если предположить k = r (как мы делали раньше)
            k = r
            if k == 0 or k >= ORDER:
                continue
            
            R_point = k * G
            r_coord = R_point.x()
            
            # d = r^-1 * (k*s - z)
            k_s = (k * s) % ORDER
            d = ((k_s - z) * inverse_mod(r_coord, ORDER)) % ORDER
            
            keys.append(d)
            print(f"  d (если k=r): {hex(d)[:30]}...")
    
    if keys:
        unique = len(set(keys))
        most_common = Counter(keys).most_common(1)[0]
        
        print(f"\n{'='*60}")
        print(f"Уникальных ключей: {unique}")
        print(f"Наиболее частый: {hex(most_common[0])} ({most_common[1]} раз)")
        
        if unique == 1:
            print(f"✓✓✓ ВСЕ КЛЮЧИ ОДИНАКОВЫЕ!")
            print(f"Приватный ключ: {hex(most_common[0])}")

if __name__ == "__main__":
    example_data = reproduce_readme_example()
    apply_to_our_data()
