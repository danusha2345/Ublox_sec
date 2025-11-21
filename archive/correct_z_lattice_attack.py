#!/usr/bin/env python3
"""
ПРАВИЛЬНЫЙ РАСЧЕТ z С УЧЕТОМ ПОЛНЫХ СООБЩЕНИЙ

Формула:
1. SHA256_field = SHA256(все полные UBX сообщения между подписями)
2. to_sign = SHA256_field + SessionID (56 байт)
3. h = SHA256(to_sign)
4. z = fold(h) - XOR первых 8 байт с байтами 24-31
"""

import csv
import struct
import hashlib
from fpylll import IntegerMatrix, BKZ

ORDER = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def read_ubx_messages(filepath):
    messages = []
    with open(filepath, 'rb') as f:
        data = f.read()
    
    i = 0
    while i < len(data) - 6:
        if data[i] == 0xB5 and data[i+1] == 0x62:
            msg_class = data[i+2]
            msg_id = data[i+3]
            length = struct.unpack('<H', data[i+4:i+6])[0]
            
            if i + 6 + length + 2 > len(data):
                i += 1
                continue
            
            full_msg = data[i:i+6+length+2]
            
            # Checksum
            ck_a = 0
            ck_b = 0
            for byte in data[i+2:i+6+length]:
                ck_a = (ck_a + byte) & 0xFF
                ck_b = (ck_b + ck_a) & 0xFF
            
            checksum = data[i+6+length:i+6+length+2]
            expected = bytes([ck_a, ck_b])
            
            if checksum == expected:
                messages.append({
                    'offset': i,
                    'type': (msg_class, msg_id),
                    'length': length,
                    'full_msg': full_msg
                })
                i += 6 + length + 2
            else:
                i += 1
        else:
            i += 1
    
    return messages

print("="*60)
print("ПРАВИЛЬНЫЙ РАСЧЕТ z И LATTICE ATTACK")
print("="*60)

print("\nЗагружаем сообщения из log...")

# Проверяем, есть ли готовый CSV с подписями
if os.path.exists('sigs_new.csv'):
    print("Найден sigs_new.csv, загружаем готовые подписи...")
    signatures = []
    with open('sigs_new.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            signatures.append({
                'r': int(row['r']),
                's': int(row['s']),
                'z': int(row['z']),
                'r_bits': int(row['r_bits'])
            })
    print(f"Загружено {len(signatures)} подписей из CSV")
else:
    # Старый метод загрузки из bin
    all_messages = read_ubx_messages('log_ublox_big.bin')
    print(f"Найдено {len(all_messages)} UBX сообщений")
    
    sign_messages = [msg for msg in all_messages if msg['type'] == (0x27, 0x04)]
    print(f"Найдено {len(sign_messages)} SEC-SIGN сообщений\n")
    
    signatures = []
    
    for idx in range(len(sign_messages)):
        sign_msg = sign_messages[idx]
        
        # Извлекаем R, S, SessionID из payload
        sign_offset = sign_msg['offset']
        sign_payload_start = sign_offset + 6
        
        with open('log_ublox_big.bin', 'rb') as f:
            f.seek(sign_payload_start)
            payload = f.read(sign_msg['length'])
        
        sessionId = payload[36:60]
        r = int.from_bytes(payload[60:84], 'big')
        s = int.from_bytes(payload[84:108], 'big')
        
        # Находим все сообщения МЕЖДУ подписями
        if idx == 0:
            start_offset = 0
        else:
            prev_sign = sign_messages[idx - 1]
            start_offset = prev_sign['offset'] + 6 + prev_sign['length'] + 2
        
        end_offset = sign_msg['offset']
        
        msgs_between = [msg for msg in all_messages
                       if start_offset <= msg['offset'] < end_offset
                       and msg['type'] != (0x27, 0x04)]
        
        # Хешируем ВСЕ ПОЛНЫЕ СООБЩЕНИЯ
        sha256_hasher = hashlib.sha256()
        for msg in msgs_between:
            sha256_hasher.update(msg['full_msg'])
        
        sha256_field_computed = sha256_hasher.digest()
        
        # Вычисляем z
        to_sign = sha256_field_computed + sessionId
        final_hash = hashlib.sha256(to_sign).digest()
        z_bytes = fold_sha256_to_192(final_hash)
        z = int.from_bytes(z_bytes, 'big')
        
        signatures.append({
            'r': r,
            's': s,
            'z': z,
            'r_bits': r.bit_length(),
            'msgs_count': len(msgs_between)
        })
    print(f"Загружено {len(signatures)} подписей из бинарного лога")


print(f"Подготовлено {len(signatures)} подписей с ПРАВИЛЬНЫМ z\n")

# Проверка консистентности d (если R=k)
print("Проверка гипотезы R=k...")
d_values = []
for i, sig in enumerate(signatures[:10]):
    k = sig['r']
    r_inv = inverse_mod(sig['r'], ORDER)
    d = ((sig['s'] * k - sig['z']) * r_inv) % ORDER
    d_values.append(d)
    if i < 3:
        print(f"  Sig {i}: d = {hex(d)[:30]}...")

unique_d = len(set(d_values))
if unique_d == 1:
    print(f"\n✓✓✓ Найден единственный ключ: {hex(d_values[0])}")
    exit(0)
else:
    print(f"\nУникальных d: {unique_d}/10 - гипотеза R=k неверна\n")

# LATTICE ATTACK
print("="*60)
print("ЗАПУСК LATTICE ATTACK С ПРАВИЛЬНЫМ z")
print("="*60)

# Сортируем по r (для MSB bias)
signatures.sort(key=lambda x: x['r'])

# Конфигурации для перебора
for n_sigs in [30, 50, 80, 100, 120]:
    for bits_bias in range(183, 193):
        sigs = signatures[:n_sigs]
        
        print(f"\r[{n_sigs} sigs, bias={192-bits_bias} bits (bound 2^{bits_bias})]", end='', flush=True)
        
        n = ORDER
        m = len(sigs)
        B = 2**bits_bias
        
        # Вычисляем t и u
        t = []
        u = []
        for sig in sigs:
            s_inv = inverse_mod(sig['s'], n)
            t_val = (s_inv * sig['r']) % n
            u_val = (s_inv * sig['z']) % n
            t.append(t_val)
            u.append(u_val)
        
        # Создаем матрицу
        M = IntegerMatrix(m + 2, m + 2)
        
        for i in range(m):
            M[i, i] = B * n
        for i in range(m):
            M[m, i] = t[i] * B
        M[m, m] = 1
        for i in range(m):
            M[m+1, i] = u[i] * B
        M[m+1, m+1] = B
        
        # BKZ
        BKZ.reduction(M, BKZ.Param(block_size=20))
        
        # Анализ
        for i in range(M.nrows):
            row = M[i]
            last_val = row[m+1]
            
            if abs(abs(last_val) - B) > B * 0.1:
                continue
            
            d_val = -row[m] if last_val < 0 else row[m]
            d_candidate = d_val % n
            
            if d_candidate == 0 or d_candidate >= n - 100:
                continue
            
            # Проверка
            valid = True
            for j in range(m):
                k_calc = (t[j] * d_candidate + u[j]) % n
                if k_calc.bit_length() > 193:
                    valid = False
                    break
            
            if valid:
                print(f"\n\n{'='*60}")
                print("✓✓✓ ПРИВАТНЫЙ КЛЮЧ НАЙДЕН ✓✓✓")
                print(f"{'='*60}")
                print(f"d = {hex(d_candidate)}")
                print(f"\nКонфигурация: {n_sigs} подписей, bound 2^{bits_bias}")
                print(f"{'='*60}")
                exit(0)

print("\n\nЛаттайс атака не дала результатов с текущими параметрами.")
