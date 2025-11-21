#!/usr/bin/env python3
"""
АТАКА НА МАЛЫЕ NONCE (Small k Attack)

Проверяет гипотезу, что для некоторых подписей nonce k является малым числом.
Перебирает k от 1 до 2^24 (16 миллионов) для каждой подписи.
Если k найдено, вычисляет d и проверяет на других подписях.
"""

import hashlib
import struct
import sys
from concurrent.futures import ProcessPoolExecutor

# SECP192R1
n = 0xFFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC2369B7

def inverse_mod(k, p):
    if k == 0: raise ZeroDivisionError("division by zero")
    if k < 0: return p - inverse_mod(-k, p)
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_s % p

def fold_sha256_to_192(digest):
    folded = bytearray(digest[:24])
    for i in range(8):
        folded[i] ^= digest[24 + i]
    return bytes(folded)

def load_signatures():
    # Упрощенная загрузка (предполагаем наличие log_ublox_big.bin)
    print("Загрузка подписей...")
    with open('log_ublox_big.bin', 'rb') as f:
        data = f.read()
        
    messages = []
    i = 0
    while i < len(data) - 6:
        if data[i] == 0xB5 and data[i+1] == 0x62:
            msg_class = data[i+2]
            msg_id = data[i+3]
            length = struct.unpack('<H', data[i+4:i+6])[0]
            if i + 6 + length + 2 > len(data): break
            
            full_msg = data[i:i+6+length+2]
            payload = data[i+6:i+6+length]
            
            messages.append({
                'offset': i,
                'type': (msg_class, msg_id),
                'length': length,
                'full_msg': full_msg,
                'payload': payload
            })
            i += 6 + length + 2
        else:
            i += 1
            
    sign_msgs = [m for m in messages if m['type'] == (0x27, 0x04)]
    signatures = []
    
    for idx, msg in enumerate(sign_msgs):
        payload = msg['payload']
        sessionId = payload[36:60]
        r = int.from_bytes(payload[60:84], 'big')
        s = int.from_bytes(payload[84:108], 'big')
        
        if idx == 0: start = 0
        else: start = sign_msgs[idx-1]['offset'] + len(sign_msgs[idx-1]['full_msg'])
        end = msg['offset']
        
        msgs_between = [m for m in messages if start <= m['offset'] < end and m['type'] != (0x27, 0x04)]
        
        hasher = hashlib.sha256()
        for m in msgs_between: hasher.update(m['full_msg'])
        sha256_field = hasher.digest()
        
        to_sign = sha256_field + sessionId
        z = int.from_bytes(fold_sha256_to_192(hashlib.sha256(to_sign).digest()), 'big')
        
        signatures.append({'r': r, 's': s, 'z': z})
        
    return signatures

def check_signature(sig, max_k=1000000):
    # d = (s*k - z) * r^-1
    r_inv = inverse_mod(sig['r'], n)
    
    candidates = []
    for k in range(1, max_k):
        d = ((sig['s'] * k - sig['z']) * r_inv) % n
        # Простая эвристика: d не должно быть слишком маленьким (хотя может)
        candidates.append(d)
    return candidates

def main():
    sigs = load_signatures()
    print(f"Загружено {len(sigs)} подписей.")
    
    # Проверяем первые 10 подписей (если генератор сломался, то скорее всего в начале или везде)
    # Или выберем подписи с самыми маленькими R? Нет, R не зависит от k линейно.
    
    # Попробуем найти пересечение кандидатов d для первых двух подписей
    print("Поиск малых k (до 10^6)...")
    
    sig0 = sigs[0]
    sig1 = sigs[1]
    
    r0_inv = inverse_mod(sig0['r'], n)
    r1_inv = inverse_mod(sig1['r'], n)
    
    # Создаем множество кандидатов d для первой подписи
    print("Генерация кандидатов для Sig #0...")
    d_set = set()
    MAX_K = 2000000 # 2 миллиона
    
    for k in range(1, MAX_K):
        d = ((sig0['s'] * k - sig0['z']) * r0_inv) % n
        d_set.add(d)
        
    print(f"Сгенерировано {len(d_set)} кандидатов.")
    
    print("Проверка кандидатов для Sig #1...")
    for k in range(1, MAX_K):
        d = ((sig1['s'] * k - sig1['z']) * r1_inv) % n
        if d in d_set:
            print(f"\n!!! НАЙДЕНО ПЕРЕСЕЧЕНИЕ !!!")
            print(f"d = {hex(d)}")
            with open('FOUND_KEY_SMALL_K.txt', 'w') as f:
                f.write(hex(d))
            return
            
    print("\nМалые k не обнаружены.")

if __name__ == "__main__":
    main()
