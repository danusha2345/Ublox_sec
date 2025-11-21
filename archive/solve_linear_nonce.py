#!/usr/bin/env python3
"""
АТАКА НА ЛИНЕЙНЫЙ NONCE (Linear Nonce Attack)

Проверяет гипотезу: k_i = k_base + C * packet_count_i
где C - небольшая константа (обычно 1).

Если это так, мы можем восстановить d алгебраически, используя всего 2 подписи.
"""

import hashlib
import struct
import sys

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

def load_signatures_with_z():
    # Копируем логику из correct_z_lattice_attack.py
    # Для краткости, здесь упрощенная версия, предполагающая наличие log_ublox_big.bin
    
    print("Загрузка и вычисление z...")
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
            
            # Checksum verify (skip for speed if trusted)
            
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
        packet_count = struct.unpack('<H', payload[4:6])[0]
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
        
        signatures.append({'r': r, 's': s, 'z': z, 'pc': packet_count})
        
    return signatures

def solve_linear(sig1, sig2, C=1):
    # s1 * (k0 + C*pc1) = z1 + r1 * d
    # s2 * (k0 + C*pc2) = z2 + r2 * d
    
    # d * (r1*s2 - r2*s1) = z2*s1 - z1*s2 + s1*s2*C*(pc1 - pc2)
    
    denom = (sig1['r'] * sig2['s'] - sig2['r'] * sig1['s']) % n
    if denom == 0: return None
    
    num = (sig2['z'] * sig1['s'] - sig1['z'] * sig2['s'] + 
           sig1['s'] * sig2['s'] * C * (sig1['pc'] - sig2['pc'])) % n
           
    d = (num * inverse_mod(denom, n)) % n
    return d

def main():
    sigs = load_signatures_with_z()
    print(f"Загружено {len(sigs)} подписей.")
    
    print("\nПроверка гипотезы k_i = k_base + C * packet_count_i")
    
    for C in [1, 2, -1, -2, 256, 65537]: # Возможные множители
        print(f"  Проверка C = {C}...")
        
        # Берем пары подписей
        d_candidates = []
        for i in range(len(sigs) - 1):
            d = solve_linear(sigs[i], sigs[i+1], C)
            if d:
                d_candidates.append(d)
                
        # Проверяем, есть ли повторяющиеся d
        from collections import Counter
        counts = Counter(d_candidates)
        most_common = counts.most_common(1)
        
        if most_common and most_common[0][1] > 5:
            d_found = most_common[0][0]
            print(f"\n!!! НАЙДЕН КАНДИДАТ !!!")
            print(f"C = {C}")
            print(f"d = {hex(d_found)}")
            print(f"Подтверждено {most_common[0][1]} парами.")
            
            # Проверка k
            k0 = (inverse_mod(sigs[0]['s'], n) * (sigs[0]['z'] + sigs[0]['r'] * d_found)) % n
            print(f"k0 = {hex(k0)}")
            return
            
    print("\nГипотеза линейного nonce не подтвердилась.")

if __name__ == "__main__":
    main()
