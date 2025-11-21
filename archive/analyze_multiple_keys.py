#!/usr/bin/env python3
"""
Проверка гипотезы: несколько приватных ключей или детерминированная генерация
"""

import csv
import hashlib
from ecdsa.curves import NIST192p
from collections import Counter, defaultdict

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

def recover_all_keys():
    """Восстанавливаем приватные ключи для всех подписей"""
    
    sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            if len(payload) < 108:
                continue
            
            # Извлекаем компоненты
            version = int.from_bytes(payload[0:2], 'little')
            pkt_count = int.from_bytes(payload[2:4], 'little')
            sha256_part = payload[4:36]
            session_id = payload[36:60]
            
            # Формируем z
            msg_to_sign = sha256_part + session_id
            z_hash = hashlib.sha256(msg_to_sign).digest()
            z_folded = fold_sha256_to_192(z_hash)
            z = int.from_bytes(z_folded, 'big')
            
            # Восстанавливаем d
            k = r
            if k == 0 or k >= ORDER:
                continue
                
            try:
                R_point = k * G
                r_coord = R_point.x()
                
                k_s = (k * s) % ORDER
                r_inv = inverse_mod(r_coord, ORDER)
                d = ((k_s - z) * r_inv) % ORDER
                
                sigs.append({
                    'idx': idx,
                    'r': r,
                    's': s,
                    'z': z,
                    'd': d,
                    'pkt_count': pkt_count,
                    'version': version,
                    'session_id': session_id.hex()
                })
            except:
                continue
    
    print(f"Восстановлено ключей: {len(sigs)}")
    
    # Анализ уникальных ключей
    d_values = [sig['d'] for sig in sigs]
    d_counter = Counter(d_values)
    
    print(f"\n{'='*60}")
    print("АНАЛИЗ УНИКАЛЬНЫХ ПРИВАТНЫХ КЛЮЧЕЙ")
    print(f"{'='*60}")
    print(f"Всего уникальных ключей: {len(d_counter)}")
    print(f"\nТоп-10 наиболее частых ключей:")
    for d_val, count in d_counter.most_common(10):
        print(f"  {hex(d_val)}: {count} раз")
    
    # Группируем по packet_count
    pkt_counts = defaultdict(list)
    for sig in sigs:
        pkt_counts[sig['pkt_count']].append(sig['d'])
    
    print(f"\n{'='*60}")
    print("АНАЛИЗ ПО PACKET COUNT")
    print(f"{'='*60}")
    for pkt_count, d_list in sorted(pkt_counts.items()):
        unique_d = len(set(d_list))
        print(f"Packet Count {pkt_count}: {len(d_list)} подписей, {unique_d} уникальных ключей")
    
    # Группируем по session_id
    session_ids = defaultdict(list)
    for sig in sigs:
        session_ids[sig['session_id']].append(sig['d'])
    
    print(f"\n{'='*60}")
    print("АНАЛИЗ ПО SESSION ID")
    print(f"{'='*60}")
    for session_id, d_list in sorted(session_ids.items()):
        unique_d = len(set(d_list))
        print(f"Session ID {session_id[:16]}...: {len(d_list)} подписей, {unique_d} уникальных ключей")
        if unique_d == 1:
            print(f"  ✓ Постоянный ключ: {hex(d_list[0])}")
    
    # Проверяем временную последовательность
    print(f"\n{'='*60}")
    print("ВРЕМЕННАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ (первые 10)")
    print(f"{'='*60}")
    for sig in sigs[:10]:
        print(f"#{sig['idx']:3d} PktCnt={sig['pkt_count']:3d} d={hex(sig['d'])[:20]}...")

if __name__ == "__main__":
    recover_all_keys()
