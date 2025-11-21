#!/usr/bin/env python3
"""
Решение HNP для u-blox UBX-SEC-ECSIGN на основе информации из README.md

Ключевые находки:
1. Используется кривая SECP192R1 (а не SECP256R1!)
2. SHA256 хеш сворачивается в 192 бита через XOR:
   for(int i=0; i<8; i++) sha[i] ^= sha[i + 24];
3. Подпись (R, S) имеет длину 24 байта каждая (192 бита)
4. Хешируется весь поток передачи, кроме самого UBX-SEC-ECSIGN
"""

import csv
import hashlib
from ecdsa.curves import NIST192p
from ecdsa import VerifyingKey, SigningKey
import sys

CURVE = NIST192p
ORDER = CURVE.order

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    """
    Сворачивает 256-битный SHA256 хеш в 192 бита путем XOR
    sha[i] ^= sha[i + 24] для i в [0, 7]
    """
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def analyze_signatures():
    """Анализ подписей с новым пониманием формата"""
    print("Анализ UBX-SEC-ECSIGN подписей")
    print("=" * 60)
    print(f"Кривая: SECP192R1")
    print(f"Порядок: {hex(ORDER)}")
    print()
    
    sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            payload_hex = row['full_payload_hex']
            
            # Проверка длины R и S
            r_bits = r.bit_length()
            s_bits = s.bit_length()
            
            sigs.append({
                'r': r,
                's': s,
                'r_bits': r_bits,
                's_bits': s_bits,
                'payload': payload_hex
            })
    
    print(f"Всего подписей: {len(sigs)}")
    
    # Статистика длин
    r_lens = [s['r_bits'] for s in sigs]
    s_lens = [s['s_bits'] for s in sigs]
    
    print(f"\nДлины R: min={min(r_lens)}, max={max(r_lens)}, avg={sum(r_lens)/len(r_lens):.1f}")
    print(f"Длины S: min={min(s_lens)}, max={max(s_lens)}, avg={sum(s_lens)/len(s_lens):.1f}")
    
    # Ожидаем ~192 бита для SECP192R1
    if max(r_lens) <= 192 and max(s_lens) <= 192:
        print("\n✓ Длины R и S соответствуют SECP192R1 (192 бита)")
    else:
        print("\n✗ Длины не соответствуют SECP192R1!")
        print("  Возможно, в экспорте были обрезаны старшие байты")
    
    # Проверка структуры payload
    print("\nАнализ структуры payload:")
    for i, sig in enumerate(sigs[:3]):
        payload = bytes.fromhex(sig['payload'])
        print(f"\nПодпись #{i}:")
        print(f"  Длина payload: {len(payload)} байт")
        
        if len(payload) >= 108:  # 0x6C как в примере
            version = payload[0:2]
            pkt_count = int.from_bytes(payload[2:4], 'little')
            sha256_part = payload[4:36]
            session_id = payload[36:60]
            signature = payload[60:108]  # 48 bytes = 24 (R) + 24 (S)
            
            print(f"  Version: {version.hex()}")
            print(f"  Packet Count: {pkt_count}")
            print(f"  SHA256: {sha256_part.hex()}")
            print(f"  Session ID: {session_id.hex()}")
            print(f"  Signature: {signature.hex()}")
            
            # Проверка: R и S из signature должны совпадать с CSV
            r_from_sig = int.from_bytes(signature[0:24], 'big')
            s_from_sig = int.from_bytes(signature[24:48], 'big')
            
            print(f"\n  R из payload: {hex(r_from_sig)}")
            print(f"  R из CSV:     {hex(sig['r'])}")
            print(f"  Совпадение R: {r_from_sig == sig['r']}")
            
            print(f"\n  S из payload: {hex(s_from_sig)}")
            print(f"  S из CSV:     {hex(sig['s'])}")
            print(f"  Совпадение S: {s_from_sig == sig['s']}")

def test_key_recovery_direct():
    """
    Тестовая проверка восстановления ключа, если мы знаем формат
    
    По README: хешируется весь поток, кроме UBX-SEC-ECSIGN.
    Но в нашем случае у нас только сами сообщения UBX-SEC-ECSIGN.
    
    Попробуем вариант: хешируется payload[0:60] (версия + счетчик + SHA256 + SessionID)
    """
    print("\n" + "=" * 60)
    print("Попытка восстановления ключа (прямой метод)")
    print("=" * 60)
    
    sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            # Попытка 1: хешируем payload[0:60] (до подписи)
            if len(payload) >= 108:
                msg = payload[0:60]
                h = hashlib.sha256(msg).digest()
                # Сворачиваем в 192 бита
                h_folded = fold_sha256_to_192(h)
                z = int.from_bytes(h_folded, 'big')
                
                sigs.append({'r': r, 's': s, 'z': z, 'msg': msg.hex()})
    
    if len(sigs) < 2:
        print("Недостаточно подписей для анализа")
        return
    
    print(f"Обработано подписей: {len(sigs)}")
    
    # Гипотеза: R содержит k
    print("\nГипотеза: R = k (nonce)")
    candidates = []
    
    n = ORDER
    G = CURVE.generator
    
    for sig in sigs[:5]:
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
            print(f"  Кандидат d: {hex(d)}")
        except Exception as e:
            print(f"  Ошибка: {e}")
            continue
    
    # Проверка консистентности
    if candidates:
        from collections import Counter
        common = Counter(candidates).most_common(1)
        if common:
            d_final, count = common[0]
            print(f"\n{'='*60}")
            if count > 1:
                print(f"✓ УСПЕХ! Найден консистентный приватный ключ!")
                print(f"  Приватный ключ: {hex(d_final)}")
                print(f"  Консистентность: {count}/{len(candidates)}")
                return d_final
            else:
                print(f"✗ Не найдено консистентного ключа")
                print(f"  Все кандидаты различны")

if __name__ == "__main__":
    analyze_signatures()
    test_key_recovery_direct()
