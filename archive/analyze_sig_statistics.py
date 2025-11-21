#!/usr/bin/env python3
"""
КРИТИЧЕСКАЯ ГИПОТЕЗА:

Мы видим, что поле R в подписи НЕ является k или r=(k*G).x.
НО что если в UBX-SEC-ECSIGN используется схема, где:

1. В поле "R" (первые 24 байта подписи) хран ится дополнительная информация
   (например, counter, session data, или часть хеша)

2. Настоящая подпись (r, s) вычисляется по-другому

Давайте попробуем рассмотреть 48 байт "подписи" как:
- Вариант A: Первые 24 байта = какой-то хеш/nonce, вторые 24 = подпись
- Вариант B: Это вообще не ECDSA подпись, а какая-то другая схема
- Вариант C: Подпись зашифрована или обфусцирована

Проверим статистические свойства этих 48 байт.
"""

import csv
import hashlib
from collections import Counter
import struct

def analyze_signature_bytes():
    """Статистический анализ байтов подписи"""
    
    all_signatures = []
    
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r_hex = row['r_hex']
            s_hex = row['s_hex']
            
            r_bytes = bytes.fromhex(r_hex)
            s_bytes = bytes.fromhex(s_hex)
            
            full_sig = r_bytes + s_bytes
            all_signatures.append({
                'r_bytes': r_bytes,
                's_bytes': s_bytes,
                'full': full_sig
            })
    
    print("="*60)
    print(f"СТАТИСТИЧЕСКИЙ АНАЛИЗ {len(all_signatures)} ПОДПИСЕЙ")
    print("="*60)
    
    # Анализ первого байта R
    first_byte_r = [sig['r_bytes'][0] for sig in all_signatures]
    print(f"\nПервый байт R:")
    for byte_val, count in Counter(first_byte_r).most_common(10):
        print(f"  0x{byte_val:02X}: {count} раз")
    
    # Анализ последнего байта S
    last_byte_s = [sig['s_bytes'][-1] for sig in all_signatures]
    print(f"\nПоследний байт S:")
    for byte_val, count in Counter(last_byte_s).most_common(10):
        print(f"  0x{byte_val:02X}: {count} раз")
    
    # Проверяем, нет ли фиксированных байтов
    print(f"\nПроверка фиксированных позиций:")
    for pos in range(24):
        bytes_at_pos_r = [sig['r_bytes'][pos] for sig in all_signatures]
        unique_r = len(set(bytes_at_pos_r))
        
        bytes_at_pos_s = [sig['s_bytes'][pos] for sig in all_signatures]
        unique_s = len(set(bytes_at_pos_s))
        
        if unique_r < 10:
            print(f"  R[{pos}]: только {unique_r} уникальных значений")
            print(f"    Топ: {Counter(bytes_at_pos_r).most_common(3)}")
        
        if unique_s < 10:
            print(f"  S[{pos}]: только {unique_s} уникальных значений")
            print(f"    Топ: {Counter(bytes_at_pos_s).most_common(3)}")
    
    # Проверяем энтропию
    print(f"\nЭнтропия (приблизительно):")
    
    all_r_bytes = b''.join(sig['r_bytes'] for sig in all_signatures)
    all_s_bytes = b''.join(sig['s_bytes'] for sig in all_signatures)
    
    r_entropy = len(set(all_r_bytes)) / 256.0
    s_entropy = len(set(all_s_bytes)) / 256.0
    
    print(f"  R: {r_entropy:.2%} (используется {len(set(all_r_bytes))}/256 возможных значений)")
    print(f"  S: {s_entropy:.2%} (используется {len(set(all_s_bytes))}/256 возможных значений)")
    
    # Проверяем, может это counter или timestamp?
    print(f"\nПроверка на монотонность (counter/timestamp):")
    
    # Интерпретируем R как little-endian integer
    r_as_int_le = [int.from_bytes(sig['r_bytes'], 'little') for sig in all_signatures]
    r_as_int_be = [int.from_bytes(sig['r_bytes'], 'big') for sig in all_signatures]
    
    # Проверяем, возрастает ли
    le_increasing = all(r_as_int_le[i] <= r_as_int_le[i+1] for i in range(len(r_as_int_le)-1))
    be_increasing = all(r_as_int_be[i] <= r_as_int_be[i+1] for i in range(len(r_as_int_be)-1))
    
    print(f"  R как LE integer возрастает: {le_increasing}")
    print(f"  R как BE integer возрастает: {be_increasing}")
    
    if not le_increasing and not be_increasing:
        # Проверяем разницы
        le_diffs = [r_as_int_le[i+1] - r_as_int_le[i] for i in range(len(r_as_int_le)-1)]
        be_diffs = [r_as_int_be[i+1] - r_as_int_be[i] for i in range(len(r_as_int_be)-1)]
        
        print(f"\n  Первые 10 разниц (LE): {le_diffs[:10]}")
        print(f"  Первые 10 разниц (BE): {be_diffs[:10]}")
    
    # Проверяем связь R и S
    print(f"\nПроверка связи R и S:")
    
    # XOR первых байтов
    xor_first = [sig['r_bytes'][0] ^ sig['s_bytes'][0] for sig in all_signatures]
    print(f"  XOR первых байтов:")
    for val, count in Counter(xor_first).most_common(5):
        print(f"    0x{val:02X}: {count} раз")
    
    # Корреляция длин
    r_lens = [r.bit_length() for r in r_as_int_be]
    s_lens = [int.from_bytes(sig['s_bytes'], 'big').bit_length() for sig in all_signatures]
    
    print(f"\n  Длины R: min={min(r_lens)}, max={max(r_lens)}, avg={sum(r_lens)/len(r_lens):.1f}")
    print(f"  Длины S: min={min(s_lens)}, max={max(s_lens)}, avg={sum(s_lens)/len(s_lens):.1f}")

def check_payload_correlation():
    """Проверяем корреляцию между payload и подписью"""
    
    print(f"\n{'='*60}")
    print("КОРРЕЛЯЦИЯ PAYLOAD И ПОДПИСИ")
    print("="*60)
    
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        
        for i, row in enumerate(reader):
            if i >= 5:  # Только первые 5
                break
                
            r_hex = row['r_hex']
            s_hex = row['s_hex']
            payload_hex = row['full_payload_hex']
            
            payload = bytes.fromhex(payload_hex)
            
            # Извлекаем компоненты
            version = payload[0:2]
            pkt_count = payload[2:4]
            sha256_field = payload[4:36]
            session_id = payload[36:60]
            
            print(f"\nПодпись #{i}:")
            print(f"  Version: {version.hex()}")
            print(f"  PktCount: {int.from_bytes(pkt_count, 'little')}")
            print(f"  SHA256: {sha256_field[:8].hex()}...")
            print(f"  SessionID: {session_id.hex()}")
            print(f"  R: {r_hex[:16]}...")
            print(f"  S: {s_hex[:16]}...")
            
            # Проверяем, может R или S содержат части payload?
            r_bytes = bytes.fromhex(r_hex)
            s_bytes = bytes.fromhex(s_hex)
            
            # Проверка на совпадение подстрок
            if sha256_field[:12] in r_bytes or sha256_field[:12] in s_bytes:
                print(f"  ⚠ SHA256 prefix найден в подписи!")
            
            if session_id[:12] in r_bytes or session_id[:12] in s_bytes:
                print(f"  ⚠ SessionID prefix найден в подписи!")

if __name__ == "__main__":
    analyze_signature_bytes()
    check_payload_correlation()
