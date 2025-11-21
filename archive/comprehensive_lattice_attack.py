#!/usr/bin/env python3
"""
ОСНОВАТЕЛЬНЫЙ LATTICE ATTACK - ДЛИТЕЛЬНЫЙ ПОИСК (2+ ЧАСА)

Стратегия:
1. Используем ВСЕ 524 подписи
2. BKZ block sizes: 20, 30, 40, 50
3. Bias range: 2^175 - 2^192 (широкий диапазон)
4. Прогрессивное увеличение сложности
"""

import csv
import struct
import hashlib
import time
from fpylll import IntegerMatrix, BKZ
from datetime import datetime

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

def load_signatures():
    """Загружает ВСЕ подписи с правильным z"""
    print("Загружаем UBX сообщения...")
    all_messages = read_ubx_messages('log_ublox_big.bin')
    sign_messages = [msg for msg in all_messages if msg['type'] == (0x27, 0x04)]
    
    print(f"Найдено {len(sign_messages)} SEC-SIGN сообщений")
    
    signatures = []
    
    for idx in range(len(sign_messages)):
        sign_msg = sign_messages[idx]
        
        # Извлекаем R, S, SessionID
        sign_offset = sign_msg['offset']
        sign_payload_start = sign_offset + 6
        
        with open('log_ublox_big.bin', 'rb') as f:
            f.seek(sign_payload_start)
            payload = f.read(sign_msg['length'])
        
        sessionId = payload[36:60]
        r = int.from_bytes(payload[60:84], 'big')
        s = int.from_bytes(payload[84:108], 'big')
        
        # Находим сообщения между подписями
        if idx == 0:
            start_offset = 0
        else:
            prev_sign = sign_messages[idx - 1]
            start_offset = prev_sign['offset'] + 6 + prev_sign['length'] + 2
        
        end_offset = sign_msg['offset']
        
        msgs_between = [msg for msg in all_messages
                       if start_offset <= msg['offset'] < end_offset
                       and msg['type'] != (0x27, 0x04)]
        
        # Вычисляем SHA256_field
        sha256_hasher = hashlib.sha256()
        for msg in msgs_between:
            sha256_hasher.update(msg['full_msg'])
        
        sha256_field = sha256_hasher.digest()
        
        # Вычисляем z
        to_sign = sha256_field + sessionId
        final_hash = hashlib.sha256(to_sign).digest()
        z_bytes = fold_sha256_to_192(final_hash)
        z = int.from_bytes(z_bytes, 'big')
        
        signatures.append({
            'r': r,
            's': s,
            'z': z,
            'r_bits': r.bit_length()
        })
    
    return signatures

def lattice_attack_single(sigs, bits_bias, block_size):
    """Одна попытка Lattice Attack"""
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
    
    # BKZ Reduction
    BKZ.reduction(M, BKZ.Param(block_size=block_size, max_loops=20))
    
    # Анализ результатов
    for i in range(min(10, M.nrows)):  # Проверяем первые 10 строк
        row = M[i]
        last_val = row[m+1]
        
        if abs(abs(last_val) - B) > B * 0.2:
            continue
        
        d_val = -row[m] if last_val < 0 else row[m]
        d_candidate = d_val % n
        
        if d_candidate == 0 or d_candidate >= n - 100:
            continue
        
        # Проверка на всех подписях
        valid_count = 0
        max_k_bits = 0
        
        for j in range(m):
            k_calc = (t[j] * d_candidate + u[j]) % n
            k_bits = k_calc.bit_length()
            max_k_bits = max(max_k_bits, k_bits)
            
            if k_bits <= 192:
                valid_count += 1
        
        # Если больше 80% подписей дают разумный k
        if valid_count >= m * 0.8:
            return d_candidate, max_k_bits, valid_count
    
    return None, None, None

def main():
    print("="*70)
    print(" ОСНОВАТЕЛЬНЫЙ LATTICE ATTACK - ДЛИТЕЛЬНЫЙ ПОИСК ".center(70))
    print("="*70)
    print(f"\nВремя начала: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Загружаем ВСЕ подписи
    all_signatures = load_signatures()
    print(f"\nЗагружено {len(all_signatures)} подписей с правильным z\n")
    
    # Сортируем по r (для MSB bias)
    all_signatures.sort(key=lambda x: x['r'])
    
    print("="*70)
    print("Конфигурация поиска:")
    print("="*70)
    print(f"Подписей: от 50 до {len(all_signatures)}")
    print(f"Bias range: 2^175 - 2^192 (17 бит range)")
    print(f"BKZ block sizes: 20, 30, 40, 50")
    print(f"Примерное время: 2-4 часа")
    print("="*70)
    print()
    
    # Конфигурации для перебора (от простых к сложным)
    configs = []
    
    # Этап 1: Быстрый поиск с малым количеством подписей
    for n_sigs in [50, 80, 100]:
        for bits in range(180, 193):
            configs.append((n_sigs, bits, 20))
    
    # Этап 2: Средние параметры
    for n_sigs in [120, 150, 180]:
        for bits in range(175, 193):
            configs.append((n_sigs, bits, 30))
    
    # Этап 3: Агрессивный поиск
    for n_sigs in [200, 250, 300]:
        for bits in range(175, 193):
            configs.append((n_sigs, bits, 40))
    
    # Этап 4: Максимальная мощность
    for n_sigs in [350, 400, 450, 500, 524]:
        for bits in range(175, 193):
            configs.append((n_sigs, bits, 50))
    
    total_configs = len(configs)
    print(f"Всего конфигураций для проверки: {total_configs}\n")
    
    start_time = time.time()
    
    for idx, (n_sigs, bits_bias, block_size) in enumerate(configs, 1):
        elapsed = time.time() - start_time
        avg_time_per_config = elapsed / idx if idx > 1 else 0
        remaining = (total_configs - idx) * avg_time_per_config
        
        print(f"\r[{idx}/{total_configs}] "
              f"sigs={n_sigs:3d}, bound=2^{bits_bias}, BKZ={block_size} | "
              f"Прошло: {int(elapsed//60)}m, Осталось: ~{int(remaining//60)}m",
              end='', flush=True)
        
        sigs = all_signatures[:n_sigs]
        
        d, max_k, valid = lattice_attack_single(sigs, bits_bias, block_size)
        
        if d is not None:
            print(f"\n\n{'='*70}")
            print("✓✓✓ ПРИВАТНЫЙ КЛЮЧ НАЙДЕН! ✓✓✓".center(70))
            print(f"{'='*70}")
            print(f"\nКонфигурация:")
            print(f"  Подписей: {n_sigs}")
            print(f"  Bias bound: 2^{bits_bias}")
            print(f"  BKZ block size: {block_size}")
            print(f"\nРезультат:")
            print(f"  d = {hex(d)}")
            print(f"\nПроверка:")
            print(f"  Max k bits: {max_k}")
            print(f"  Валидных подписей: {valid}/{n_sigs} ({100*valid/n_sigs:.1f}%)")
            print(f"\n{'='*70}")
            print(f"Время поиска: {int((time.time()-start_time)//60)} минут")
            print(f"{'='*70}\n")
            return
    
    elapsed = time.time() - start_time
    print(f"\n\n{'='*70}")
    print(f"Поиск завершен без результата")
    print(f"Время: {int(elapsed//3600)}ч {int((elapsed%3600)//60)}м")
    print(f"Проверено конфигураций: {total_configs}")
    print(f"{'='*70}")
    print("\nВозможные причины:")
    print("1. Bias в k отсутствует или слишком слаб")
    print("2. Требуется больше подписей (2000+)")
    print("3. Нужен BKZ с еще большим block size (60-80)")
    print("4. u-blox использует криптографически стойкий RNG")

if __name__ == "__main__":
    main()
