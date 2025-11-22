#!/usr/bin/env sage
import csv
import hashlib
import os
import random as py_random
import time
import multiprocessing
from sage.all import *

# =============================================================================
# КОНФИГУРАЦИЯ
# =============================================================================
WORKERS = 10           # Количество параллельных процессов
SUBSET_SIZE = 90       # Размер решетки (достаточно для сильной утечки)
TOP_SIGS = 120         # Берем только самые лучшие (концентрат)
BLOCK_SIZES = [20, 30, 40, 50, 60] # Этапы BKZ
# =============================================================================

# SECP192R1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

E = EllipticCurve(GF(p), [a, b])
G = E.point((Gx, Gy))
order = Integer(n)

def load_signatures():
    all_sigs = []
    filename = 'sigs_combined.csv' if os.path.exists('sigs_combined.csv') else 'sigs_new.csv'
    print(f"Загрузка из {filename}...")
    
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r = Integer(int(row['r']))
            all_sigs.append({
                'r': r,
                's': Integer(int(row['s'])),
                'z': Integer(int(row['z'])),
                'r_bits': r.nbits()
            })
    
    # Сортируем и берем топ
    all_sigs.sort(key=lambda x: x['r']) # ВКЛЮЧЕНО: Bias в r подтвержден FFT!
    print(f"Всего подписей: {len(all_sigs)}")
    print(f"Используем КОНЦЕНТРАТ из топ-{TOP_SIGS} лучших подписей")
    return all_sigs[:TOP_SIGS]

# Глобальная переменная для воркеров
sigs_pool = []

def worker_task(worker_id):
    # Инициализация RNG
    set_random_seed()
    
    # Выбираем случайное подмножество из ТОПА
    my_sigs = py_random.sample(sigs_pool, SUBSET_SIZE)
    
    # Строим решетку
    m = len(my_sigs)
    t_list = []
    u_list = []
    
    for sig in my_sigs:
        s_inv = inverse_mod(sig['s'], order)
        t_list.append((s_inv * sig['r']) % order)
        u_list.append((s_inv * sig['z']) % order)
    
    # Bound
    max_bits = max(s['r_bits'] for s in my_sigs)
    B = 2^(max_bits)
    
    rows = []
    for i in range(m):
        row = [0] * (m + 2)
        row[i] = B * order
        rows.append(row)
        
    rows.append([t_list[i] * B for i in range(m)] + [1, 0])
    rows.append([u_list[i] * B for i in range(m)] + [0, B])
    
    M = Matrix(ZZ, rows)
    
    print(f"[W{worker_id}] Старт LLL (bits={max_bits})...")
    M.LLL()
    
    res = check_solution(M, m, B, t_list, u_list, my_sigs)
    if res: return res
    
    for block in BLOCK_SIZES:
        print(f"[W{worker_id}] Старт BKZ-{block}...")
        M.BKZ(block_size=block)
        res = check_solution(M, m, B, t_list, u_list, my_sigs)
        if res: return res
        
    print(f"[W{worker_id}] Неудача.")
    return None

def check_solution(M, m, B, t_list, u_list, sigs):
    for i in range(M.nrows()):
        row = M[i]
        if abs(abs(row[m+1]) - B) > B//100: continue
        
        vec = row if row[m+1] > 0 else -row
        d_cand = Integer(vec[m]) % order
        if d_cand == 0: continue
        
        k0 = (t_list[0] * d_cand + u_list[0]) % order
        if k0.nbits() <= sigs[0]['r_bits'] + 5:
            Pub = d_cand * G
            r0 = sigs[0]['r']
            w = inverse_mod(sigs[0]['s'], order)
            u1 = (sigs[0]['z'] * w) % order
            u2 = (r0 * w) % order
            P = u1*G + u2*Pub
            if (Integer(P[0]) % order) == r0:
                return d_cand
    return None

def main():
    global sigs_pool
    sigs_pool = load_signatures()
    
    print(f"Запуск {WORKERS} процессов...")
    pool = multiprocessing.Pool(processes=WORKERS)
    tasks = range(WORKERS * 100)
    
    for result in pool.imap_unordered(worker_task, tasks):
        if result:
            print(f"\n{'='*60}")
            print(f"!!! КЛЮЧ НАЙДЕН !!!")
            print(f"Private Key: {hex(result)}")
            print(f"{'='*60}")
            with open('FOUND_KEY_FARM.txt', 'w') as f:
                f.write(hex(result))
            pool.terminate()
            return
            
    print("Все попытки исчерпаны.")

if __name__ == '__main__':
    main()
