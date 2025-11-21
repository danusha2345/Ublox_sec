#!/usr/bin/env python3
"""
ОПТИМИЗИРОВАННАЯ LATTICE ATTACK с выбором лучших подписей

Стратегия: выбираем подписи с минимальными R (самый сильный bias)
"""

import csv
import hashlib
from mpmath import mp
from ecdsa.curves import NIST192p

mp.dps = 500

CURVE = NIST192p
ORDER = CURVE.order
BASIS_SIZE = 30  # Увеличим до 30 подписей

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

def create_matrix(rows, cols):
    return [[mp.mpf(0)] * cols for _ in range(rows)]

def dot_product(v1, v2):
    return sum(x * y for x, y in zip(v1, v2))

def gram_schmidt(basis):
    n = len(basis)
    m = len(basis[0])
    ortho = [[mp.mpf(x) for x in row] for row in basis]
    mu = [[mp.mpf(0)] * n for _ in range(n)]
    
    for i in range(n):
        for j in range(i):
            dot_val = dot_product(basis[i], ortho[j])
            norm_sq = dot_product(ortho[j], ortho[j])
            if norm_sq == 0:
                mu[i][j] = mp.mpf(0)
            else:
                mu[i][j] = dot_val / norm_sq
            
            for k in range(m):
                ortho[i][k] -= mu[i][j] * ortho[j][k]
    return ortho, mu

def lll_reduction(basis, delta=0.99):
    n = len(basis)
    m = len(basis[0])
    ortho, mu = gram_schmidt(basis)
    k = 1
    
    iterations = 0
    max_iterations = 15000  # Увеличили лимит
    
    while k < n and iterations < max_iterations:
        iterations += 1
        
        if iterations % 1000 == 0:
            print(f"  LLL итерация {iterations}...")
        
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = int(round(float(mu[k][j])))
                for l in range(m):
                    basis[k][l] -= q * basis[j][l]
                ortho, mu = gram_schmidt(basis)
        
        norm_sq_k = dot_product(ortho[k], ortho[k])
        norm_sq_k_1 = dot_product(ortho[k-1], ortho[k-1])
        
        if norm_sq_k >= (delta - mu[k][k-1]**2) * norm_sq_k_1:
            k += 1
        else:
            basis[k], basis[k-1] = basis[k-1], basis[k]
            ortho, mu = gram_schmidt(basis)
            k = max(k - 1, 1)
    
    print(f"  LLL завершен за {iterations} итераций")
    return basis

def solve_hnp_optimized():
    print("="*60)
    print("ОПТИМИЗИРОВАННАЯ LATTICE ATTACK")
    print("="*60)
    
    # Загружаем ВСЕ подписи
    all_sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            if len(payload) < 108:
                continue
            
            sha256_field = payload[4:36]
            session_id = payload[36:60]
            sig = payload[60:108]
            
            r_bytes = sig[0:24]
            s_bytes = sig[24:48]
            
            r = int.from_bytes(r_bytes, 'big')
            s = int.from_bytes(s_bytes, 'big')
            
            # z ПРАВИЛЬНО
            msg = sha256_field + session_id
            h = hashlib.sha256(msg).digest()
            z_folded = fold_sha256_to_192(h)
            z = int.from_bytes(z_folded, 'big')
            
            all_sigs.append({'r': r, 's': s, 'z': z, 'r_bits': r.bit_length()})
    
    print(f"Загружено всего подписей: {len(all_sigs)}")
    
    # Сортируем по R (берем smallest R - самый сильный bias)
    all_sigs.sort(key=lambda x: x['r'])
    
    # Берем первые BASIS_SIZE
    sigs = all_sigs[:BASIS_SIZE]
    
    print(f"Используем {len(sigs)} подписей с минимальными R")
    r_lens = [s['r_bits'] for s in sigs]
    print(f"Длины R: min={min(r_lens)}, max={max(r_lens)}, avg={sum(r_lens)/len(r_lens):.1f}")
    print()
    
    n = ORDER
    m = len(sigs)
    
    # Вычисляем t_i и u_i
    t = []
    u = []
    for sig in sigs:
        s_inv = inverse_mod(sig['s'], n)
        t_val = (s_inv * sig['r']) % n
        u_val = (s_inv * sig['z']) % n
        t.append(t_val)
        u.append(u_val)
    
    print("Построение решетки...")
    
    # Используем более консервативный bound
    # Судя по статистике, есть подписи с 185-190 бит
    B = 2**191  # Берем bound 2^191
    
    print(f"Bound: 2^191")
    print(f"Размер матрицы: {m+2} x {m+2}\n")
    
    # Матрица
    rows = []
    
    for i in range(m):
        row = [mp.mpf(0)] * (m + 2)
        row[i] = mp.mpf(B * n)
        rows.append(row)
    
    row_t = [mp.mpf(t[i] * B) for i in range(m)] + [mp.mpf(1), mp.mpf(0)]
    rows.append(row_t)
    
    row_u = [mp.mpf(u[i] * B) for i in range(m)] + [mp.mpf(0), mp.mpf(B)]
    rows.append(row_u)
    
    print("Запуск LLL редукции...\n")
    
    reduced_basis = lll_reduction(rows)
    
    print("\nАнализ редуцированного базиса...")
    
    candidates = []
    
    for i, row in enumerate(reduced_basis):
        last_val = int(round(float(row[m+1])))
        
        if abs(abs(last_val) - B) > B * 0.01:
            continue
        
        if last_val < 0:
            row = [-x for x in row]
            last_val = -last_val
        
        d_candidate = int(round(float(row[m]))) % n
        
        if d_candidate == 0 or d_candidate == n:
            continue
        
        print(f"\nВектор #{i}:")
        print(f"  d: {hex(d_candidate)[:50]}...")
        
        # Проверяем k для ВСЕХ подписей
        k_values = []
        for j in range(m):
            k_calc = (t[j] * d_candidate + u[j]) % n
            k_values.append(k_calc.bit_length())
        
        k_min = min(k_values)
        k_max = max(k_values)
        k_avg = sum(k_values) / len(k_values)
        
        print(f"  k: min={k_min}, max={k_max}, avg={k_avg:.1f} бит")
        
        if k_max <= 192:
            candidates.append((d_candidate, k_max, k_avg, i))
    
    if candidates:
        candidates.sort(key=lambda x: x[2])
        
        print(f"\n{'='*60}")
        print(f"✓✓✓ НАЙДЕНО КАНДИДАТОВ: {len(candidates)}")
        print(f"{'='*60}\n")
        
        for d_cand, k_max, k_avg, idx in candidates[:3]:
            print(f"Кандидат #{idx}:")
            print(f"  d: {hex(d_cand)}")
            print(f"  k: max={k_max}, avg={k_avg:.1f}")
            
            G = CURVE.generator
            Pub = d_cand * G
            print(f"  Pub.x: {hex(Pub.x())}")
            print()
        
        return candidates[0][0]
    
    print("\nНе найдено подходящих векторов")
    return None

if __name__ == "__main__":
    solve_hnp_optimized()
