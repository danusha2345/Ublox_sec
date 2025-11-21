#!/usr/bin/env python3
"""
МАКСИМАЛЬНАЯ Lattice Attack - использу ем ВСЕ лучшие подписи

Стратегия: выбрать 40-50 подписей с самыми малыми R (< 2^188)
"""

import csv
import hashlib
from mpmath import mp
from ecdsa.curves import NIST192p

mp.dps = 600  # Максимальная точность

CURVE = NIST192p
ORDER = CURVE.order
BASIS_SIZE = 40  # 40 подписей

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

# [Функции LLL - те же что и раньше]
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
    max_iterations = 20000
    
    while k < n and iterations < max_iterations:
        iterations += 1
        
        if iterations % 100 == 0:
            print(f'  LLL итерация {iterations}...')
        
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
    
    print(f'  LLL завершен за {iterations} итераций')
    return basis

print('='*60)
print('МАКСИМАЛЬНАЯ LATTICE ATTACK')
print('='*60)

# Загружаем ВСЕ подписи
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

print(f'Загружено {len(all_sigs)} подписей')

# Выбираем самые лучшие (минимальные R)
all_sigs.sort(key=lambda x: x['r'])
sigs = all_sigs[:BASIS_SIZE]

r_lens = [s['r_bits'] for s in sigs]
print(f'Используем {len(sigs)} подписей с минимальными R')
print(f'Длины R: min={min(r_lens)}, max={max(r_lens)}, avg={sum(r_lens)/len(r_lens):.1f}')

# Показываем топ-5
print(f'\\nТоп-5 минимальных R:')
for i in range(5):
    print(f'  #{i+1}: {sigs[i]["r_bits"]} бит - {hex(sigs[i]["r"])[:40]}...')

print()

n = ORDER
m = len(sigs)

# t и u
t = []
u = []
for sig in sigs:
    s_inv = inverse_mod(sig['s'], n)
    t_val = (s_inv * sig['r']) % n
    u_val = (s_inv * sig['z']) % n
    t.append(t_val)
    u.append(u_val)

print('Построение решетки...')

# Используем bound на основе минимального R
# Минимальный R имеет 185-187 бит
B = 2**188  # Консервативный bound

print(f'Bound: 2^188')
print(f'Размер матрицы: {m+2} x {m+2}')
print()

rows = []

for i in range(m):
    row = [mp.mpf(0)] * (m + 2)
    row[i] = mp.mpf(B * n)
    rows.append(row)

row_t = [mp.mpf(t[i] * B) for i in range(m)] + [mp.mpf(1), mp.mpf(0)]
rows.append(row_t)

row_u = [mp.mpf(u[i] * B) for i in range(m)] + [mp.mpf(0), mp.mpf(B)]
rows.append(row_u)

print('Запуск LLL редукции (может занять ДОЛГО)...\\n')

reduced_basis = lll_reduction(rows)

print('\\nАнализ редуцированного базиса...')

candidates = []

for i, row in enumerate(reduced_basis):
    last_val = int(round(float(row[m+1])))
    
    if abs(abs(last_val) - B) > B * 0.02:  # Допуск 2%
        continue
    
    if last_val < 0:
        row = [-x for x in row]
    
    d_candidate = int(round(float(row[m]))) % n
    
    if d_candidate == 0 or d_candidate >= n - 10:
        continue
    
    # Проверка
    k_values = []
    for j in range(m):
        k_calc = (t[j] * d_candidate + u[j]) % n
        k_values.append(k_calc.bit_length())
    
    k_max = max(k_values)
    k_avg = sum(k_values) / len(k_values)
    
    if k_max <= 192:
        print(f'\\nВектор #{i}: d = {hex(d_candidate)[:50]}...')
        print(f'  k: max={k_max}, avg={k_avg:.1f}')
        candidates.append((d_candidate, k_max, k_avg, i))

if candidates:
    candidates.sort(key=lambda x: x[2])
    
    print(f'\n{"="*60}')
    print(f'НАЙДЕНО КАНДИДАТОВ: {len(candidates)}')
    print(f'{"="*60}')
    
    for d_cand, k_max, k_avg, idx in candidates:
        print(f'\\nd: {hex(d_cand)}')
        print(f'k: max={k_max}, avg={k_avg:.1f}')
        
        G = CURVE.generator
        Pub = d_cand * G
        print(f'Pub.x: {hex(Pub.x())}')
else:
    print('\\nНе найдено подходящих векторов')
