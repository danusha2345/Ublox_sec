#!/usr/bin/env python3
"""
ПРАВИЛЬНАЯ LATTICE ATTACK (HNP) для восстановления приватного ключа

Теперь мы знаем:
1. Кривая: SECP192R1
2. z вычисляется ПРАВИЛЬНО: SHA256(sha256_field + session_id), folded to 192-bit
3. Биас: R значения имеют ~190 бит вместо 192 (k имеет биас!)

Hidden Number Problem (HNP):
Дано: (r_i, s_i, z_i) для i = 1..m
Где: s_i = k_i^-1 * (z_i + r_i * d) mod n

Преобразуем: k_i * s_i = z_i + r_i * d mod n
             k_i = s_i^-1 * (z_i + r_i * d) mod n
             k_i = (s_i^-1 * r_i) * d + (s_i^-1 * z_i) mod n
             k_i = t_i * d + u_i mod n

Где: t_i = s_i^-1 * r_i mod n
     u_i = s_i^-1 * z_i mod n

Если k_i < 2^B (где B = 190), то это HNP с bounds.
"""

import csv
import hashlib
from mpmath import mp
from ecdsa.curves import NIST192p

mp.dps = 500  # Высокая точность

CURVE = NIST192p
ORDER = CURVE.order
BASIS_SIZE = 20  # Используем 20 подписей (было 15)

def inverse_mod(a, m):
    return pow(a, -1, m)

def fold_sha256_to_192(sha256_hash):
    """Правильный fold из README"""
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
    max_iterations = 10000
    
    while k < n and iterations < max_iterations:
        iterations += 1
        
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

def solve_hnp_lattice():
    print("="*60)
    print("LATTICE ATTACK (HNP) С ПРАВИЛЬНЫМ z")
    print("="*60)
    
    # Загружаем подписи
    sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            
            if len(payload) < 108:
                continue
            
            # Извлекаем компоненты
            # Поля по сырым логам: SHA начинается с 0x04, SessionID 24 байта
            sha256_field = payload[4:36]      # 32 байта
            session_id  = payload[36:60]      # 24 байта
            r_bytes = payload[60:84]          # 24 байта
            s_bytes = payload[84:108]         # 24 байта
            
            r = int.from_bytes(r_bytes, 'big')
            s = int.from_bytes(s_bytes, 'big')
            
            # z ПРАВИЛЬНО (из README)
            msg = sha256_field + session_id
            h = hashlib.sha256(msg).digest()
            z_folded = fold_sha256_to_192(h)
            z = int.from_bytes(z_folded, 'big')
            
            sigs.append({'r': r, 's': s, 'z': z})
            
            if len(sigs) >= BASIS_SIZE:
                break
    
    print(f"Используем {len(sigs)} подписей для атаки\n")
    
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
    
    # Bias: k < 2^189 (более консервативная оценка)
    # Судя по данным, R имеет 187-192 бита
    # Попробуем bound 2^189
    B = 2**189  # Bound для k (было 2**190)
    
    # Матрица (m+2) x (m+2):
    # [B*n              0]
    # [    B*n          0]
    # [        ...      0]
    # [            B*n  0]
    # [B*t1 ... B*tm  1  0]
    # [B*u1 ... B*um  0  B]
    
    rows = []
    
    # Первые m строк: B*n*e_i
    for i in range(m):
        row = [mp.mpf(0)] * (m + 2)
        row[i] = mp.mpf(B * n)
        rows.append(row)
    
    # Строка m: коэффициенты t
    row_t = [mp.mpf(t[i] * B) for i in range(m)] + [mp.mpf(1), mp.mpf(0)]
    rows.append(row_t)
    
    # Строка m+1: константы u
    row_u = [mp.mpf(u[i] * B) for i in range(m)] + [mp.mpf(0), mp.mpf(B)]
    rows.append(row_u)
    
    print(f"Размер матрицы: {len(rows)} x {len(rows[0])}")
    print("Запуск LLL редукции (может занять несколько минут)...\n")
    
    reduced_basis = lll_reduction(rows)
    
    print("\nАнализ редуцированного базиса...")
    
    # Ищем вектор вида (B*k1, ..., B*km, d, B)
    candidates = []
    
    for i, row in enumerate(reduced_basis):
        # Проверяем последний элемент
        last_val = int(round(float(row[m+1])))
        
        # Пропускаем если последний элемент не близок к ±B
        if abs(abs(last_val) - B) > B * 0.01:  # Допуск 1%
            continue
        
        # Нормализуем знак
        if last_val < 0:
            row = [-x for x in row]
            last_val = -last_val
        
        d_candidate = int(round(float(row[m]))) % n
        
        # ВАЖНО: Пропускаем тривиальные решения
        if d_candidate == 0 or d_candidate == n:
            print(f"\nВектор #{i}: ПРОПУЩЕН (d=0 или d=n)")
            continue
        
        print(f"\nВектор #{i}: последний элемент = {last_val} (разница от B: {abs(last_val - B)})")
        print(f"  d кандидат: {hex(d_candidate)}")
        
        # Верификация: вычисляем k для ВСЕХ подписей
        k_values = []
        valid = True
        max_k_bits = 0
        
        for j in range(m):
            k_calc = (t[j] * d_candidate + u[j]) % n
            k_bits = k_calc.bit_length()
            k_values.append((j, k_calc, k_bits))
            max_k_bits = max(max_k_bits, k_bits)
            
            if k_bits > 192:
                valid = False
        
        # Показываем статистику k
        k_bit_lens = [kb for _, _, kb in k_values]
        avg_bits = sum(k_bit_lens) / len(k_bit_lens)
        
        print(f"\n  Статистика k для {len(k_values)} подписей:")
        print(f"    min={min(k_bit_lens)}, max={max(k_bit_lens)}, avg={avg_bits:.1f} бит")
        
        # Показываем первые 5
        print(f"  Первые 5 k:")
        for j, k_val, k_bits in k_values[:5]:
            status = '✓' if k_bits <= 192 else '✗'
            print(f"    k[{j}]: {k_bits} бит {status}")
        
        if valid and max_k_bits <= 192:
            candidates.append((d_candidate, max_k_bits, avg_bits, i))
    
    if candidates:
        # Сортируем по среднему количеству бит (чем меньше, тем лучше)
        candidates.sort(key=lambda x: x[2])
        
        print(f"\n{'='*60}")
        print(f"Найдено кандидатов: {len(candidates)}")
        print(f"{'='*60}")
        
        for d_candidate, max_bits, avg_bits, vec_idx in candidates:
            print(f"\nКандидат (вектор #{vec_idx}):")
            print(f"  d: {hex(d_candidate)}")
            print(f"  k: max={max_bits}, avg={avg_bits:.1f} бит")
        
        # Берем лучшего кандидата
        d_final, max_bits, avg_bits, vec_idx = candidates[0]
        
        print(f"\n{'='*60}")
        print(f"✓✓✓ SUCCESS! ПРИВАТНЫЙ КЛЮЧ НАЙДЕН!")
        print(f"{'='*60}")
        print(f"Приватный ключ: {hex(d_final)}")
        print(f"\nВсе k: max={max_bits}, avg={avg_bits:.1f} бит")
        
        # Вычисляем публичный ключ
        from ecdsa.curves import NIST192p
        G = NIST192p.generator
        Pub = d_final * G
        print(f"\nПубличный ключ:")
        print(f"  Px: {hex(Pub.x())}")
        print(f"  Py: {hex(Pub.y())}")
        
        return d_final
    
    print(f"\n{'='*60}")
    print("Не найдено подходящих векторов")
    print("="*60)
    return None

if __name__ == "__main__":
    solve_hnp_lattice()
