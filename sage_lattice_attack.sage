#!/usr/bin/env sage
"""
LATTICE ATTACK с SageMath - МАКСИМАЛЬНАЯ МОЩНОСТЬ!

SageMath использует оптимизированный fpLLL, который в 10-100 раз быстрее!
Также поддерживает BKZ 2.0 для более глубокой редукции.
"""

import csv
import hashlib
import os

print('='*60)
print('LATTICE ATTACK с SAGEMATH (ОПТИМИЗИРОВАННЫЙ fpLLL + BKZ)')
print('='*60)
print()

# SECP192R1 параметры
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831

# Создаем кривую
E = EllipticCurve(GF(p), [a, b])
G = E.point((Gx, Gy))
order = Integer(n)

print(f'Кривая: SECP192R1 (NIST P-192)')
print(f'Порядок: {hex(order)}')
print()

def fold_sha256_to_192(sha256_hash):
    """Точное folding из README"""
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

# Загружаем подписи
print('Загрузка подписей...')
all_sigs = []

if os.path.exists('sigs_new.csv'):
    print("Загрузка из sigs_new.csv...")
    with open('sigs_new.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r = Integer(int(row['r']))
            s = Integer(int(row['s']))
            z = Integer(int(row['z']))
            all_sigs.append({
                'r': r, 's': s, 'z': z, 'r_bits': r.nbits()
            })
else:
    print("Загрузка из hnp_capture.csv...")
    with open('hnp_capture.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)

            if len(payload) < 108: continue

            # Смещения по сырым логам: SHA с 0x04, SessionID 24 байта
            sha256_field = payload[4:36]      # 32 байта
            session_id   = payload[36:60]     # 24 байта
            r_bytes      = payload[60:84]     # 24 байта
            s_bytes      = payload[84:108]    # 24 байта
            
            r = Integer(int.from_bytes(r_bytes, 'big'))
            s = Integer(int.from_bytes(s_bytes, 'big'))
            
            # z
            msg = sha256_field + session_id
            h = hashlib.sha256(msg).digest()
            z_folded = fold_sha256_to_192(h)
            z = Integer(int.from_bytes(z_folded, 'big'))
            
            all_sigs.append({
                'r': r, 's': s, 'z': z, 'r_bits': r.nbits()
            })

print(f'Загружено подписей: {len(all_sigs)}')

# Сортируем по R (берем минимальные)
all_sigs.sort(key=lambda x: x['r'])

# Конфигурация атаки
BASIS_SIZE = 256
sigs = all_sigs[:BASIS_SIZE]

r_lens = [s['r_bits'] for s in sigs]
print(f'Используем {len(sigs)} подписей с минимальными R')
print(f'R lengths: min={min(r_lens)}, max={max(r_lens)}, avg={sum(r_lens)/len(r_lens):.1f} бит')

# Топ-5
print('Топ-5 минимальных R:')
for i in range(5):
    print(f'  #{i+1}: {sigs[i]["r_bits"]} бит')
print()

m = len(sigs)

# Вычисляем t_i и u_i
# s_i = k_i^-1 * (z_i + r_i * d)
# k_i = t_i * d + u_i

print('Вычисление коэффициентов t и u...')
t_list = []
u_list = []

for sig in sigs:
    s_inv = inverse_mod(sig['s'], order)
    t_val = (s_inv * sig['r']) % order
    u_val = (s_inv * sig['z']) % order
    t_list.append(t_val)
    u_list.append(u_val)

print('Построение решетки...')

# Bound: используем максимальную длину R в выборке
max_bits = max(r_lens)
B = 2^(max_bits) 

print(f'Bound: 2^{max_bits}')
print(f'Размер матрицы: {m+2} x {m+2}')
print()

# Строим матрицу
rows = []

# Первые m строк: диагональные B*n
for i in range(m):
    row = [0] * (m + 2)
    row[i] = B * order
    rows.append(row)

# Строка m: коэффициенты t
row_t = [t_list[i] * B for i in range(m)] + [1, 0]
rows.append(row_t)

# Строка m+1: константы u  
row_u = [u_list[i] * B for i in range(m)] + [0, B]
rows.append(row_u)

# Создаем матрицу SageMath
M = Matrix(ZZ, rows)

print('Запуск LLL редукции...')
M_reduced = M.LLL()
print('LLL завершен!')

def check_matrix(reduced_matrix, method_name):
    print(f'\nАнализ результатов ({method_name})...')
    candidates = []
    
    for i in range(reduced_matrix.nrows()):
        row = reduced_matrix[i]
        
        # Проверяем последний элемент (должен быть ±B)
        last_val = row[m+1]
        if abs(abs(last_val) - B) > B // 100: continue
        
        # Нормализуем знак
        if last_val < 0: row = -row
        
        # Извлекаем d
        d_candidate = Integer(row[m]) % order
        if d_candidate == 0 or d_candidate >= order - 10: continue
        
        print(f'  Вектор #{i}: d = {hex(d_candidate)}')
        
        # Быстрая проверка: вычисляем k для первой подписи
        k0 = (t_list[0] * d_candidate + u_list[0]) % order
        if k0.nbits() <= max_bits + 5: # Небольшой допуск
             # Полная верификация
             Pub = d_candidate * G
             # Проверяем подпись 0
             r0 = sigs[0]['r']
             s0 = sigs[0]['s']
             z0 = sigs[0]['z']
             
             w = inverse_mod(s0, order)
             u1 = (z0 * w) % order
             u2 = (r0 * w) % order
             P = u1*G + u2*Pub
             if (Integer(P[0]) % order) == r0:
                 print(f'    ✓ ПОДПИСЬ ВАЛИДНА! ЭТО ОНО!')
                 candidates.append(d_candidate)
                 return candidates
             else:
                 print(f'    ✗ Подпись не валидна')
    return candidates

# Проверка после LLL
found = check_matrix(M_reduced, "LLL")

if not found:
    print('\nLLL не нашел решение. Запускаем BKZ (Block Size 20)...')
    M_bkz = M.BKZ(block_size=20)
    found = check_matrix(M_bkz, "BKZ-20")

if not found:
    print('\nBKZ-20 не нашел решение. Запускаем BKZ (Block Size 30)...')
    M_bkz30 = M.BKZ(block_size=30)
    found = check_matrix(M_bkz30, "BKZ-30")

if found:
    print(f'\n{"="*60}')
    print(f'✓✓✓ УСПЕХ! ПРИВАТНЫЙ КЛЮЧ НАЙДЕН!')
    print(f'{"="*60}')
    print(f'Private Key: {hex(found[0])}')
    
    with open('FOUND_KEY_SAGE.txt', 'w') as f:
        f.write(hex(found[0]))
else:
    print(f'\n{"="*60}')
    print('Не найдено подходящих векторов даже с BKZ-30')
    print('Попробуйте увеличить BASIS_SIZE или собрать больше данных.')
