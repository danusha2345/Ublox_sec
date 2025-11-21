import csv
import hashlib
import logging
from fpylll import IntegerMatrix, LLL, BKZ

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Параметры SECP192R1
ORDER = 0xfffffffffffffffffffffffffffffffe5fb1a724dc2369b7

def inverse_mod(k, p):
    """Возвращает обратное значение k по модулю p."""
    if k == 0:
        raise ZeroDivisionError("division by zero")
    if k < 0:
        k = p - (-k % p)
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_s % p

def fold_sha256_to_192(digest):
    """
    Сворачивание SHA-256 (32 байта) в 192 бита (24 байта).
    Берем первые 24 байта и XOR-им первые 8 байт с последними 8 байтами хеша.
    """
    digest_bytes = bytearray(digest)
    folded = digest_bytes[:24]
    for i in range(8):
        folded[i] ^= digest_bytes[24 + i]
    return bytes(folded)

def solve_lsb_lattice(sigs, num_bits):
    """
    Lattice Attack для LSB bias (младшие биты k известны/нули).
    Предполагаем, что k = a * 2^L + b, где b (LSB) мало или 0.
    В данном случае проверяем гипотезу, что LSB k равны 0 (k = a * 2^L).
    """
    n = ORDER
    m = len(sigs)
    
    # Если LSB k равны 0 (L бит), то k = k' * 2^L
    # s * (k' * 2^L) = z + r * d (mod n)
    # k' * (s * 2^L) - d * r = z (mod n)
    # Это стандартная форма HNP, но коэффициенты другие.
    # t = r * (s * 2^L)^-1  (коэффициент при d)
    # u = z * (s * 2^L)^-1  (свободный член)
    # k' - t * d = u (mod n)
    # k' < n / 2^L (это наш bias!)
    
    L = num_bits # Количество нулевых бит в конце
    B = n // (2**L) # Верхняя граница для k'
    
    print(f"Checking LSB bias: {L} bits (k has {L} trailing zeros)")
    
    M = IntegerMatrix(m + 2, m + 2)
    
    t_vals = []
    u_vals = []
    
    factor = pow(2, L, n)
    
    for sig in sigs:
        r, s, z = sig['r'], sig['s'], sig['z']
        
        # s * k = z + r * d
        # s * (k' * 2^L) = z + r * d
        # k' = (z * s^-1 * 2^-L) + (r * s^-1 * 2^-L) * d
        
        s_inv = inverse_mod(s, n)
        factor_inv = inverse_mod(factor, n)
        
        term1 = (z * s_inv * factor_inv) % n # u
        term2 = (r * s_inv * factor_inv) % n # t
        
        u_vals.append(term1)
        t_vals.append(term2)
        
    # Строим решетку
    # Basis:
    # (B, 0, ..., 0, t1*B, u1*B)
    # (0, B, ..., 0, t2*B, u2*B)
    # ...
    # (0, 0, ..., B, tm*B, um*B)
    # (0, 0, ..., 0, n*B,  0   )
    # (0, 0, ..., 0, 0,    B   ) <- для u
    
    # Упрощенная матрица (как в MSB, но t и u другие)
    # row i (0..m-1): (0... B ... 0, t_i, u_i) - нет, это для CVP
    # Используем ту же конструкцию, что и в MSB, так как уравнение k' - t*d - u = 0 (approx) такое же.
    
    # M:
    # q  0  0 ... 0
    # 0  q  0 ... 0
    # ...
    # t1 t2 ... 1 0
    # u1 u2 ... 0 B_scale
    
    # Используем конструкцию из fast_lattice_attack, но с новыми t и u
    # k' - t*d = u (mod n)
    # k' < B
    
    scale = 2**L # Это наш "вес" bias. Чем больше L, тем меньше k', тем больше вес.
    
    for i in range(m):
        M[i, i] = n * scale
        
    for i in range(m):
        M[m, i] = t_vals[i] * scale
        
    M[m, m] = 1
    
    for i in range(m):
        M[m+1, i] = u_vals[i] * scale
        
    M[m+1, m+1] = scale
    
    # Редукция
    BKZ.reduction(M, BKZ.Param(block_size=20))
    
    # Проверка
    for i in range(M.nrows):
        row = M[i]
        val = row[m+1]
        if abs(val) != scale: # Должно быть +/- scale
            continue
            
        # d находится в row[m]
        d_candidate = abs(row[m]) % n
        
        # Проверка
        k_calc = (inverse_mod(sigs[0]['s'], n) * (sigs[0]['z'] + sigs[0]['r'] * d_candidate)) % n
        
        # Проверяем, делится ли k на 2^L
        if k_calc % (2**L) == 0:
             print(f"\n!!! FOUND POTENTIAL KEY !!!")
             print(f"d: {hex(d_candidate)}")
             return d_candidate
             
    return None

def main():
    # Загрузка подписей
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
            
            all_sigs.append({'r': r, 's': s, 'z': z})
            
    print(f"Loaded {len(all_sigs)} signatures")
    
    # Пробуем разное количество бит LSB (от 1 до 10)
    # И разное количество подписей
    
    for lsb_bits in range(2, 12):
        for n_sigs in [40, 60, 80, 100]:
            res = solve_lsb_lattice(all_sigs[:n_sigs], lsb_bits)
            if res:
                print("Success!")
                return

if __name__ == "__main__":
    main()
