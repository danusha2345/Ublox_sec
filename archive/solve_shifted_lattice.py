import csv
import hashlib
import logging
from fpylll import IntegerMatrix, LLL, BKZ

# Параметры SECP192R1
ORDER = 0xfffffffffffffffffffffffffffffffe5fb1a724dc2369b7

def inverse_mod(k, p):
    if k == 0: raise ZeroDivisionError("division by zero")
    if k < 0: k = p - (-k % p)
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
    digest_bytes = bytearray(digest)
    folded = digest_bytes[:24]
    for i in range(8):
        folded[i] ^= digest_bytes[24 + i]
    return bytes(folded)

def solve_shifted_lattice(sigs, shift, bits_bias):
    """
    Lattice Attack с циклическим сдвигом bias.
    Предполагаем, что bias находится не в MSB, а смещен на 'shift' бит.
    Умножаем уравнение на 2^shift, чтобы сдвинуть bias в MSB.
    """
    n = ORDER
    m = len(sigs)
    B = 2**(192 - bits_bias) # Bound for the biased part
    
    # k = (z + r*d) * s^-1
    # k * 2^shift = (z * s^-1 * 2^shift) + (r * s^-1 * 2^shift) * d
    # Пусть k_shifted = k * 2^shift (mod n).
    # Если bias был в битах [x, x+bits], то в k_shifted он будет в MSB (при правильном shift).
    
    # Но это работает только если bias - это "нули".
    # Если bias - это "нули" в середине, то после умножения они станут "нулями" в MSB?
    # Нет, умножение на 2^shift (mod n) перемешивает биты из-за модуля.
    # ЭТО РАБОТАЕТ ТОЛЬКО ДЛЯ LSB/MSB или блоков.
    
    # Правильный подход для "Middle Bias":
    # k = k_high * 2^(shift + bits) + k_bias * 2^shift + k_low
    # где k_bias мал (или константа).
    # Это сложно для простой решетки.
    
    # Однако, попробуем простую эвристику:
    # Если bias "сильный" (много нулей подряд), то умножение на 2^shift может помочь,
    # если мы работаем не по модулю n, а в целых числах? Нет, ECDSA работает по модулю.
    
    pass 

# Вместо этого реализуем "Middle Bias" атаку.
# k = a + x * 2^L + b * 2^M
# где x - мал (bias).
# Это слишком сложно для быстрого скрипта.

# Вернемся к идее: Bias может быть в LSB.
# solve_lsb_lattice.py уже делает это.

# Что если bias - это "Shared Prefix"?
# k_i = K_PREF + e_i
# Тогда k_i - k_j = e_i - e_j (малая разность).
# Это решается решеткой с разностями.

def solve_diff_lattice(sigs, n_sigs, bound_bits):
    """
    Атака на разности (k_i - k_j мал).
    Работает, если у всех k есть общий префикс (MSB bias).
    Это эквивалентно обычной атаке, но матрица другая.
    """
    pass

# Оставим пока solve_lsb_lattice.py работать.
