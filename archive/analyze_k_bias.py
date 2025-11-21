#!/usr/bin/env python3
"""
Анализ: Если бы мы знали d, какие были бы k?
Проверяем, есть ли хоть КАКОЙ-ТО bias в nonce.
"""

import csv
import hashlib

ORDER = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

def inv_mod(a, m):
    return pow(a, -1, m)

def fold(h):
    h = bytearray(h)
    for i in range(8):
        h[i] ^= h[24 + i]
    return bytes(h[:24])

# Загружаем
sigs = []
with open('hnp_capture.csv', 'r') as f:
    for row in csv.DictReader(f):
        payload = bytes.fromhex(row['full_payload_hex'])
        sha256_field = payload[4:36]
        sessionId = payload[36:60]
        
        r = int.from_bytes(payload[60:84], 'big')
        s = int.from_bytes(payload[84:108], 'big')
        
        msg = sha256_field + sessionId
        h = hashlib.sha256(msg).digest()
        z = int.from_bytes(fold(h), 'big')
        
        sigs.append({'r': r, 's': s, 'z': z})

print(f"Загружено {len(sigs)} подписей\n")

# Берем первую и последнюю подпись, пытаемся найти d
# s1 * k1 = z1 + r1 * d
# s2 * k2 = z2 + r2 * d

# Если k небольшое (bias), попробуем перебор малых k
print("Перебор малых значений k1 и k2...\n")

sig1, sig2 = sigs[0], sigs[1]

# Пробуем k1, k2 в диапазоне [1, 2^16] (очень маленькие)
found = False
for k1 in range(1, min(2**12, ORDER)):
    # d = (s1*k1 - z1) / r1
    try:
        r1_inv = inv_mod(sig1['r'], ORDER)
        d = ((sig1['s'] * k1 - sig1['z']) * r1_inv) % ORDER
        
        # Проверяем на sig2
        # k2 = (z2 + r2*d) / s2
        s2_inv = inv_mod(sig2['s'], ORDER)
        k2 = ((sig2['z'] + sig2['r'] * d) * s2_inv) % ORDER
        
        # k2 тоже должен быть маленьким
        if k2.bit_length() <= 16:
            print(f"k1={k1}, k2={k2}, d={hex(d)[:30]}...")
            
            # Проверяем на sig3
            if len(sigs) >= 3:
                sig3 = sigs[2]
                s3_inv = inv_mod(sig3['s'], ORDER)
                k3 = ((sig3['z'] + sig3['r'] * d) * s3_inv) % ORDER
                if k3.bit_length() <= 16:
                    print(f"  ✓ k3={k3} тоже маленький!")
                    found = True
                    break
    except:
        pass

if not found:
    print("Малые k не найдены.\n")

# Альтернатива: проверяем, может ли r быть связан с k через простую функцию
print("="*60)
print("Проверка: r = H(k) или r = k*G.x")
print("="*60)

# Стандартный ECDSA: r = (k*G).x
# Это значит k может быть ЛЮБЫМ, а r зависит от умножения точки на кривой.
# Bias в r НЕ означает bias в k (это случайное отображение).

print("\nВ стандартном ECDSA r - это x-координата k*G.")
print("Даже если все r < 2^183, это НЕ означает, что k < 2^183.")
print("k может быть полностью случайным, а bias в r - это артефакт выборки.\n")

# Вычислим вероятность того, что случайная точка на SECP192R1
# имеет x-координату < 2^183
prob = (2**183) / ORDER
print(f"Вероятность случайной точки иметь x < 2^183: {prob:.4%}")
print(f"Ожидаемое количество таких точек из {len(sigs)}: {len(sigs) * prob:.1f}")

# Подсчитаем, сколько у нас действительно r < 2^183
r_small = sum(1 for sig in sigs if sig['r'].bit_length() < 183)
print(f"Фактическое количество r < 2^183: {r_small}")

if r_small > len(sigs) * prob * 1.5:
    print("\n✓ Больше ожидаемого! Возможно, bias есть.")
else:
    print("\n✗ В пределах случайности. Bias в r вероятно случаен.")
