#!/usr/bin/env python3
"""
АНАЛИЗ КОРРЕЛЯЦИИ PACKET COUNT И NONCE

Проверяет гипотезу, что nonce k генерируется линейно или предсказуемо на основе Packet Count.
Если k_i = k_0 + C * (packet_count_i - packet_count_0), то мы можем восстановить ключ.
"""

import struct
import matplotlib.pyplot as plt
import hashlib

# Загружаем данные
signatures = []
with open('log_ublox_big.bin', 'rb') as f:
    data = f.read()

i = 0
while i < len(data) - 6:
    if data[i] == 0xB5 and data[i+1] == 0x62:
        msg_class = data[i+2]
        msg_id = data[i+3]
        length = struct.unpack('<H', data[i+4:i+6])[0]
        
        if msg_class == 0x27 and msg_id == 0x04:
            payload = data[i+6:i+6+length]
            packet_count = struct.unpack('<H', payload[4:6])[0]
            r = int.from_bytes(payload[62:86], 'big')
            s = int.from_bytes(payload[84:108], 'big') # Ошибка в индексе? 86:110
            # Проверим индексы из SPEC:
            # +0x3E (62) -> R (24) -> 86
            # +0x56 (86) -> S (24) -> 110
            s = int.from_bytes(payload[86:110], 'big')
            
            signatures.append({
                'packet_count': packet_count,
                'r': r,
                's': s
            })
            i += 6 + length + 2
        else:
            i += 6 + length + 2
    else:
        i += 1

print(f"Загружено {len(signatures)} подписей")

# Анализ Packet Count
packet_counts = [s['packet_count'] for s in signatures]
print(f"Packet Counts: min={min(packet_counts)}, max={max(packet_counts)}")

# Проверка на непрерывность
diffs = [packet_counts[i+1] - packet_counts[i] for i in range(len(packet_counts)-1)]
print(f"Разности Packet Count: min={min(diffs)}, max={max(diffs)}, avg={sum(diffs)/len(diffs):.2f}")

# Гипотеза: k линейно зависит от Packet Count
# k_i = k_base + packet_count_i
# Тогда s_i * (k_base + pc_i) = z_i + r_i * d
# Это уравнение с двумя неизвестными (k_base, d) для каждой пары подписей!
# Можно решить систему линейных уравнений.

print("\nПроверка линейной зависимости k от Packet Count...")
# s1 * (k0 + pc1) = z1 + r1 * d
# s2 * (k0 + pc2) = z2 + r2 * d
#
# s1*k0 + s1*pc1 = z1 + r1*d
# s2*k0 + s2*pc2 = z2 + r2*d
#
# k0 = (z1 + r1*d - s1*pc1) / s1
# k0 = (z2 + r2*d - s2*pc2) / s2
#
# (z1 + r1*d - s1*pc1) * s2 = (z2 + r2*d - s2*pc2) * s1
# z1*s2 + r1*d*s2 - s1*pc1*s2 = z2*s1 + r2*d*s1 - s2*pc2*s1
# d * (r1*s2 - r2*s1) = z2*s1 - z1*s2 + s1*s2*(pc1 - pc2)
# d = (z2*s1 - z1*s2 + s1*s2*(pc1 - pc2)) * (r1*s2 - r2*s1)^-1

# Нам нужны z. Загрузим их из correct_z_lattice_attack.py (или вычислим заново)
# Для простоты, возьмем код вычисления z
def fold_sha256_to_192(digest):
    folded = bytearray(digest[:24])
    for i in range(8):
        folded[i] ^= digest[24 + i]
    return bytes(folded)

# ... (код вычисления z пропущен для краткости, предположим мы его добавим или импортируем)
# Но у нас нет z в этом скрипте. 
# Давайте просто проверим корреляцию R и Packet Count.

# Если k растет линейно, то R = (k*G).x будет вести себя хаотично, НО
# если k мало меняется, то R тоже может быть близко? Нет, эллиптическая кривая.

# Проверим повторяющиеся разности R
from collections import Counter
r_diffs = []
for i in range(len(signatures)-1):
    # Просто разница значений (бессмысленно для EC, но вдруг)
    r_diffs.append(signatures[i+1]['r'] - signatures[i]['r'])

print(f"Уникальных разностей R: {len(set(r_diffs))} из {len(r_diffs)}")

# Вывод:
print("\nДля проверки гипотезы линейного k нужен Z.")
print("Рекомендуется добавить эту проверку в основной скрипт атаки.")
