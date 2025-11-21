#!/usr/bin/env python3
"""
СКРИПТ ВЕРИФИКАЦИИ КАНДИДАТА ПРИВАТНОГО КЛЮЧА

Использует факт, что ключ ОДИН для всех подписей.
Проверяет валидность подписей для заданного d.
"""

import sys
import csv
import os

# Параметры SECP192R1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF
n = 0xFFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC2369B7
a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

def inverse_mod(k, p):
    if k == 0:
        raise ZeroDivisionError("division by zero")
    if k < 0:
        return p - inverse_mod(-k, p)
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_s % p

def point_add(x1, y1, x2, y2):
    if x1 is None: return x2, y2
    if x2 is None: return x1, y1
    if x1 == x2 and y1 != y2: return None, None
    if x1 == x2:
        m = (3 * x1 * x1 + a) * inverse_mod(2 * y1, p)
    else:
        m = (y1 - y2) * inverse_mod(x1 - x2, p)
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return x3, y3

def point_mul(k, x, y):
    rx, ry = None, None
    while k:
        if k & 1:
            rx, ry = point_add(rx, ry, x, y)
        x, y = point_add(x, y, x, y)
        k >>= 1
    return rx, ry

def verify_signature(r, s, z, Qx, Qy):
    if not (1 <= r < n and 1 <= s < n):
        return False
    w = inverse_mod(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    
    x1, y1 = point_mul(u1, Gx, Gy)
    x2, y2 = point_mul(u2, Qx, Qy)
    x, y = point_add(x1, y1, x2, y2)
    
    if x is None:
        return False
    return (x % n) == r

def load_signatures():
    signatures = []
    # Приоритет: sigs_new.csv -> hnp_capture.csv
    if os.path.exists('sigs_new.csv'):
        print("Загрузка из sigs_new.csv...")
        with open('sigs_new.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                signatures.append({
                    'r': int(row['r']),
                    's': int(row['s']),
                    'z': int(row['z'])
                })
    elif os.path.exists('hnp_capture.csv'):
        print("Загрузка из hnp_capture.csv...")
        # В hnp_capture.csv может не быть z, или он может быть неправильным
        # Но для теста предположим, что мы его вычислили или он там есть
        # Если нет z, этот скрипт не сработает без доработки
        # Поэтому лучше использовать correct_z_lattice_attack.py для генерации
        print("ПРЕДУПРЕЖДЕНИЕ: hnp_capture.csv может не содержать правильный z!")
        # Попытаемся загрузить, но проверим поля
        with open('hnp_capture.csv', 'r') as f:
            reader = csv.DictReader(f)
            if 'z' not in reader.fieldnames:
                print("ОШИБКА: В CSV нет поля 'z'. Сначала запустите correct_z_lattice_attack.py")
                sys.exit(1)
            for row in reader:
                signatures.append({
                    'r': int(row['r_hex'], 16) if 'r_hex' in row else int(row['r']),
                    's': int(row['s_hex'], 16) if 's_hex' in row else int(row['s']),
                    'z': int(row['z_hex'], 16) if 'z_hex' in row else int(row['z'])
                })
    else:
        print("ОШИБКА: Не найдены файлы с подписями (sigs_new.csv или hnp_capture.csv)")
        sys.exit(1)
    return signatures

def main():
    if len(sys.argv) < 2:
        print("Использование: python3 verify_candidate_key.py <private_key_hex_or_int>")
        sys.exit(1)
        
    key_input = sys.argv[1]
    try:
        if os.path.exists(key_input):
            with open(key_input, 'r') as f:
                content = f.read().strip()
                if content.startswith('0x'):
                    d = int(content, 16)
                else:
                    d = int(content)
        elif key_input.startswith('0x'):
            d = int(key_input, 16)
        else:
            d = int(key_input)
    except:
        print("Ошибка: Неверный формат ключа или файл не найден")
        sys.exit(1)
        
    print(f"Проверка ключа d = {hex(d)}")
    
    # Вычисляем публичный ключ Q = d*G
    Qx, Qy = point_mul(d, Gx, Gy)
    print(f"Публичный ключ Q: ({hex(Qx)}, {hex(Qy)})")
    
    signatures = load_signatures()
    print(f"Всего подписей для проверки: {len(signatures)}")
    
    valid_count = 0
    for i, sig in enumerate(signatures):
        if verify_signature(sig['r'], sig['s'], sig['z'], Qx, Qy):
            valid_count += 1
        
        if i % 100 == 0:
            print(f"  Проверено {i}...")
            
    print(f"\nРЕЗУЛЬТАТ: {valid_count} / {len(signatures)} валидны")
    
    if valid_count == len(signatures):
        print("\n🎉🎉🎉 УСПЕХ! ЭТО ПРАВИЛЬНЫЙ ПРИВАТНЫЙ КЛЮЧ! 🎉🎉🎉")
        print(f"Private Key: {hex(d)}")
        with open('FOUND_KEY.txt', 'w') as f:
            f.write(hex(d))
    elif valid_count > 0:
        print(f"\n⚠ Частичное совпадение! Ключ подходит к {valid_count} подписям.")
        print("Возможно, есть несколько ключей или ошибка в z для некоторых сообщений.")
    else:
        print("\n❌ Ключ не подходит ни к одной подписи.")

if __name__ == "__main__":
    main()
