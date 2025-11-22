from ecdsa import VerifyingKey, NIST192p
from ecdsa.ellipticcurve import Point
from ecdsa.util import sigdecode_string
import csv
import hashlib

# Параметры из примера
Px_bytes = bytes([0x0F,0xF6,0x26,0x5F,0x72,0x20,0x8B,0x39,0xE7,0x25,0xEB,0xE2,0x8E,0x26,0x25,0xF3,0x56,0x17,0xEE,0xFC,0x8A,0xC8,0x66,0x25])
Py_bytes = bytes([0x35,0x2D,0xC7,0x6D,0xF0,0xF3,0x28,0x34,0x4C,0x09,0x62,0xB3,0x0D,0x20,0xA1,0x97,0xFE,0xEB,0x20,0x02,0xB4,0x00,0x11,0x1A])

# Создаем публичный ключ
curve = NIST192p
Px = int.from_bytes(Px_bytes, 'big')
Py = int.from_bytes(Py_bytes, 'big')
point = Point(curve.curve, Px, Py)
vk = VerifyingKey.from_public_point(point, curve=curve)

print(f"Проверка публичного ключа из примера...")
print(f"Px: {Px_bytes.hex()}")
print(f"Py: {Py_bytes.hex()}")

# Загружаем подписи из логов
sigs = []
try:
    with open('sigs_combined.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sigs.append(row)
except FileNotFoundError:
    print("sigs_combined.csv не найден, пробую sigs_new.csv")
    with open('sigs_new.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sigs.append(row)

print(f"Загружено {len(sigs)} подписей для проверки.")

valid_count = 0
checked_count = 0

for i, sig in enumerate(sigs[:100]): # Проверяем первые 100
    r_int = int(sig['r'])
    s_int = int(sig['s'])
    z_int = int(sig['z'])
    
    # Конвертируем в байты
    r_bytes = r_int.to_bytes(24, 'big')
    s_bytes = s_int.to_bytes(24, 'big')
    z_bytes = z_int.to_bytes(24, 'big')
    
    signature = r_bytes + s_bytes
    
    try:
        # verify_digest принимает хэш (z) и подпись
        # В ecdsa verify_digest ожидает digest нужной длины.
        # Для P-192 digest должен быть.
        # Но у нас z уже 24 байта.
        if vk.verify_digest(signature, z_bytes, sigdecode=sigdecode_string):
            valid_count += 1
            print(f"Подпись #{i}: VALID")
    except Exception as e:
        # print(f"Подпись #{i}: Invalid ({e})")
        pass
    checked_count += 1

print(f"\nРезультат:")
print(f"Проверено: {checked_count}")
print(f"Валидно: {valid_count}")

if valid_count > 0:
    print("\n!!! ЭТОТ ПУБЛИЧНЫЙ КЛЮЧ ПОДХОДИТ К НАШИМ ЛОГАМ !!!")
else:
    print("\nЭтот публичный ключ НЕ от наших логов (или z вычислен иначе).")
