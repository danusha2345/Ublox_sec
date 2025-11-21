#!/usr/bin/env python3
"""Декодирование UBX-SEC-UNIQID (Chip ID)"""

import struct

# Сообщение от пользователя
msg_hex = "B562270​30A0002000000E095650F2A549D67"

# Убираем unicode символы
import re
msg_hex = re.sub(r'[^0-9A-Fa-f]', '', msg_hex)
msg = bytes.fromhex(msg_hex)

print("="*60)
print("UBX-SEC-UNIQID (0x27 0x03) - CHIP ID")
print("="*60)

# Header
sync1, sync2 = msg[0], msg[1]
msg_class, msg_id = msg[2], msg[3]
length = struct.unpack('<H', msg[4:6])[0]

print(f"\nHeader:")
print(f"  Sync: 0x{sync1:02X} 0x{sync2:02X}")
print(f"  Class: 0x{msg_class:02X} (SEC)")
print(f"  ID: 0x{msg_id:02X} (UNIQID)")
print(f"  Length: {length} bytes (0x{length:02X})")

# Payload
payload = msg[6:6+length]
print(f"\nPayload ({len(payload)} bytes):")
print(f"  Raw: {payload.hex()}")

# Попробуем разные интерпретации
print(f"\nИнтерпретации Chip ID:")

# Version (обычно первые 2 байта)
if len(payload) >= 2:
    version = struct.unpack('<H', payload[0:2])[0]
    print(f"  Version: 0x{version:04X}")

# Оставшиеся байты могут быть Chip ID
chip_id_bytes = payload[2:]
print(f"\n  Chip ID ({len(chip_id_bytes)} bytes):")
print(f"    Hex: {chip_id_bytes.hex()}")
print(f"    Bytes: {' '.join(f'{b:02X}' for b in chip_id_bytes)}")

# Как integer (разные endianness)
if len(chip_id_bytes) >= 4:
    chip_id_le = struct.unpack('<I', chip_id_bytes[:4])[0]
    chip_id_be = struct.unpack('>I', chip_id_bytes[:4])[0]
    print(f"\n  Как uint32:")
    print(f"    Little-Endian: {chip_id_le} (0x{chip_id_le:08X})")
    print(f"    Big-Endian: {chip_id_be} (0x{chip_id_be:08X})")

if len(chip_id_bytes) == 8:
    chip_id_le64 = struct.unpack('<Q', chip_id_bytes)[0]
    chip_id_be64 = struct.unpack('>Q', chip_id_bytes)[0]
    print(f"\n  Как uint64:")
    print(f"    Little-Endian: {chip_id_le64} (0x{chip_id_le64:016X})")
    print(f"    Big-Endian: {chip_id_be64} (0x{chip_id_be64:016X})")

# Checksum
checksum = msg[6+length:6+length+2]
print(f"\nChecksum:")
print(f"  Received: {checksum.hex()}")

# Вычисляем ожидаемый checksum
ck_a = 0
ck_b = 0
for byte in msg[2:6+length]:
    ck_a = (ck_a + byte) & 0xFF
    ck_b = (ck_b + ck_a) & 0xFF

expected = bytes([ck_a, ck_b])
print(f"  Expected: {expected.hex()}")
print(f"  Valid: {'✓' if checksum == expected else '✗'}")

print(f"\n{'='*60}")
print("ПОТЕНЦИАЛЬНОЕ ИСПОЛЬЗОВАНИЕ:")
print("="*60)
print("Chip ID может использоваться для:")
print("1. Деривации приватного ключа (d = H(Chip_ID + Master_Secret))")
print("2. Как seed для детерминированного RNG для nonce k")
print("3. Как уникальный идентификатор для привязки ключа к устройству")
