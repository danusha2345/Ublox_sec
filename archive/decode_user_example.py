#!/usr/bin/env python3
"""Декодирование примера от пользователя"""

import struct
import hashlib

# Пример от пользователя (убираю unicode символы)
msg_hex = "B562270​46C000100E000226D41641A08EDEDE4E7BD500EBE529201AEF806BB6AFAFB1445F354367B3DCC00000000000000000000000000000000000000000000000000000000C85DDA19A00C103866E329DE0EBE5D68868FBE4EE662CF584FBBA8FA361EDA9D43F13F00474AED405A64FF39993EA0FBDEC3"

# Чистим от всех не-hex символов
import re
msg_hex = re.sub(r'[^0-9A-Fa-f]', '', msg_hex)
msg = bytes.fromhex(msg_hex)

print(f"Длина всего сообщения: {len(msg)} байт\n")

# Header
sync1, sync2 = msg[0], msg[1]
msg_class, msg_id = msg[2], msg[3]
length = struct.unpack('<H', msg[4:6])[0]

print(f"Header:")
print(f"  Sync: 0x{sync1:02X} 0x{sync2:02X}")
print(f"  Class: 0x{msg_class:02X}, ID: 0x{msg_id:02X}")
print(f"  Length: {length} (0x{length:04X})")

# Payload
payload = msg[6:6+length]
print(f"\nPayload: {len(payload)} байт")

# Декодируем payload согласно README
version = struct.unpack('<H', payload[0:2])[0]
packet_count = struct.unpack('<H', payload[2:4])[0]
sha256_field = payload[4:36]
sessionId = payload[36:60]
signature = payload[60:108]

r = signature[:24]
s = signature[24:48]

print(f"\n+0x00 Version: 0x{version:04X}")
print(f"+0x02 Packet Count: {packet_count}")
print(f"+0x04 SHA256 (32 bytes):")
print(f"      {sha256_field.hex()}")
print(f"+0x24 SessionID (24 bytes):")
print(f"      {sessionId.hex()}")
print(f"+0x3C Signature (48 bytes):")
print(f"      R: {r.hex()}")
print(f"      S: {s.hex()}")

# Проверяем z согласно README
print(f"\n{'='*60}")
print("Вычисление z согласно README:")
print(f"{'='*60}")

# Подписываемые данные = SHA256_field + SessionID
to_sign = sha256_field + sessionId
print(f"To sign: {len(to_sign)} байт")

# Хешируем
final_hash = hashlib.sha256(to_sign).digest()
print(f"SHA256(to_sign): {final_hash.hex()}")

# Folding
folded = bytearray(final_hash[:24])
for i in range(8):
    folded[i] ^= final_hash[24 + i]

z_bytes = bytes(folded)
z = int.from_bytes(z_bytes, 'big')

print(f"Folded (192 bits): {z_bytes.hex()}")
print(f"z (decimal): {z}")
print(f"z (hex): {hex(z)}")

# Проверяем checksum
checksum_received = msg[6+length:6+length+2]
ck_a = 0
ck_b = 0
for byte in msg[2:6+length]:
    ck_a = (ck_a + byte) & 0xFF
    ck_b = (ck_b + ck_a) & 0xFF

checksum_computed = bytes([ck_a, ck_b])
print(f"\nChecksum received: {checksum_received.hex()}")
print(f"Checksum computed: {checksum_computed.hex()}")
if checksum_received == checksum_computed:
    print("✓ Checksum OK")
else:
    print("✗ Checksum FAIL")
