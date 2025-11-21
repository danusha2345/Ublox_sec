#!/usr/bin/env python3
"""Декодирует структуру payload из hnp_capture.csv"""

import struct

# Первый payload из CSV
payload_hex = "0100430095d83aea3ee43e167042b73148189f7b3ca2c46ff85021f01c531d6556bcefc1000000000000000000000000000000000000000000000000aa73f25615b5b741c6dccca5c71c856aa9c8641928b4f58cf2eb97d432ab6809a91d71b01548216c9c4ea46e53b91816"

payload = bytes.fromhex(payload_hex)

print(f"Длина payload: {len(payload)} байт\n")

version = struct.unpack('<H', payload[0:2])[0]
reserved = struct.unpack('<H', payload[2:4])[0] 
pktCount = struct.unpack('<H', payload[4:6])[0]

print(f"Version: 0x{version:04X}")
print(f"Reserved: 0x{reserved:04X}")
print(f"PktCount: {pktCount} (0x{pktCount:04X})")

# SHA256 должно быть 32 байта, начиная с позиции 6
sha256_field = payload[6:38]
print(f"\nSHA256 field (32 bytes):")
print(f"  {sha256_field.hex()}")
print(f"  Заканчивается на: ...{sha256_field[-4:].hex()}")

# SessionID
sessionId = payload[38:60]
print(f"\nSessionID (22 bytes):")
print(f"  {sessionId.hex()}")

# Signature
signature = payload[60:108]
r = signature[:24]
s = signature[24:48]

print(f"\nSignature (48 bytes):")
print(f"  R: {r.hex()}")
print(f"  S: {s.hex()}")

# Пример от пользователя
print("\n" + "="*60)
print("Пример от пользователя:")
user_example = "0100E00022 6D 41641A08EDEDE4E7BD500EBE529201AEF806BB6AFAFB1445F354367B3DCC0000" + \
               "0000000000000000000000000000000000000000000000" + \
               "C85DDA19A00C103866E329DE0EBE5D68868FBE4EE662CF58" + \
               "4FBBA8FA361EDA9D43F13F00474AED405A64FF39993EA0FBDEC3"
user_example = user_example.replace(" ", "")
payload2 = bytes.fromhex(user_example)

print(f"Длина: {len(payload2)} байт")
version2 = struct.unpack('<H', payload2[0:2])[0]
reserved2 = struct.unpack('<H', payload2[2:4])[0]
pktCount2 = struct.unpack('<H', payload2[4:6])[0]

print(f"Version: 0x{version2:04X}")
print(f"Reserved: 0x{reserved2:04X}")
print(f"PktCount: {pktCount2}")

sha256_field2 = payload2[6:38]
print(f"SHA256: {sha256_field2.hex()}")
print(f"Последние 4 байта SHA256: {sha256_field2[-4:].hex()}")
