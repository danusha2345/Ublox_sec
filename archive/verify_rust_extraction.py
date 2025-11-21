#!/usr/bin/env python3
"""
Проверка правильности извлечения данных Rust tool'ом
"""

import csv
import struct

# Загружаем первую подпись из CSV
with open('hnp_capture.csv', 'r') as f:
    reader = csv.DictReader(f)
    first_row = next(reader)

packet_idx = int(first_row['packet_idx'])
r_hex = first_row['r_hex']
s_hex = first_row['s_hex']
payload_hex = first_row['full_payload_hex']

print("="*60)
print("ПРОВЕРКА ИЗВЛЕЧЕНИЯ ДАННЫХ RUST TOOL")
print("="*60)

payload = bytes.fromhex(payload_hex)

print(f"\nPacket Index: {packet_idx}")
print(f"Payload Length: {len(payload)} байт")

# Декодируем payload согласно README
print(f"\n{'Offset':<10} {'Size':<6} {'Field':<20} {'Value'}")
print("-"*60)

version = struct.unpack('<H', payload[0:2])[0]
print(f"0x00       2      Version              0x{version:04X}")

pkt_count = struct.unpack('<H', payload[2:4])[0]
print(f"0x02       2      Packet Count         {pkt_count}")

sha256_field = payload[4:36]
print(f"0x04       32     SHA256 field         {sha256_field[:8].hex()}...")

sessionId = payload[36:60]
print(f"0x24       24     SessionID            {sessionId[:8].hex()}...")

# Теперь проверяем, откуда Rust извлекает R и S
# Rust использует: sig_start = len - 48 = 108 - 48 = 60
sig_start = len(payload) - 48

r_from_payload = payload[sig_start:sig_start+24]
s_from_payload = payload[sig_start+24:sig_start+48]

print(f"0x{sig_start:02X}       48     Signature")
print(f"  0x{sig_start:02X}     24       R                  {r_from_payload.hex()}")
print(f"  0x{sig_start+24:02X}     24       S                  {s_from_payload.hex()}")

# Проверяем совпадение с CSV
print(f"\n{'='*60}")
print("СВЕРКА С CSV:")
print(f"{'='*60}")

r_from_csv = bytes.fromhex(r_hex)
s_from_csv = bytes.fromhex(s_hex)

print(f"\nR из payload: {r_from_payload.hex()}")
print(f"R из CSV:     {r_from_csv.hex()}")
print(f"Совпадает:    {'✓ ДА' if r_from_payload == r_from_csv else '✗ НЕТ'}")

print(f"\nS из payload: {s_from_payload.hex()}")
print(f"S из CSV:     {s_from_csv.hex()}")  
print(f"Совпадает:    {'✓ ДА' if s_from_payload == s_from_csv else '✗ НЕТ'}")

# Проверяем, что позиция sig_start соответствует README (+0x3C = 60)
expected_sig_offset = 0x3C
print(f"\n{'='*60}")
print("ПРОВЕРКА СМЕЩЕНИЯ ПОДПИСИ:")
print(f"{'='*60}")
print(f"Ожидаемое смещение (README): 0x{expected_sig_offset:02X} ({expected_sig_offset})")
print(f"Фактическое смещение (Rust): 0x{sig_start:02X} ({sig_start})")
print(f"Совпадает: {'✓ ДА' if sig_start == expected_sig_offset else '✗ НЕТ'}")

# Дополнительно: проверяем структуру всего payload
print(f"\n{'='*60}")
print("ПОЛНАЯ СТРУКТУРА PAYLOAD:")
print(f"{'='*60}")

total = 2 + 2 + 32 + 24 + 48
print(f"Version:     2 байта")
print(f"PktCount:    2 байта")
print(f"SHA256:     32 байта")
print(f"SessionID:  24 байта")
print(f"Signature:  48 байт")
print(f"            -------")
print(f"ИТОГО:      {total} байт")
print(f"Фактически: {len(payload)} байт")
print(f"Совпадает:  {'✓ ДА' if len(payload) == total else '✗ НЕТ'}")

if len(payload) == total and r_from_payload == r_from_csv and s_from_payload == s_from_csv and sig_start == expected_sig_offset:
    print(f"\n{'='*60}")
    print("✓✓✓ RUST TOOL ИЗВЛЕКАЕТ ДАННЫЕ ПРАВИЛЬНО ✓✓✓")
    print(f"{'='*60}")
else:
    print(f"\n{'='*60}")
    print("✗✗✗ ОБНАРУЖЕНЫ ПРОБЛЕМЫ В ИЗВЛЕЧЕНИИ ДАННЫХ ✗✗✗")
    print(f"{'='*60}")
