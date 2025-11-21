#!/usr/bin/env python3
"""
Верификация: наш вычисленный SHA256_field совпадает с полем в сообщении?
"""

import struct
import hashlib

def read_ubx_messages(filepath):
    messages = []
    with open(filepath, 'rb') as f:
        data = f.read()
    
    i = 0
    while i < len(data) - 6:
        if data[i] == 0xB5 and data[i+1] == 0x62:
            msg_class = data[i+2]
            msg_id = data[i+3]
            length = struct.unpack('<H', data[i+4:i+6])[0]
            
            if i + 6 + length + 2 > len(data):
                i += 1
                continue
            
            full_msg = data[i:i+6+length+2]
            payload = data[i+6:i+6+length] if length > 0 else b''
            
            ck_a = 0
            ck_b = 0
            for byte in data[i+2:i+6+length]:
                ck_a = (ck_a + byte) & 0xFF
                ck_b = (ck_b + ck_a) & 0xFF
            
            checksum = data[i+6+length:i+6+length+2]
            expected = bytes([ck_a, ck_b])
            
            if checksum == expected:
                messages.append({
                    'offset': i,
                    'type': (msg_class, msg_id),
                    'length': length,
                    'payload': payload,
                    'full_msg': full_msg
                })
                i += 6 + length + 2
            else:
                i += 1
        else:
            i += 1
    
    return messages

print("Загружаем сообщения...")
all_messages = read_ubx_messages('log_ublox_big.bin')
sign_messages = [msg for msg in all_messages if msg['type'] == (0x27, 0x04)]

print(f"Проверяем {min(10, len(sign_messages))} подписей...\n")

matches = 0
for idx in range(min(10, len(sign_messages))):
    sign_msg = sign_messages[idx]
    payload = sign_msg['payload']
    
    # SHA256_field из сообщения
    sha256_from_msg = payload[4:36]
    
    # Вычисляем SHA256 всех сообщений между
    if idx == 0:
        start_offset = 0
    else:
        prev_sign = sign_messages[idx - 1]
        start_offset = prev_sign['offset'] + 6 + prev_sign['length'] + 2
    
    end_offset = sign_msg['offset']
    
    msgs_between = [msg for msg in all_messages
                   if start_offset <= msg['offset'] < end_offset
                   and msg['type'] != (0x27, 0x04)]
    
    # Хешируем
    hasher = hashlib.sha256()
    for msg in msgs_between:
        hasher.update(msg['full_msg'])
    
    sha256_computed = hasher.digest()
    
    match = '✓' if sha256_computed == sha256_from_msg else '✗'
    if sha256_computed == sha256_from_msg:
        matches += 1
    
    print(f"Sig {idx}: {match}")
    if idx < 3:
        print(f"  From msg:  {sha256_from_msg.hex()}")
        print(f"  Computed:  {sha256_computed.hex()}")

print(f"\n{'='*60}")
print(f"Совпадений: {matches}/{min(10, len(sign_messages))}")
if matches == min(10, len(sign_messages)):
    print("✓✓✓ ВСЕ СОВПАДАЮТ - ФОРМУЛА ПРАВИЛЬНАЯ!")
else:
    print("✗ Есть несовпадения")
print(f"{'='*60}")
