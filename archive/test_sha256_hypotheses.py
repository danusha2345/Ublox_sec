#!/usr/bin/env python3
"""
КРИТИЧЕСКАЯ ПРОВЕРКА: Что такое SHA256_field?

Гипотезы:
1. SHA256(все payload'ы между подписями)
2. SHA256(все ПОЛНЫЕ сообщения с headers между подписями)  
3. SHA256(только определенные типы сообщений, например NAV-PVT)
4. Это вообще не хеш, а какой-то ID
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
            
            msg_type = (msg_class, msg_id)
            payload = data[i+6:i+6+length]
            full_msg = data[i:i+6+length+2]  # С header и checksum
            
            # Проверка checksum
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
                    'class': msg_class,
                    'id': msg_id,
                    'type': msg_type,
                    'length': length,
                    'payload': payload,
                    'full_msg': full_msg,
                    'full_msg_no_checksum': data[i:i+6+length]
                })
                i += 6 + length + 2
            else:
                i += 1
        else:
            i += 1
    
    return messages

print("Загружаем сообщения...")
messages = read_ubx_messages('log_ublox_big.bin')
print(f"Найдено {len(messages)} UBX сообщений\n")

sign_messages = [msg for msg in messages if msg['type'] == (0x27, 0x04)]
print(f"Найдено {len(sign_messages)} SEC-SIGN сообщений\n")

# Проверяем первые 5 подписей
for idx in range(min(5, len(sign_messages))):
    sign_msg = sign_messages[idx]
    payload = sign_msg['payload']
    
    sha256_field = payload[4:36]
    
    # Находим сообщения между подписями
    if idx == 0:
        start_offset = 0
    else:
        prev_sign = sign_messages[idx - 1]
        start_offset = prev_sign['offset'] + 6 + prev_sign['length'] + 2
    
    end_offset = sign_msg['offset']
    
    msgs_between = [msg for msg in messages 
                   if start_offset <= msg['offset'] < end_offset 
                   and msg['type'] != (0x27, 0x04)]
    
    print(f"\n{'='*60}")
    print(f"Подпись #{idx}: {len(msgs_between)} сообщений между")
    print(f"{'='*60}")
    print(f"SHA256_field: {sha256_field.hex()}")
    
    # Гипотеза 1: хеш всех payload'ов
    h1 = hashlib.sha256()
    for msg in msgs_between:
        h1.update(msg['payload'])
    hash1 = h1.digest()
    print(f"\nГипотеза 1 (payload'ы):     {hash1.hex()}")
    print(f"  Совпадает: {'✓' if hash1 == sha256_field else '✗'}")
    
    # Гипотеза 2: хеш всех ПОЛНЫХ сообщений (с headers)
    h2 = hashlib.sha256()
    for msg in msgs_between:
        h2.update(msg['full_msg'])
    hash2 = h2.digest()
    print(f"\nГипотеза 2 (full messages): {hash2.hex()}")
    print(f"  Совпадает: {'✓' if hash2 == sha256_field else '✗'}")
    
    # Гипотеза 3: хеш сообщений БЕЗ checksum
    h3 = hashlib.sha256()
    for msg in msgs_between:
        h3.update(msg['full_msg_no_checksum'])
    hash3 = h3.digest()
    print(f"\nГипотеза 3 (no checksum):   {hash3.hex()}")
    print(f"  Совпадает: {'✓' if hash3 == sha256_field else '✗'}")
    
    # Гипотеза 4: хеш только NAV сообщений (класс 0x01)
    nav_msgs = [msg for msg in msgs_between if msg['class'] == 0x01]
    if nav_msgs:
        h4 = hashlib.sha256()
        for msg in nav_msgs:
            h4.update(msg['payload'])
        hash4 = h4.digest()
        print(f"\nГипотеза 4 (только NAV):    {hash4.hex()}")
        print(f"  Совпадает: {'✓' if hash4 == sha256_field else '✗'}")
        print(f"  NAV сообщений: {len(nav_msgs)}")
    
    # Проверяем типы сообщений
    msg_types = {}
    for msg in msgs_between:
        key = f"0x{msg['class']:02X} 0x{msg['id']:02X}"
        msg_types[key] = msg_types.get(key, 0) + 1
    
    print(f"\nТипы сообщений:")
    for msg_type, count in sorted(msg_types.items(), key=lambda x: -x[1])[:5]:
        print(f"  {msg_type}: {count}")

print(f"\n{'='*60}")
print("ВЫВОДЫ")
print(f"{'='*60}")
print("Если ни одна гипотеза не совпала, то SHA256_field - это")
print("либо хеш чего-то другого, либо вообще не хеш.")
