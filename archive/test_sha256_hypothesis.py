#!/usr/bin/env python3
"""
Проверяет гипотезу: SHA256 field = первые 30 байт SHA256(все сообщения между подписями).
Последние 2 байта в поле всегда 0x0000.
"""

import hashlib
import struct

def read_ubx_messages(filepath):
    """Читает все UBX сообщения из бинарного файла."""
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
            checksum = data[i+6+length:i+6+length+2]
            
            ck_a = 0
            ck_b = 0
            for byte in data[i+2:i+6+length]:
                ck_a = (ck_a + byte) & 0xFF
                ck_b = (ck_b + ck_a) & 0xFF
            
            expected_checksum = bytes([ck_a, ck_b])
            
            if checksum == expected_checksum:
                messages.append({
                    'offset': i,
                    'class': msg_class,
                    'id': msg_id,
                    'length': length,
                    'payload': payload,
                    'type': msg_type
                })
                i += 6 + length + 2
            else:
                i += 1
        else:
            i += 1
    
    return messages

def main():
    print("Загружаем сообщения...")
    messages = read_ubx_messages('log_ublox_big.bin')
    print(f"Найдено {len(messages)} UBX сообщений\n")
    
    sign_messages = [msg for msg in messages if msg['type'] == (0x27, 0x04)]
    print(f"Найдено {len(sign_messages)} SEC-SIGN сообщений\n")
    
    if len(sign_messages) < 2:
        print("Недостаточно подписей")
        return
    
    matches = 0
    mismatches = 0
    
    for idx in range(min(20, len(sign_messages))):
        sign_msg = sign_messages[idx]
        payload = sign_msg['payload']
        
        if len(payload) < 108:
            continue
        
        # SHA256 field: байты 6-37 (32 байта, но последние 2 = 0x0000)
        sha256_field_full = payload[6:38]
        sha256_field_truncated = sha256_field_full[:30]  # Первые 30 байт
        
        pktCount = struct.unpack('<H', payload[4:6])[0]
        
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
        
        # Хешируем все payload'ы
        hasher = hashlib.sha256()
        for msg in msgs_between:
            hasher.update(msg['payload'])
        
        computed_hash_full = hasher.digest()
        computed_hash_truncated = computed_hash_full[:30]
        
        print(f"\n[{idx}] PktCount={pktCount}, Msgs={len(msgs_between)}")
        print(f"  SHA256 field (30 байт): {sha256_field_truncated.hex()}")
        print(f"  SHA256(payloads)[0:30]: {computed_hash_truncated.hex()}")
        
        if computed_hash_truncated == sha256_field_truncated:
            print(f"  ✓ СОВПАДЕНИЕ!")
            matches += 1
        else:
            print(f"  ✗ НЕ СОВПАДАЕТ")
            mismatches += 1
    
    print(f"\n{'='*60}")
    print(f"ИТОГО: {matches} совпадений, {mismatches} несовпадений")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
