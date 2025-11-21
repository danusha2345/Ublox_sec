#!/usr/bin/env python3
"""
Проверяет, соответствует ли SHA256 поле в UBX-SEC-SIGN хешу предыдущего сообщения.
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
        # Ищем sync bytes 0xB5 0x62
        if data[i] == 0xB5 and data[i+1] == 0x62:
            msg_class = data[i+2]
            msg_id = data[i+3]
            length = struct.unpack('<H', data[i+4:i+6])[0]
            
            # Проверяем, что у нас достаточно данных
            if i + 6 + length + 2 > len(data):
                i += 1
                continue
            
            msg_type = (msg_class, msg_id)
            payload = data[i+6:i+6+length]
            checksum = data[i+6+length:i+6+length+2]
            
            # Вычисляем ожидаемую контрольную сумму
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
    print("Загружаем сообщения из log_ublox_big.bin...")
    messages = read_ubx_messages('log_ublox_big.bin')
    print(f"Найдено {len(messages)} UBX сообщений\n")
    
    # Находим все SEC-SIGN сообщения (0x27, 0x04)
    sign_messages = [msg for msg in messages if msg['type'] == (0x27, 0x04)]
    print(f"Найдено {len(sign_messages)} UBX-SEC-SIGN сообщений\n")
    
    if len(sign_messages) < 2:
        print("Недостаточно подписей для анализа")
        return
    
    # Для каждой подписи проверяем SHA256 field
    matches = 0
    mismatches = 0
    
    for idx in range(min(10, len(sign_messages))):  # Проверяем первые 10
        sign_msg = sign_messages[idx]
        payload = sign_msg['payload']
        
        # Структура UBX-SEC-SIGN (согласно реальным данным):
        # Payload = 108 байт
        # 0-1: version (2 bytes)
        # 2-3: reserved (2 bytes)
        # 4-5: pktCount (2 bytes, LE)
        # 6-37: SHA256 (32 bytes)
        # 38-59: sessionId (22 bytes) - КОРОЧЕ ЧЕМ В README!
        # 60-107: signature (48 bytes: 24 R + 24 S)
        
        if len(payload) < 108:
            print(f"[{idx}] Слишком короткий payload: {len(payload)} байт")
            continue
        
        sha256_field = payload[6:38]
        pkt_count = struct.unpack('<H', payload[4:6])[0]
        
        print(f"\n[{idx}] Подпись на offset {sign_msg['offset']}, PktCount={pkt_count}")
        print(f"  SHA256 field: {sha256_field.hex()}")
        
        # Находим все сообщения МЕЖДУ предыдущей подписью и текущей
        if idx == 0:
            # Для первой подписи берем все сообщения от начала файла
            start_offset = 0
        else:
            # Для остальных - от конца предыдущей подписи
            prev_sign = sign_messages[idx - 1]
            start_offset = prev_sign['offset'] + 6 + prev_sign['length'] + 2
        
        end_offset = sign_msg['offset']
        
        # Собираем все сообщения (кроме SEC-SIGN) в этом диапазоне
        msgs_between = [msg for msg in messages 
                       if start_offset <= msg['offset'] < end_offset 
                       and msg['type'] != (0x27, 0x04)]
        
        print(f"  Сообщений между подписями: {len(msgs_between)}")
        
        # Хешируем все payload'ы подряд
        hasher = hashlib.sha256()
        for msg in msgs_between:
            hasher.update(msg['payload'])
        
        computed_hash = hasher.digest()
        
        print(f"  SHA256(все payloads): {computed_hash.hex()}")
        
        if computed_hash == sha256_field:
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
