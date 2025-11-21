#!/usr/bin/env python3
"""
КРИТИЧЕСКОЕ ОТКРЫТИЕ: SHA256 field формируется с FIXSEED/DYNSEED wrapping!

Формат:
salted = FIXSEED(4) + DYNSEED(4) + stream_data + DYNSEED(4) + FIXSEED_reversed(4)
SHA256_field = SHA256(salted)

DYNSEED = 0x00000000 (известен)
FIXSEED = ??? (4 байта, неизвестен)

Стратегия: brute-force FIXSEED или найти из известных паттернов
"""

import csv
import hashlib
import struct

def extract_stream_data_between_ecsign():
    """Извлекает данные между UBX-SEC-ECSIGN сообщениями"""
    
    print("Извлечение данных между UBX-SEC-ECSIGN...")
    
    with open('лог юблокс для анализа/лог_юблокс___3.csv', 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    # Найти все позиции UBX-SEC-ECSIGN (0xB5 0x62 0x27 0x04)
    ecsign_positions = []
    for i in range(len(rows) - 4):
        if (rows[i]['data'] == '0xB5' and 
            rows[i+1]['data'] == '0x62' and 
            rows[i+2]['data'] == '0x27' and 
            rows[i+3]['data'] == '0x04'):
            # Читаем длину payload
            len_low = int(rows[i+4]['data'], 16)
            len_high = int(rows[i+5]['data'], 16)
            payload_len = len_low | (len_high << 8)
            
            # Полный размер сообщения: 6 (header) + payload_len + 2 (checksum)
            total_len = 6 + payload_len + 2
            
            # Извлекаем SHA256 field из payload (offset +6+4 = +10)
            sha256_field_start = i + 10
            sha256_field = bytes([int(rows[j]['data'], 16) for j in range(sha256_field_start, sha256_field_start + 32)])
            
            ecsign_positions.append({
                'start': i,
                'end': i + total_len,
                'sha256_field': sha256_field
            })
    
    print(f"Найдено {len(ecsign_positions)} UBX-SEC-ECSIGN сообщений\n")
    
    # Извлекаем данные между сообщениями
    stream_segments = []
    for i in range(len(ecsign_positions) - 1):
        start = ecsign_positions[i]['end']
        end = ecsign_positions[i+1]['start']
        
        stream_data = bytes([int(rows[j]['data'], 16) for j in range(start, end)])
        expected_sha256 = ecsign_positions[i+1]['sha256_field']
        
        stream_segments.append({
            'stream_data': stream_data,
            'expected_sha256': expected_sha256,
            'length': len(stream_data)
        })
    
    return stream_segments

def try_fixseed(fixseed_bytes, stream_segments):
    """
    Проверяет FIXSEED на соответствие
    
    fixseed_bytes: 4 байта FIXSEED
    """
    DYNSEED = b'\x00\x00\x00\x00'
    fixseed_reversed = bytes(reversed(fixseed_bytes))
    
    matches = 0
    for seg in stream_segments[:5]:  # Проверяем первые 5
        salted = fixseed_bytes + DYNSEED + seg['stream_data'] + DYNSEED + fixseed_reversed
        computed_hash = hashlib.sha256(salted).digest()
        
        if computed_hash == seg['expected_sha256']:
            matches += 1
    
    return matches

def brute_force_fixseed(stream_segments):
    """Brute-force FIXSEED"""
    
    print("="*60)
    print("BRUTE-FORCE FIXSEED")
    print("="*60)
    
    # Chip ID
    CHIP_ID = bytes.fromhex('E095650F2A')
    
    # Из примера README известен FIXSEED = 0x01234567
    # + варианты из Chip ID
    known_patterns = [
        # Из README
        b'\x67\x45\x23\x01',  # 0x01234567 (little-endian из README)
        b'\x01\x23\x45\x67',  # 0x01234567 (big-endian)
        
        # Из Chip ID
        CHIP_ID[:4],          # 0xE095650F - первые 4 байта
        CHIP_ID[1:5],         # 0x95650F2A - байты 1-4
        bytes(reversed(CHIP_ID[:4])),  # Reversed
        
        # Hash-based
        hashlib.sha256(CHIP_ID).digest()[:4],
        hashlib.md5(CHIP_ID).digest()[:4],
        hashlib.sha1(CHIP_ID).digest()[:4],
        
        # Generic patterns
        b'\x00\x00\x00\x00',  # All zeros
        b'\xFF\xFF\xFF\xFF',  # All ones
        b'\xDE\xAD\xBE\xEF',  # 0xDEADBEEF
        b'\x55\x55\x55\x55',  # Pattern
        b'\xAA\xAA\xAA\xAA',  # Pattern
    ]
    
    print("Проверка известных паттернов...")
    for pattern in known_patterns:
        matches = try_fixseed(pattern, stream_segments)
        print(f"  FIXSEED {pattern.hex()}: {matches}/{min(5, len(stream_segments))} совпадений")
        
        if matches >= 3:
            print(f"\n✓✓✓ FIXSEED НАЙДЕН: {pattern.hex()}")
            return pattern
    
    # Если не нашли, пробуем brute-force первый байт
    print("\nBrute-force первого байта...")
    for first_byte in range(256):
        if first_byte % 64 == 0:
            print(f"  Проверка {first_byte}/256...")
        
        # Попробуем паттерн: first_byte + 0x000000
        fixseed = bytes([first_byte, 0, 0, 0])
        matches = try_fixseed(fixseed, stream_segments[:3])  # Проверяем только первые 3
        
        if matches >= 2:
            # Дополнительная проверка на всех 5
            full_matches = try_fixseed(fixseed, stream_segments[:5])
            if full_matches >= 3:
                print(f"\n✓ Потенциальный FIXSEED: {fixseed.hex()} ({full_matches}/5)")
                return fixseed
    
    print("\n✗ FIXSEED не найден среди паттернов")
    return None

def main():
    segments = extract_stream_data_between_ecsign()
    
    print(f"Извлечено {len(segments)} stream сегментов")
    print(f"Размеры: min={min(s['length'] for s in segments)}, max={max(s['length'] for s in segments)}, avg={sum(s['length'] for s in segments)/len(segments):.0f}")
    print()
    
    # Показываем первый сегмент
    print("Первый stream segment:")
    print(f"  Длина: {segments[0]['length']} байт")
    print(f"  Первые 32 байта: {segments[0]['stream_data'][:32].hex()}")
    print(f"  Ожидаемый SHA256: {segments[0]['expected_sha256'].hex()}")
    print()
    
    # Brute-force FIXSEED
    fixseed = brute_force_fixseed(segments)
    
    if fixseed:
        print(f"\n{'='*60}")
        print("SUCCESS! FIXSEED найден!")
        print(f"{'='*60}")
        print(f"FIXSEED: {fixseed.hex().upper()}")
        
        # Проверяем на ВСЕХ сегментах
        total_matches = try_fixseed(fixseed, segments)
        print(f"Подтверждено на {total_matches}/{len(segments)} сегментах")

if __name__ == "__main__":
    main()
