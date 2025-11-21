#!/usr/bin/env python3
"""
АВТОМАТИЧЕСКИЙ АНАЛИЗАТОР НОВОГО ЛОГА

Этот скрипт выполняет полный цикл обработки нового лога:
1. Конвертирует CSV в BIN
2. Извлекает подписи UBX-SEC-SIGN
3. Вычисляет правильный z (SHA256 folded)
4. Анализирует статистику (Bias)
5. Готовит данные для атаки
"""

import csv
import struct
import hashlib
import os
import sys

# Настройки
INPUT_CSV = 'лог_юблокс___4.csv'  # Имя нового файла (нужно будет уточнить)
OUTPUT_BIN = 'log_ublox_new.bin'
OUTPUT_SIGS = 'sigs_new.csv'

def convert_csv_to_bin(csv_path, bin_path):
    print(f"[1/4] Конвертация {csv_path} -> {bin_path}...")
    if not os.path.exists(csv_path):
        print(f"ОШИБКА: Файл {csv_path} не найден!")
        return False
        
    with open(csv_path, 'r', encoding='utf-8') as f_in:
        with open(bin_path, 'wb') as f_out:
            reader = csv.DictReader(f_in)
            count = 0
            for row in reader:
                # Предполагаем формат 'data' или 'hex'
                col = 'data' if 'data' in row else list(row.keys())[0]
                try:
                    byte_val = int(row[col], 16)
                    f_out.write(bytes([byte_val]))
                    count += 1
                except:
                    continue
                
                if count % 1000000 == 0:
                    print(f"  Обработано {count//1000000}M байт...", end='\r')
    print(f"\n  Готово! Размер: {count} байт")
    return True

def fold_sha256_to_192(digest):
    folded = bytearray(digest[:24])
    for i in range(8):
        folded[i] ^= digest[24 + i]
    return bytes(folded)

def extract_signatures(bin_path):
    print(f"[2/4] Извлечение подписей из {bin_path}...")
    
    with open(bin_path, 'rb') as f:
        data = f.read()
    
    # 1. Находим все сообщения для контекста (чтобы считать хеш)
    messages = []
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
            
            # Checksum check
            ck_a, ck_b = 0, 0
            for byte in data[i+2:i+6+length]:
                ck_a = (ck_a + byte) & 0xFF
                ck_b = (ck_b + ck_a) & 0xFF
            
            if data[i+6+length] == ck_a and data[i+6+length+1] == ck_b:
                messages.append({
                    'offset': i,
                    'type': (msg_class, msg_id),
                    'length': length,
                    'full_msg': full_msg,
                    'payload': data[i+6:i+6+length]
                })
                i += 6 + length + 2
            else:
                i += 1
        else:
            i += 1
            
    print(f"  Всего UBX сообщений: {len(messages)}")
    
    # 2. Обрабатываем подписи
    sign_msgs = [m for m in messages if m['type'] == (0x27, 0x04)]
    print(f"  Найдено подписей: {len(sign_msgs)}")
    
    signatures = []
    for idx, msg in enumerate(sign_msgs):
        payload = msg['payload']
        if len(payload) != 108:
            continue
            
        # Поля payload (фактический формат в сырых логах):
        # 0-2: Version (2)
        # 2-4: Packet Count (2)
        # 4-36: SHA256 field (32)
        # 36-60: Session ID (24)
        # 60-84: R (24)
        # 84-108: S (24)
        sha256_field = payload[4:36]
        session_id   = payload[36:60]
        r            = int.from_bytes(payload[60:84], 'big')
        s            = int.from_bytes(payload[84:108], 'big')
        
        # Вычисляем хеш сообщений МЕЖДУ подписями
        if idx == 0:
            start_offset = 0
        else:
            prev = sign_msgs[idx-1]
            start_offset = prev['offset'] + len(prev['full_msg'])
            
        end_offset = msg['offset']
        
        msgs_between = [m for m in messages 
                       if start_offset <= m['offset'] < end_offset 
                       and m['type'] != (0x27, 0x04)]
        
        hasher = hashlib.sha256()
        for m in msgs_between:
            hasher.update(m['full_msg'])

        sha256_field = hasher.digest()

        # Вычисляем z = fold(SHA256(sha_field || session_id))
        to_sign = sha256_field + session_id
        z_digest = hashlib.sha256(to_sign).digest()
        z = int.from_bytes(fold_sha256_to_192(z_digest), 'big')
        
        signatures.append({'r': r, 's': s, 'z': z})
        
    return signatures

def analyze_statistics(signatures):
    print(f"[3/4] Анализ статистики ({len(signatures)} подписей)...")
    
    r_bits = [s['r'].bit_length() for s in signatures]
    min_bits = min(r_bits)
    max_bits = max(r_bits)
    avg_bits = sum(r_bits) / len(r_bits)
    
    print(f"  R bit length: min={min_bits}, max={max_bits}, avg={avg_bits:.2f}")
    
    bias = 192 - max_bits
    print(f"  Наблюдаемый Bias: {bias} бит (старшие биты всегда 0)")
    
    count_small = sum(1 for b in r_bits if b < 185)
    print(f"  R < 185 бит: {count_small} ({100*count_small/len(signatures):.1f}%)")
    
    return bias

def save_signatures(signatures, filepath):
    print(f"[4/4] Сохранение в {filepath}...")
    with open(filepath, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['r', 's', 'z', 'r_bits'])
        for s in signatures:
            writer.writerow([s['r'], s['s'], s['z'], s['r'].bit_length()])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        INPUT_CSV = sys.argv[1]
    
    print(f"=== АНАЛИЗ НОВОГО ЛОГА: {INPUT_CSV} ===")
    
    if not os.path.exists(INPUT_CSV):
        print(f"Файл {INPUT_CSV} не найден. Укажите путь аргументом.")
        sys.exit(1)
        
    if convert_csv_to_bin(INPUT_CSV, OUTPUT_BIN):
        sigs = extract_signatures(OUTPUT_BIN)
        if sigs:
            bias = analyze_statistics(sigs)
            save_signatures(sigs, OUTPUT_SIGS)
            
            print("\n=== РЕКОМЕНДАЦИИ ===")
            if len(sigs) > 1000:
                print("✓ Данных достаточно для серьезной атаки!")
            else:
                print("⚠ Маловато данных (желательно >2000)")
                
            if bias > 5:
                print(f"✓ Обнаружен Bias {bias} бит! Lattice Attack имеет высокие шансы.")
                print(f"  Запустите: python3 correct_lattice_attack.py")
            else:
                print("⚠ Bias слабый или отсутствует. Lattice Attack может не сработать.")
