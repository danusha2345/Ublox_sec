#!/usr/bin/env python3
"""
Конвертер CSV лога u-blox в бинарный формат для Rust анализатора
"""

import csv

# НОВЫЙ длинный лог
input_csv = 'лог юблокс для анализа/big_log_ublox_1.csv'
output_bin = 'log_ublox_big.bin'

print(f"Конвертация {input_csv} → {output_bin}")

with open(input_csv, 'r', encoding='utf-8') as f_in:
    with open(output_bin, 'wb') as f_out:
        reader = csv.DictReader(f_in)
        
        count = 0
        for row in reader:
            byte_hex = row['data']
            byte_val = int(byte_hex, 16)
            f_out.write(bytes([byte_val]))
            count += 1
            
            if count % 1000000 == 0:
                print(f"  Обработано {count//1000000}M байт...")

print(f"Готово! Записано {count} байт")
