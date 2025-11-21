#!/usr/bin/env python3
"""Проверка всех подписей на корректность извлечения"""

import csv

errors = []
total = 0

with open('hnp_capture.csv', 'r') as f:
    reader = csv.DictReader(f)
    for i, row in enumerate(reader):
        total += 1
        payload = bytes.fromhex(row['full_payload_hex'])
        
        # Проверки
        if len(payload) != 108:
            errors.append(f"Sig {i}: неправильная длина payload {len(payload)}")
            continue
        
        # Извлекаем R и S из правильных позиций
        r_from_payload = payload[60:84]
        s_from_payload = payload[84:108]
        
        r_from_csv = bytes.fromhex(row['r_hex'])
        s_from_csv = bytes.fromhex(row['s_hex'])
        
        if r_from_payload != r_from_csv:
            errors.append(f"Sig {i}: R не совпадает")
        
        if s_from_payload != s_from_csv:
            errors.append(f"Sig {i}: S не совпадает")

print(f"Проверено подписей: {total}")
print(f"Ошибок найдено: {len(errors)}")

if errors:
    print("\nОшибки:")
    for err in errors[:10]:
        print(f"  - {err}")
else:
    print("\n✓ Все подписи извлечены корректно!")
