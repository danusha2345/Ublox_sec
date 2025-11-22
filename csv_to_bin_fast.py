import csv
import sys
import os

def convert_csv_to_bin(input_csv, output_bin):
    print(f"Конвертация {input_csv} -> {output_bin}...")
    
    # Буфер для записи
    buffer = bytearray()
    count = 0
    
    with open(input_csv, 'r') as f_in, open(output_bin, 'wb') as f_out:
        # Пропускаем заголовок, если он есть
        # Но csv.reader сам разберется, если мы скажем
        reader = csv.reader(f_in)
        header = next(reader, None)
        
        for row in reader:
            if len(row) < 2: continue
            
            # Данные во второй колонке: "0x24"
            val_str = row[1]
            try:
                val = int(val_str, 16)
                buffer.append(val)
                count += 1
            except ValueError:
                continue
                
            # Пишем блоками по 1 МБ
            if len(buffer) >= 1024 * 1024:
                f_out.write(buffer)
                buffer.clear()
                print(f"Обработано {count} байт...", end='\r')
                
        # Дописываем остаток
        if buffer:
            f_out.write(buffer)
            
    print(f"\nГотово! Записано {count} байт в {output_bin}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python csv_to_bin_fast.py <input.csv> <output.bin>")
    else:
        convert_csv_to_bin(sys.argv[1], sys.argv[2])
