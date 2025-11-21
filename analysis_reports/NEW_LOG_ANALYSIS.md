# Инструкция для анализа нового длинного лога

## Когда лог будет готов

### Шаг 1: Конвертация
```bash
# Обновить путь к новому файлу в convert_csv_to_bin.py
# Например: лог_юблокс___3.csv -> log_ublox_3.bin
python3 convert_csv_to_bin.py
```

### Шаг 2: Rust анализ
```bash
cargo run --release -- log_ublox_3.bin
```

Это обновит `hnp_capture.csv` с новыми подписями.

### Шаг 3: Статистический анализ распределения R
```bash
./venv/bin/python -c "
import csv
r_vals = []
with open('hnp_capture.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        r_vals.append(int(row['r_hex'], 16))

print(f'Всего подписей: {len(r_vals)}')
r_bits = [r.bit_length() for r in r_vals]
print(f'R bit lengths: min={min(r_bits)}, max={max(r_bits)}, avg={sum(r_bits)/len(r_bits):.2f}')

# Распределение по длинам
from collections import Counter
dist = Counter(r_bits)
print('\\nРаспределение:')
for bits in sorted(dist.keys()):
    print(f'  {bits} бит: {dist[bits]} раз ({100*dist[bits]/len(r_bits):.1f}%)')

# Оценка bias
max_bits = max(r_bits)
print(f'\\nМаксимальная длина: {max_bits} бит')
print(f'Bias: ~{192 - max_bits} старших бит всегда 0')
print(f'Рекомендуемый bound для Lattice: 2^{max_bits}')
"
```

### Шаг 4: Lattice Attack с оптимальными параметрами
После анализа распределения, обновить в `correct_lattice_attack.py`:
```python
BASIS_SIZE = <количество_подписей // 5>  # Примерно 20% от общего числа
B = 2**<max_bit_length>  # Из статистики выше
```

Затем:
```bash
./venv/bin/python correct_lattice_attack.py
```

### Шаг 5: Если LLL слишком медленный
Попробовать с меньшим BASIS_SIZE (10-15 подписей), но больше данных для выбора лучших:
```python
# Выбрать подписи с минимальными R (самый сильный bias)
sigs = sorted(all_sigs, key=lambda x: x['r'])[:BASIS_SIZE]
```

---

**Текущий статус:**
- LLL работает с 20 подписями, bound=2^189
- Chip ID: 0xE095650F2A
- Метод вычисления z: ПРАВИЛЬНЫЙ (SHA256 folded)

### Шаг 6: Получение публичного ключа (КРИТИЧНО)
1. Открыть u-center.
2. `View -> Configuration View` -> `CFG (Configuration)` -> `VALGET`.
3. Group: `CFG-SEC`.
4. Key Name: **"Get all items in this group (max. 64)"**.
5. Нажать `Poll`.
6. Скопировать ответ (hex или скриншот) и прислать.
Это позволит мгновенно проверить все гипотезы.
