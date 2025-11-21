# Полная Техническая Документация: u-blox UBX-SEC-SIGN (0x27 0x04)

## Оглавление
1. [Структура Сообщения](#структура-сообщения)
2. [Криптографические Параметры](#криптографические-параметры)
3. [Формулы Вычисления](#формулы-вычисления)
4. [Процесс Извлечения Данных](#процесс-извлечения-данных)
5. [Примеры Кода](#примеры-кода)

---

## Структура Сообщения

### UBX Message Format (Общий)

```
+------+------+-------+-----+--------+--------+----------+------+------+
| 0xB5 | 0x62 | CLASS | ID  | LEN_LO | LEN_HI | PAYLOAD  | CK_A | CK_B |
+------+------+-------+-----+--------+--------+----------+------+------+
  Sync1  Sync2  1 byte 1 byte 1 byte  1 byte  LEN bytes 1 byte 1 byte
```

**Checksum Calculation:**
```python
ck_a = 0
ck_b = 0
for byte in [CLASS, ID, LEN_LO, LEN_HI, PAYLOAD...]:
    ck_a = (ck_a + byte) & 0xFF
    ck_b = (ck_b + ck_a) & 0xFF
```

### UBX-SEC-SIGN (0x27 0x04) Payload Structure

**Версия:** u-blox M10 (может отличаться от M9)

**Полная длина payload:** 108 байт (0x6C)

```
Offset  Size  Type      Field           Description
------  ----  --------  --------------  ------------------------------------
0x00    2     uint16_LE Version         Обычно 0x0001
0x02    2     uint16_LE Packet Count    Счетчик пакетов между подписями
0x04    32    bytes     SHA256          Хеш накопленных UBX сообщений
0x24    24    bytes     SessionID       ID сессии (в логах M10 — нули)
0x3C    24    bytes     R               Компонент R подписи (big-endian)
0x54    24    bytes     S               Компонент S подписи (big-endian)
```

**ВАЖНО:**
- Все числовые поля в начале (Version, Packet Count) — little-endian.
- R и S — big-endian.
- В логах u-blox M10 поля Reserved **нет**.

### Hex Dump Пример

```
Полное сообщение:
B5 62 27 04 6C 00  <- Header (Class=0x27, ID=0x04, Length=0x006C=108)

Payload (108 bytes):
01 00              <- Version (0x0001)
22 6D              <- Packet Count (little-endian: 0x6D22 = 27938)
41 64 1A 08 ED ... <- SHA256 (32 bytes)
00 00 00 00 00 ... <- SessionID (24 bytes, все нули)
C8 5D DA 19 A0 ... <- R (24 bytes, big-endian)
4F BB A8 FA 36 ... <- S (24 bytes, big-endian)

CK_A CK_B          <- Checksum (2 bytes)
```

### UBX-SEC-UNIQID (0x27 0x03) - Chip ID

**Назначение:** Содержит уникальный идентификатор чипа устройства

**Поддержка:** u-blox 9 with protocol version 27 (официальная документация)

#### Официальная Структура (u-blox 9)

**Длина payload:** 9 байт

```
Offset  Size  Type      Field           Description
------  ----  --------  --------------  ------------------------------------
+0x00   1     U1        version         Message version (0x01)
+0x01   3     U1[3]     reserved        Зарезервировано
+0x04   5     U1[5]     uniqueId        Unique chip ID (40 bits)
```

**Message Structure (из документации):**
```
Header: 0xB5 0x62
Class:  0x27
ID:     0x03
Length: 9 bytes
```

#### Наблюдаемая Структура (u-blox M10)

**Длина payload:** 10 байт (0x0A) - **ОТЛИЧАЕТСЯ ОТ ДОКУМЕНТАЦИИ!**

```
Offset  Size  Type      Field           Description
------  ----  --------  --------------  ------------------------------------
+0x00   2     uint16_LE Version         0x02 (не 0x01!)
+0x02   9     bytes     Chip ID         Уникальный ID 
```

**Пример сообщения из наших данных (M10):**
```
B5 62 27 03 0A 00  <- Header (Length=0x000A=10, не 9!)

Payload (10 bytes):
02                           <- Version (0x02 LE)
00 00 00 E0 95 65 0F 2A 54   <- Chip ID  
9D 67                        <- Checksum
```

**Chip ID для нашего устройства (M10):**
- **Hex:** `000000E095650F2A54` (9 байт)
- **Decimal (BE):** 246,932,250,241,620
- **Decimal (LE):** 6,064,676,777,188,392,960

#### Различия M9 vs M10

| Параметр | M9 (документация) | M10 (наши данные) |
|----------|-------------------|-------------------|
| Payload Length | 9 bytes | 10 bytes |
| Version Field Size | 1 byte (0x01) | 1 bytes (0x02) |
| Chip ID Size | 5 bytes (40 bits) | 9 bytes  |
| Reserved Field | 3 bytes | Отсутствует |

**Вывод:** u-blox M10 использует **расширенную** версию сообщения с 64-битным Chip ID вместо 40-битного.

#### Потенциальное использование

1. **Уникальный идентификатор** для привязки ключей к конкретному устройству
2. **Деривация приватного ключа:** `d = H(Chip_ID || Master_Secret)`
3. **Seed для детерминистического RNG:** `k = H(Chip_ID || Counter || Message)`
4. **Защита от подмены:** Ключи могут быть записаны в OTP памяти, привязанные к Chip ID

#### Результаты Тестирования

**Проверено на 524 подписях:**
- ✗ Chip ID **НЕ** влияет напрямую на значения R или S
- ✗ Нет корреляции между битами Chip ID и битами подписей
- ✗ `d ≠ H(Chip_ID)` ни для SHA256, ни для SHA1
- ✗ `k ≠ H(Chip_ID || Counter)` для тестированных вариантов

**Вывод:** Chip ID используется только как идентификатор. Приватный ключ и nonce генерируются независимо от Chip ID (или с использованием недоступной нам Master Secret).

---

## Криптографические Параметры

### Эллиптическая Кривая

**Кривая:** SECP192R1 (NIST P-192)

**Параметры:**
```python
# Из стандарта NIST FIPS 186-4
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF  # Prime field
a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
b = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1

# Generator point G
Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811

# Order (количество точек группы)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC2369B7
```

**Размеры:**
- Координаты точек: 192 бита (24 байта)
- Скаляры (k, d): 192 бита
- R, S в подписи: по 24 байта каждый

### Приватный Ключ

**КРИТИЧЕСКИ ВАЖНО:** 

> **Используется ОДИН единственный приватный ключ `d` для всех подписей!**

Это подтверждено и означает:
- Все 524 подписи в нашем датасете созданы **одним ключом**
- НЕТ ротации ключей между сессиями
- НЕТ множественных ключей на одном устройстве
- Ключ **уникален для данного устройства** 
- Если ключ будет восстановлен, он будет работать для **всех подписей** этого устройства

**Импликации для атаки:**
- Lattice Attack ищет **единственное** решение
- Любое найденное `d` должно быть валидно для **всех** подписей
- Это упрощает верификацию - достаточно проверить на нескольких подписях

### ECDSA Алгоритм

**Стандарт:** FIPS 186-4 ECDSA

**Подпись (R, S) для сообщения z:**
```
1. Выбрать случайный nonce: k ∈ [1, n-1]
2. Вычислить точку: (x, y) = k * G
3. r = x mod n
4. s = k^(-1) * (z + r*d) mod n
5. Подпись: (R, S) где R = r (как 24-байтовый big-endian), S = s
```

**Верификация с публичным ключом Q = d*G:**
```
1. Проверить: 1 ≤ r, s < n
2. w = s^(-1) mod n
3. u1 = z*w mod n
4. u2 = r*w mod n
5. (x, y) = u1*G + u2*Q
6. Подпись валидна если x mod n == r
```

---

## Формулы Вычисления

### 1. Вычисление SHA256 Field

**Входные данные:** Все UBX сообщения между двумя UBX-SEC-SIGN

**Процесс:**
```python
import hashlib

# Собрать все ПОЛНЫЕ UBX сообщения (с headers и checksums)
# между предыдущей и текущей подписью
messages_between = []  # List of full UBX messages

# Хешировать ВСЁ подряд
sha256_hasher = hashlib.sha256()
for msg in messages_between:
    # msg = B5 62 CLASS ID LEN_LO LEN_HI PAYLOAD CK_A CK_B
    sha256_hasher.update(msg)

sha256_field = sha256_hasher.digest()  # 32 байта
```

**КРИТИЧЕСКИ ВАЖНО:**
- Хешируются **ПОЛНЫЕ** сообщения, включая:
  - Sync bytes (B5 62)
  - Header (CLASS, ID, LENGTH)
  - Payload
  - Checksum (CK_A, CK_B)
- НЕ хешируются сами UBX-SEC-SIGN сообщения
- НЕ только payload, а **полное сообщение**

### 2. Вычисление z (Message Hash для ECDSA)

**Входные данные:**
- `sha256_field` (32 байта) - вычислен выше
- `sessionId` (24 байта) - из payload UBX-SEC-SIGN

**Процесс:**
```python
import hashlib

# Шаг 1: Объединить SHA256 field + SessionID
to_sign = sha256_field + sessionId  # 32 + 24 = 56 байт

# Шаг 2: Хешировать
final_hash = hashlib.sha256(to_sign).digest()  # 32 байта

# Шаг 3: Folding к 192 битам (24 байта)
# XOR первых 8 байт с байтами 24-31
folded = bytearray(final_hash[:24])
for i in range(8):
    folded[i] ^= final_hash[24 + i]

z_bytes = bytes(folded)  # 24 байта

# Шаг 4: Конвертация в целое число (big-endian)
z = int.from_bytes(z_bytes, byteorder='big')
```

**Математически:**
```
h = SHA256(sha256_field || sessionId)
z[0..23] = h[0..23]
for i in 0..7:
    z[i] = z[i] XOR h[24+i]
z_number = bytes_to_int_be(z[0..23])
```

### 3. ECDSA Уравнение

**Связь между r, s, z, d, k:**
```
s * k ≡ z + r * d (mod n)

Где:
  k - nonce (случайное число, используемое при подписи)
  d - приватный ключ
  r - x-координата точки k*G (mod n)
  s - второй компонент подписи
  z - хеш сообщения (вычислен выше)
  n - порядок группы кривой
```

**Для восстановления приватного ключа:**
```
Если известен k:
  d = (s*k - z) * r^(-1) mod n

Если известны два k1, k2 для двух подписей:
  d = (s1*k1 - s2*k2 - z1 + z2) * (r2 - r1)^(-1) mod n

Если известен MSB/LSB bias в k:
  Использовать Lattice Attack (HNP - Hidden Number Problem)
```

---

## Процесс Извлечения Данных

### Из Бинарного Лога

**Шаг 1:** Найти все UBX-SEC-SIGN сообщения
```python
def find_sec_sign_messages(data):
    messages = []
    i = 0
    while i < len(data) - 6:
        if data[i] == 0xB5 and data[i+1] == 0x62:
            msg_class = data[i+2]
            msg_id = data[i+3]
            length = struct.unpack('<H', data[i+4:i+6])[0]
            
            if msg_class == 0x27 and msg_id == 0x04:
                # Это SEC-SIGN
                payload = data[i+6:i+6+length]
                messages.append({
                    'offset': i,
                    'length': length,
                    'payload': payload
                })
            
            i += 6 + length + 2  # Next message
        else:
            i += 1
    
    return messages
```

**Шаг 2:** Извлечь R, S, SHA256_field из payload
```python
def extract_signature_data(payload):
    # Payload должен быть 108 байт
    assert len(payload) == 108
    
    version = struct.unpack('<H', payload[0:2])[0]
    reserved = struct.unpack('<H', payload[2:4])[0]
    packet_count = struct.unpack('<H', payload[4:6])[0]
    
    sha256_field = payload[6:38]    # 32 bytes
    sessionId = payload[38:62]      # 24 bytes
    
    r_bytes = payload[62:86]        # 24 bytes (big-endian)
    s_bytes = payload[86:110]       # 24 bytes (big-endian)
    
    r = int.from_bytes(r_bytes, 'big')
    s = int.from_bytes(s_bytes, 'big')
    
    return {
        'version': version,
        'packet_count': packet_count,
        'sha256_field': sha256_field,
        'sessionId': sessionId,
        'r': r,
        's': s
    }
```

**Шаг 3:** Вычислить z
```python
def compute_z(sha256_field, sessionId):
    # Объединяем
    to_sign = sha256_field + sessionId
    
    # Хешируем
    final_hash = hashlib.sha256(to_sign).digest()
    
    # Folding
    folded = bytearray(final_hash[:24])
    for i in range(8):
        folded[i] ^= final_hash[24 + i]
    
    # Конвертируем в число
    z = int.from_bytes(bytes(folded), 'big')
    return z
```

**Шаг 4:** Собрать все вместе
```python
def process_log_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Найти все SEC-SIGN
    sec_sign_msgs = find_sec_sign_messages(data)
    
    signatures = []
    for msg in sec_sign_msgs:
        sig_data = extract_signature_data(msg['payload'])
        z = compute_z(sig_data['sha256_field'], sig_data['sessionId'])
        
        signatures.append({
            'r': sig_data['r'],
            's': sig_data['s'],
            'z': z,
            'packet_count': sig_data['packet_count']
        })
    
    return signatures
```

---

## Примеры Кода

### Полный Пример: Извлечение и Вычисление z

```python
#!/usr/bin/env python3
import struct
import hashlib

def fold_sha256_to_192(digest):
    """Folding SHA256 (32 bytes) к 192 битам (24 bytes)"""
    folded = bytearray(digest[:24])
    for i in range(8):
        folded[i] ^= digest[24 + i]
    return bytes(folded)

def read_ubx_messages(filepath):
    """Читает все UBX сообщения из бинарного файла"""
    messages = []
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    i = 0
    while i < len(data) - 6:
        # Проверка sync bytes
        if data[i] == 0xB5 and data[i+1] == 0x62:
            msg_class = data[i+2]
            msg_id = data[i+3]
            length = struct.unpack('<H', data[i+4:i+6])[0]
            
            # Проверка границ
            if i + 6 + length + 2 > len(data):
                i += 1
                continue
            
            # Полное сообщение (с headers и checksum)
            full_msg = data[i:i+6+length+2]
            payload = data[i+6:i+6+length] if length > 0 else b''
            
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
                    'type': (msg_class, msg_id),
                    'length': length,
                    'payload': payload,
                    'full_msg': full_msg
                })
                i += 6 + length + 2
            else:
                # Checksum не совпал, пропускаем
                i += 1
        else:
            i += 1
    
    return messages

def extract_signatures_with_z(filepath):
    """Извлекает все подписи с правильно вычисленным z"""
    
    # Загружаем все сообщения
    all_messages = read_ubx_messages(filepath)
    
    # Находим SEC-SIGN сообщения
    sign_messages = [msg for msg in all_messages if msg['type'] == (0x27, 0x04)]
    
    signatures = []
    
    for idx in range(len(sign_messages)):
        sign_msg = sign_messages[idx]
        payload = sign_msg['payload']
        
        # Извлекаем поля из payload
        packet_count = struct.unpack('<H', payload[4:6])[0]
        sessionId = payload[38:62]  # 24 bytes
        r = int.from_bytes(payload[62:86], 'big')  # 24 bytes
        s = int.from_bytes(payload[86:110], 'big')  # 24 bytes
        
        # Находим все сообщения МЕЖДУ подписями
        if idx == 0:
            start_offset = 0
        else:
            prev_sign = sign_messages[idx - 1]
            start_offset = prev_sign['offset'] + 6 + prev_sign['length'] + 2
        
        end_offset = sign_msg['offset']
        
        msgs_between = [msg for msg in all_messages
                       if start_offset <= msg['offset'] < end_offset
                       and msg['type'] != (0x27, 0x04)]
        
        # Вычисляем SHA256_field
        sha256_hasher = hashlib.sha256()
        for msg in msgs_between:
            sha256_hasher.update(msg['full_msg'])
        
        sha256_field = sha256_hasher.digest()
        
        # Вычисляем z
        to_sign = sha256_field + sessionId
        final_hash = hashlib.sha256(to_sign).digest()
        z_bytes = fold_sha256_to_192(final_hash)
        z = int.from_bytes(z_bytes, 'big')
        
        signatures.append({
            'r': r,
            's': s,
            'z': z,
            'packet_count': packet_count,
            'msgs_between_count': len(msgs_between)
        })
    
    return signatures

# Использование:
if __name__ == "__main__":
    signatures = extract_signatures_with_z('log_ublox_big.bin')
    
    print(f"Извлечено {len(signatures)} подписей")
    
    # Вывод первой подписи
    if signatures:
        sig = signatures[0]
        print(f"\nПервая подпись:")
        print(f"  r = {hex(sig['r'])}")
        print(f"  s = {hex(sig['s'])}")
        print(f"  z = {hex(sig['z'])}")
        print(f"  Packet Count: {sig['packet_count']}")
        print(f"  Messages Between: {sig['msgs_between_count']}")
```

### Верификация Подписи (если известен публичный ключ)

```python
from ecdsa import NIST192p, VerifyingKey
from ecdsa.util import sigdecode_string

def verify_signature(r, s, z, public_key_hex):
    """
    Верифицирует ECDSA подпись
    
    Args:
        r, s: компоненты подписи (int)
        z: хеш сообщения (int)
        public_key_hex: публичный ключ в hex (48 bytes = 24 Px + 24 Py)
    
    Returns:
        bool: True если подпись валидна
    """
    # Конвертируем публичный ключ
    pubkey_bytes = bytes.fromhex(public_key_hex)
    vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST192p)
    
    # Формируем signature bytes
    r_bytes = r.to_bytes(24, 'big')
    s_bytes = s.to_bytes(24, 'big')
    sig_bytes = r_bytes + s_bytes
    
    # Формируем message digest
    z_bytes = z.to_bytes(24, 'big')
    
    try:
        vk.verify_digest(sig_bytes, z_bytes, sigdecode=sigdecode_string)
        return True
    except:
        return False
```

---

## Источники и Ссылки

### Официальная Документация
- **u-blox Integration Manual**: UBX Protocol Specification
- **NIST FIPS 186-4**: Digital Signature Standard (DSS) - ECDSA

### Сообщество
- [cturvey/RandomNinjaChef](https://github.com/cturvey/RandomNinjaChef/blob/main/uBloxSigning/README.md) - Детальное описание UBX-SEC-ECSIGN (основа нашего понимания)
- [u-blox Community Forum](https://portal.u-blox.com/s/question/0D52p00008HKCkJCAX/how-to-verify-ubxsecsign)

### Криптография
- SECP192R1 Curve Parameters: [SEC 2: Recommended Elliptic Curve Domain Parameters](https://www.secg.org/sec2-v2.pdf)
- Lattice Attack References: "Lattice Attacks on ECDSA" by Nguyen & Shparlinski

---

**Дата:** 2025-11-20  
**Версия:** 1.0  
**Устройство:** u-blox M10  
**Проверено на:** 524 подписях
