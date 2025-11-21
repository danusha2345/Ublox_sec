# Chip ID и связь с приватным ключом

## UBX-SEC-UNIQID (0x27 0x03)

### Запрос
```
0xB5 0x62 0x27 0x03 0x00 0x00 0x2A 0xA5
```
- Sync: 0xB5 0x62
- Class: 0x27 (SEC)
- ID: 0x03 (UNIQID)
- Length: 0x00 0x00 (0 bytes)
- Checksum: 0x2A 0xA5

### Ответ
```
0xB5 0x62 0x27 0x03 0x0A 0x00 0x02 0x00 0x00 0x00 0xE0 0x95 0x65 0x0F 0x2A 0x54 0x9D 0x67
```
- Sync: 0xB5 0x62
- Class: 0x27 (SEC)
- ID: 0x03 (UNIQID)
- Length: 0x0A 0x00 (10 bytes)
- Payload:
  - Version: 0x02
  - Reserved: 0x00 0x00 0x00
  - **Unique Chip ID: 0xE0 0x95 0x65 0x0F 0x2A** (5 bytes, 40 bits)
- Checksum: 0x9D 0x67

### Извлеченные данные

**Chip ID (40-bit):** `0xE095650F2A`
- Decimal: 963,254,071,082
- Binary: `11100000 10010101 01100101 00001111 00101010`

## Документация UBX-SEC

### UBX-SEC-SIGN (0x27 0x01)
- **Назначение:** SHA-256 подпись предыдущего сообщения
- **Алгоритм:** SHA-256 с programmed seeds
- **Формат payload:**
  - Byte 0: version
  - Byte 1-3: reserved
  - Byte 4: classID (класс подписываемого сообщения)
  - Byte 5: messageID (ID подписываемого сообщения)
  - Byte 6-7: checksum (UBX checksum подписываемого сообщения)
  - Byte 8-39: **hash** (SHA-256 хеш подписываемого сообщения, 32 байта)

### UBX-SEC-UNIQID (0x27 0x03)
- **Назначение:** Получить уникальный chip identifier
- **Длина:** 40 bits (5 bytes)
- **Использование:** Идентификация конкретного чипа

## Гипотеза: Chip ID как основа для ключа

### Возможные схемы:

1. **Прямая деривация:**
   ```
   private_key = HMAC-SHA256(chip_id, "u-blox-ecdsa-key")
   ```

2. **HKDF (RFC 5869):**
   ```
   private_key = HKDF-Expand(HKDF-Extract(salt, chip_id), info, 24)
   ```

3. **Детерминированная генерация (RFC 6979 variant):**
   ```
   private_key = hash(chip_id || counter || domain_separator)
   ```

4. **Простое хеширование:**
   ```
   private_key = SHA256(chip_id) [folded to 192-bit]
   ```

## Следующие шаги

1. ✅ Сохранить Chip ID: `0xE095650F2A`
2. ⏭ Попробовать различные схемы деривации ключа
3. ⏭ Проверить, дает ли сгенерированный ключ консистентные результаты

---

**Chip ID:** `0xE095650F2A`  
**Дата извлечения:** 2025-11-19
