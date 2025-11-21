#!/usr/bin/env python3
"""
Генератор команды UBX-CFG-VALGET для получения публичного ключа
"""
import struct

def calc_checksum(payload):
    ck_a = 0
    ck_b = 0
    for b in payload:
        ck_a = (ck_a + b) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    return ck_a, ck_b

def create_ubx_msg(msg_class, msg_id, payload):
    msg = bytearray([0xB5, 0x62, msg_class, msg_id])
    length = len(payload)
    msg.extend(struct.pack('<H', length))
    msg.extend(payload)
    
    ck_a, ck_b = calc_checksum(msg[2:])
    msg.append(ck_a)
    msg.append(ck_b)
    return msg

def main():
    # UBX-CFG-VALGET (0x06 0x8B)
    # Key IDs for Security (from Interface Description)
    # CFG-SEC-OSECPUBX: 0x10C20005 (пример, нужно уточнить)
    # CFG-SEC-OSECPUBY: 0x10C20006 (пример)
    
    # Если точные ID неизвестны, можно запросить группу
    # Но VALGET требует конкретных ключей.
    
    # Попробуем запросить версию (CFG-SEC-CFGVER?) или просто известные ключи
    # 0x10C20005 - CFG-SEC-OSECPUBX (Public key X coordinate)
    # 0x10C20006 - CFG-SEC-OSECPUBY (Public key Y coordinate)
    
    keys = [0x10C20005, 0x10C20006]
    
    payload = bytearray()
    payload.append(0x00) # Version
    payload.append(0x00) # Layer (0=RAM)
    payload.extend([0x00, 0x00]) # Reserved
    
    for key in keys:
        payload.extend(struct.pack('<I', key))
        
    msg = create_ubx_msg(0x06, 0x8B, payload)
    
    print(f"UBX-CFG-VALGET command ({len(msg)} bytes):")
    print(msg.hex().upper())
    
    with open("get_pubkey.bin", "wb") as f:
        f.write(msg)
    print("\nSaved to get_pubkey.bin")

if __name__ == "__main__":
    main()
