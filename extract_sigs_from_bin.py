#!/usr/bin/env python3
"""
Extract signatures from logs_combined.bin
"""
import struct
import hashlib
import csv
import os

def fold_sha256_to_192(sha256_hash):
    h = bytearray(sha256_hash)
    for i in range(8):
        h[i] ^= h[i + 24]
    return bytes(h[:24])

import sys

def main():
    if len(sys.argv) >= 3:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
    else:
        input_file = 'logs_combined.bin'
        output_file = 'sigs_combined.csv'
    
    if not os.path.exists(input_file):
        print(f"File {input_file} not found!")
        return

    print(f"Processing {input_file}...")
    
    with open(input_file, 'rb') as f:
        data = f.read()
        
    # Search for UBX-SEC-SIGN header: B5 62 27 04
    # Length is 108 bytes (0x6C 0x00)
    header = b'\xB5\x62\x27\x04\x6C\x00'
    
    sigs = []
    offset = 0
    
    while True:
        idx = data.find(header, offset)
        if idx == -1:
            break
            
        # Payload starts after header (6 bytes)
        payload_start = idx + 6
        payload = data[payload_start : payload_start + 108]
        
        if len(payload) < 108:
            break
            
        # Extract fields
        # 0-2: Version
        # 2-4: Packet Count
        # 4-36: SHA256
        # 36-60: SessionID
        # 60-84: R
        # 84-108: S
        
        sha256_field = payload[4:36]
        session_id = payload[36:60]
        r_bytes = payload[60:84]
        s_bytes = payload[84:108]
        
        r = int.from_bytes(r_bytes, 'big')
        s = int.from_bytes(s_bytes, 'big')
        
        # Calculate z
        msg = sha256_field + session_id
        h = hashlib.sha256(msg).digest()
        z_bytes = fold_sha256_to_192(h)
        z = int.from_bytes(z_bytes, 'big')
        
        sigs.append({
            'r': r,
            's': s,
            'z': z,
            'r_bits': r.bit_length()
        })
        
        offset = idx + 1
        
    print(f"Found {len(sigs)} signatures.")
    
    # Save to CSV
    with open(output_file, 'w') as f:
        writer = csv.DictWriter(f, fieldnames=['r', 's', 'z', 'r_bits'])
        writer.writeheader()
        for s in sigs:
            writer.writerow(s)
            
    print(f"Saved to {output_file}")
    
    # Statistics
    r_bits = [s['r_bits'] for s in sigs]
    min_bits = min(r_bits)
    avg_bits = sum(r_bits) / len(r_bits)
    
    print("-" * 30)
    print(f"Min r_bits: {min_bits}")
    print(f"Avg r_bits: {avg_bits:.2f}")
    print(f"Count < 185: {sum(1 for x in r_bits if x < 185)}")
    print(f"Count < 180: {sum(1 for x in r_bits if x < 180)}")
    print("-" * 30)

if __name__ == "__main__":
    main()
