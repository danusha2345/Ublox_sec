#!/usr/bin/env python3
import csv
import matplotlib.pyplot as plt
import numpy as np

def main():
    r_vals = []
    with open('hnp_capture.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sig_hex = row['full_payload_hex'][60:108]
            r = int.from_bytes(bytes.fromhex(sig_hex[:48]), 'big')
            r_vals.append(r)

    print(f"Loaded {len(r_vals)} signatures")
    
    # Bit lengths
    bits = [r.bit_length() for r in r_vals]
    
    plt.figure(figsize=(12, 6))
    plt.hist(bits, bins=range(180, 194), align='left', rwidth=0.8)
    plt.title('Distribution of R Bit Lengths')
    plt.xlabel('Bit Length')
    plt.ylabel('Count')
    plt.grid(True, alpha=0.3)
    plt.xticks(range(180, 194))
    
    output_file = 'plots/r_distribution_new.png'
    plt.savefig(output_file)
    print(f"Saved plot to {output_file}")
    
    # Most Significant Byte distribution
    msb = [r >> 184 for r in r_vals] # Top 8 bits (approx)
    
    plt.figure(figsize=(12, 6))
    plt.hist(msb, bins=50)
    plt.title('Distribution of Most Significant Bytes of R')
    plt.savefig('plots/r_msb_distribution.png')
    print("Saved MSB plot")

if __name__ == "__main__":
    main()
