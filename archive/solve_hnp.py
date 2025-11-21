import csv
import hashlib
import sys
from ecdsa import NIST256p

# Configuration
CURVE = NIST256p
ORDER = CURVE.order
BASIS_SIZE = 5 

def read_signatures(filename):
    sigs = []
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
            payload_hex = row['full_payload_hex']
            payload = bytes.fromhex(payload_hex)
            msg_to_hash = payload[:-64]
            h = hashlib.sha256(msg_to_hash).digest()
            z = int.from_bytes(h, 'big')
            sigs.append({'r': r, 's': s, 'z': z})
    return sigs

def inverse_mod(a, m):
    return pow(a, -1, m)

# Custom LLL Implementation
def create_matrix(rows, cols):
    return [[0] * cols for _ in range(rows)]

def dot_product(v1, v2):
    return sum(x * y for x, y in zip(v1, v2))

from mpmath import mp
mp.dps = 300 # High precision

def gram_schmidt(basis):
    n = len(basis)
    m = len(basis[0])
    ortho = [[mp.mpf(x) for x in row] for row in basis]
    mu = [[mp.mpf(0)] * n for _ in range(n)]
    
    for i in range(n):
        for j in range(i):
            dot_val = dot_product(basis[i], ortho[j])
            norm_sq = dot_product(ortho[j], ortho[j])
            if norm_sq == 0:
                mu[i][j] = mp.mpf(0)
            else:
                mu[i][j] = dot_val / norm_sq
            
            for k in range(m):
                ortho[i][k] -= mu[i][j] * ortho[j][k]
    return ortho, mu

def lll_reduction(basis, delta=0.99):
    n = len(basis)
    m = len(basis[0])
    ortho, mu = gram_schmidt(basis)
    k = 1
    
    while k < n:
        # Size reduction
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = int(round(mu[k][j]))
                for l in range(m):
                    basis[k][l] -= q * basis[j][l]
                ortho, mu = gram_schmidt(basis) # Recompute GS (slow but safe)
        
        # Lovasz condition
        norm_sq_k = dot_product(ortho[k], ortho[k])
        norm_sq_k_1 = dot_product(ortho[k-1], ortho[k-1])
        
        if norm_sq_k >= (delta - mu[k][k-1]**2) * norm_sq_k_1:
            k += 1
        else:
            # Swap
            basis[k], basis[k-1] = basis[k-1], basis[k]
            ortho, mu = gram_schmidt(basis)
            k = max(k - 1, 1)
            
from ecdsa import NIST256p, SECP256k1

def solve_direct_bruteforce(raw_sigs):
    print("\nStarting brute force for r=k hypothesis...")
    
    curves = [
        ("NIST256p", NIST256p),
        ("SECP256k1", SECP256k1)
    ]
    
    hashes = [
        ("SHA256", hashlib.sha256),
        ("SHA1", hashlib.sha1),
        ("Identity", None)
    ]
    
    # Data modes handled inside loop
    
    for curve_name, curve in curves:
        n = curve.order
        G = curve.generator
        print(f"Testing Curve: {curve_name}")
        
        for hash_name, hash_func in hashes:
            # print(f"  Testing Hash: {hash_name}")
            
            # Data modes
            data_modes = ["PayloadOnly", "UBXHeader", "FullHeader", "Payload+Footer?"]
            
            for mode in data_modes:
                # Collect candidates
                candidates = []
                
                for row in raw_sigs:
                    r_val = int(row['r_hex'], 16) # This is k candidate
                    s_val = int(row['s_hex'], 16)
                    payload_hex = row['full_payload_hex']
                    payload = bytes.fromhex(payload_hex)
                    payload_content = payload[:-64]
                    
                    if mode == "PayloadOnly":
                        msg = payload_content
                    elif mode == "UBXHeader":
                        length = len(payload)
                        header = bytes([0x27, 0x04]) + length.to_bytes(2, 'little')
                        msg = header + payload_content
                    elif mode == "FullHeader":
                        length = len(payload)
                        header = bytes([0xB5, 0x62, 0x27, 0x04]) + length.to_bytes(2, 'little')
                        msg = header + payload_content
                    elif mode == "AdjustedHeader":
                        # Length in header is payload length WITHOUT signature
                        length = len(payload) - 64
                        header = bytes([0xB5, 0x62, 0x27, 0x04]) + length.to_bytes(2, 'little')
                        msg = header + payload_content
                    elif mode == "Payload+Footer?":
                        # Maybe signature covers everything except itself?
                        msg = payload[:-64] 
                    
                    if hash_func:
                        h = hash_func(msg).digest()
                        z = int.from_bytes(h, 'big')
                    else:
                        # Identity hash (truncate to n bit length)
                        z = int.from_bytes(msg, 'big') % n
                    
                    k = r_val
                    if k == 0 or k >= n: continue

                    # Hypothesis 1: Standard ECDSA with r_field = k
                    # s = k^-1 (z + (kG).x * d)
                    try:
                        R_point = k * G
                        r_true = R_point.x()
                        val = (k * s_val - z) % n
                        d1 = (val * inverse_mod(r_true, n)) % n
                        candidates.append(d1)
                    except:
                        pass
                        
                    # Hypothesis 2: Lazy ECDSA with r_field = k AND used as r in formula
                    # s = k^-1 (z + k * d)  => sk = z + kd => kd = sk - z => d = k^-1(sk - z) = s - z/k
                    # d = (s - z * k^-1)
                    d2 = (s_val - z * inverse_mod(k, n)) % n
                    candidates.append(d2)
                    
                    # Hypothesis 3: Linear (s = k*d + z  => d = (s-z)/k)
                    d3 = ((s_val - z) * inverse_mod(k, n)) % n
                    candidates.append(d3)

                # Check consistency
                if not candidates: continue
                
                from collections import Counter
                common = Counter(candidates).most_common(1)
                if common:
                    d_final, count = common[0]
                    if count > 1: # At least 2 matches
                        print(f"SUCCESS! Found Key!")
                        print(f"  Curve: {curve_name}")
                        print(f"  Hash: {hash_name}")
                        print(f"  Mode: {mode}")
                        print(f"  Private Key: {hex(d_final)}")
                        return d_final

    print("Brute force failed.")
    return None

if __name__ == "__main__":
    raw_sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_sigs.append(row)
            
    if len(raw_sigs) > 20:
        raw_sigs = raw_sigs[:20]
        
    solve_direct_bruteforce(raw_sigs)
