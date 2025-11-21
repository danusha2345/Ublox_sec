import csv
import hashlib
import sys
from ecdsa import NIST256p
from mpmath import mp

# Configuration
CURVE = NIST256p
ORDER = CURVE.order
BASIS_SIZE = 6
mp.dps = 400

def inverse_mod(a, m):
    return pow(a, -1, m)

def create_matrix(rows, cols):
    return [[mp.mpf(0)] * cols for _ in range(rows)]

def dot_product(v1, v2):
    return sum(x * y for x, y in zip(v1, v2))

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
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = int(round(mu[k][j]))
                for l in range(m):
                    basis[k][l] -= q * basis[j][l]
                ortho, mu = gram_schmidt(basis)
        
        norm_sq_k = dot_product(ortho[k], ortho[k])
        norm_sq_k_1 = dot_product(ortho[k-1], ortho[k-1])
        
        if norm_sq_k >= (delta - mu[k][k-1]**2) * norm_sq_k_1:
            k += 1
        else:
            basis[k], basis[k-1] = basis[k-1], basis[k]
            ortho, mu = gram_schmidt(basis)
            k = max(k - 1, 1)
            
    return basis

def solve_hnp_lattice(sigs, mode_name):
    print(f"Attempting Lattice Attack (HNP) with mode: {mode_name}")
    n = ORDER
    m = len(sigs)
    
    t = []
    u = []
    for sig in sigs:
        s_inv = inverse_mod(sig['s'], n)
        t.append((s_inv * sig['r']) % n)
        u.append((s_inv * sig['z']) % n)
        
    # Matrix Construction
    # Rows 0..m-1: B * n * e_i
    # Row m: (B * t1, ..., B * tm, 1, 0)
    # Row m+1: (B * u1, ..., B * um, 0, B)
    
    B = 2**128 # Bound for k (and scale factor)
    rows = []
    
    # First m rows
    for i in range(m):
        row = [mp.mpf(0)] * (m + 2)
        row[i] = mp.mpf(B * n)
        rows.append(row)
        
    # Row m (coefficients t)
    row_t = [mp.mpf(val * B) for val in t] + [mp.mpf(1), mp.mpf(0)]
    rows.append(row_t)
    
    # Row m+1 (constants u)
    row_u = [mp.mpf(val * B) for val in u] + [mp.mpf(0), mp.mpf(B)]
    rows.append(row_u)
    
    print("Running LLL...")
    reduced_basis = lll_reduction(rows)
    
    print("Checking reduced basis...")
    for row in reduced_basis:
        # We are looking for a vector where the 'd' component (index m) reveals the key
        # The vector v = (B*k1, ..., B*km, d, B)
        # So row[m] should be d (or -d)
        
        d_candidate = int(round(row[m]))
        
        # Try both +d and -d
        for sign in [1, -1]:
            d_val = (sign * d_candidate) % n
            if d_val == 0: continue
            
            # Verify with first signature
            # k1 = t1 d + u1
            k1_calc = (t[0] * d_val + u[0]) % n
            
            # Check if k1 is small (approx 128 bits)
            if k1_calc < 2**130:
                print("SUCCESS! Private Key Found.")
                print(f"Private Key: {hex(d_val)}")
                
                # Double check with second signature
                k2_calc = (t[1] * d_val + u[1]) % n
                if k2_calc < 2**130:
                    print("Verified with second signature.")
                    return d_val
                else:
                    print(f"Warning: k1 small ({k1_calc.bit_length()} bits) but k2 large ({k2_calc.bit_length()} bits). False positive?")

    return None

if __name__ == "__main__":
    raw_sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_sigs.append(row)
            
    if len(raw_sigs) > BASIS_SIZE:
        raw_sigs = raw_sigs[:BASIS_SIZE]

    modes = ["PayloadOnly", "UBXHeader", "FullHeader"]
    
    for mode in modes:
        parsed_sigs = []
        for row in raw_sigs:
            r = int(row['r_hex'], 16)
            s = int(row['s_hex'], 16)
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
                
            h = hashlib.sha256(msg).digest()
            z = int.from_bytes(h, 'big')
            parsed_sigs.append({'r': r, 's': s, 'z': z})
            
        key = solve_hnp_lattice(parsed_sigs, mode)
        if key:
            break
