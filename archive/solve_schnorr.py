import csv
import hashlib
from ecdsa import NIST256p

def inverse_mod(a, m):
    return pow(a, -1, m)

def solve_schnorr():
    print("Checking Schnorr hypothesis...")
    curve = NIST256p
    n = curve.order
    G = curve.generator
    
    sigs = []
    with open("hnp_capture.csv", 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sigs.append(row)
            if len(sigs) >= 5: break
            
    for row in sigs:
        r_val = int(row['r_hex'], 16) # Assume this is k
        s_val = int(row['s_hex'], 16)
        payload_hex = row['full_payload_hex']
        payload = bytes.fromhex(payload_hex)
        msg = payload[:-64]
        
        k = r_val
        if k == 0 or k >= n: continue
        
        try:
            R_point = k * G
            r_x = R_point.x()
            r_bytes = r_x.to_bytes(32, 'big')
        except:
            continue
            
        # Schnorr Challenge e = H(R || m) or H(m || R)
        # Try H(R || m)
        e_bytes = hashlib.sha256(r_bytes + msg).digest()
        e = int.from_bytes(e_bytes, 'big')
        
        # s = k + e * d  =>  d = (s - k) * e^-1
        d = ((s_val - k) * inverse_mod(e, n)) % n
        print(f"Candidate d (Schnorr H(R||m)): {hex(d)}")
        
        # Try H(m || R)
        e_bytes = hashlib.sha256(msg + r_bytes).digest()
        e = int.from_bytes(e_bytes, 'big')
        d = ((s_val - k) * inverse_mod(e, n)) % n
        print(f"Candidate d (Schnorr H(m||R)): {hex(d)}")

if __name__ == "__main__":
    solve_schnorr()
