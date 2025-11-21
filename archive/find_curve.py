#!/usr/bin/env python3
"""
Поиск правильной кривой для точки из README
"""
from ecdsa.curves import NIST192p, BRAINPOOLP192r1

# Точка из README
x_hex = "05612C583C0F7968B93272075303711F429D50D952711CE9"
y_hex = "80A2F5E0A21986B9502643358C616A01D0174006F7D71739"

x_be = int(x_hex, 16)
y_be = int(y_hex, 16)

x_le = int.from_bytes(bytes.fromhex(x_hex), 'little')
y_le = int.from_bytes(bytes.fromhex(y_hex), 'little')

def check_curve(name, curve, x, y, endian):
    p = curve.p()
    a = curve.a()
    b = curve.b()
    
    lhs = (y * y) % p
    rhs = (x * x * x + a * x + b) % p
    
    if lhs == rhs:
        print(f"✓ MATCH FOUND: {name} ({endian})")
        return True
    return False

print("Checking curves...")

curves = [
    ("NIST P-192", NIST192p.curve),
    ("Brainpool P192r1", BRAINPOOLP192r1.curve),
]

# Добавим secp192k1 вручную (нет в ecdsa по умолчанию)
class Secp192k1:
    def p(self): return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37
    def a(self): return 0
    def b(self): return 3

curves.append(("secp192k1", Secp192k1()))

for name, curve in curves:
    check_curve(name, curve, x_be, y_be, "Big-Endian")
    check_curve(name, curve, x_le, y_le, "Little-Endian")
    
    # Check swapped X/Y
    check_curve(name, curve, y_be, x_be, "Big-Endian Swapped")
    check_curve(name, curve, y_le, x_le, "Little-Endian Swapped")

print("Done.")
