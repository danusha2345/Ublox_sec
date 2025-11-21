#!/usr/bin/env python3
"""
Проверка гипотезы Little-Endian R/S
"""
import hashlib
from ecdsa.curves import NIST192p

CURVE = NIST192p
ORDER = CURVE.order
G = CURVE.generator

# Пример из README
# R: 1B471F5AA84FEAE19C7C8EBBBA7DB612EDC9B8DBB71B2D01
# S: D4B47078E28C2359D118FD9EDBA837E325A437C78783AD1E
# z: 94CD038F5C2234E0FBAFFF842D26C89470273AAC3D8C3B44
# PubKey: 
#   x: 05612C583C0F7968B93272075303711F429D50D952711CE9
#   y: 80A2F5E0A21986B9502643358C616A01D0174006F7D71739

r_hex = "1B471F5AA84FEAE19C7C8EBBBA7DB612EDC9B8DBB71B2D01"
s_hex = "D4B47078E28C2359D118FD9EDBA837E325A437C78783AD1E"
z_hex = "94CD038F5C2234E0FBAFFF842D26C89470273AAC3D8C3B44"

pub_x_hex = "05612C583C0F7968B93272075303711F429D50D952711CE9"
pub_y_hex = "80A2F5E0A21986B9502643358C616A01D0174006F7D71739"

def verify(r, s, z, pub_point):
    if r < 1 or r >= ORDER or s < 1 or s >= ORDER:
        return False
    
    w = pow(s, -1, ORDER)
    u1 = (z * w) % ORDER
    u2 = (r * w) % ORDER
    
    P = u1 * G + u2 * pub_point
    return P.x() % ORDER == r

from ecdsa.ellipticcurve import Point

# Пробуем Big-Endian Point
try:
    pub_point = Point(CURVE.curve, int(pub_x_hex, 16), int(pub_y_hex, 16))
    print("Pub Key (BE) valid on curve!")
except AssertionError:
    print("Pub Key (BE) NOT on curve!")

# Пробуем Little-Endian Point
try:
    x_le = int.from_bytes(bytes.fromhex(pub_x_hex), 'little')
    y_le = int.from_bytes(bytes.fromhex(pub_y_hex), 'little')
    pub_point_le = Point(CURVE.curve, x_le, y_le)
    print(f"Pub Key (LE) valid on curve!\\n  x={hex(x_le)}\\n  y={hex(y_le)}")
    pub_point = pub_point_le
except AssertionError:
    print("Pub Key (LE) NOT on curve!")
    # Fallback to BE for verify function to not crash immediately (though it will fail)
    pub_point = Point(CURVE.curve, int(pub_x_hex, 16), int(pub_y_hex, 16)) if False else None

print("Проверка Big-Endian (стандарт)...")
r_be = int(r_hex, 16)
s_be = int(s_hex, 16)
z_be = int(z_hex, 16)
print(f"Результат: {verify(r_be, s_be, z_be, pub_point)}")

print("\nПроверка Little-Endian R/S...")
r_le = int.from_bytes(bytes.fromhex(r_hex), 'little')
s_le = int.from_bytes(bytes.fromhex(s_hex), 'little')
print(f"R (LE): {hex(r_le)}")
print(f"S (LE): {hex(s_le)}")
print(f"Результат: {verify(r_le, s_le, z_be, pub_point)}")

print("\nПроверка Little-Endian ВСЕГО (R, S, z)...")
z_le = int.from_bytes(bytes.fromhex(z_hex), 'little')
print(f"z (LE): {hex(z_le)}")
print(f"Результат: {verify(r_le, s_le, z_le, pub_point)}")
