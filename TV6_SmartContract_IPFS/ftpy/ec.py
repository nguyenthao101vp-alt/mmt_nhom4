"""Số học đường cong secp256k1 (Jacobian) - đủ cho DKG, ElGamal ngưỡng và bằng chứng Chaum-Pedersen.

Đây là bản tham chiếu thuần Python để nhóm đọc hiểu và đo thời gian. Khi cần tốc độ, thay bằng
thư viện C (coincurve) mà không phải đổi các hàm bên trên.
"""
from __future__ import annotations

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
INF = None  # điểm vô cực ở dạng affine

Point = tuple[int, int] | None


def is_on_curve(p: Point) -> bool:
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + 7)) % P == 0


def _jdouble(X, Y, Z):
    if Y == 0 or Z == 0:
        return (0, 1, 0)
    YY = Y * Y % P
    S = 4 * X * YY % P
    M = 3 * X * X % P
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * YY * YY) % P
    Z3 = 2 * Y * Z % P
    return (X3, Y3, Z3)


def _jadd_mixed(X1, Y1, Z1, x2, y2):
    """Cộng điểm Jacobian (X1,Y1,Z1) với điểm affine (x2,y2)."""
    if Z1 == 0:
        return (x2, y2, 1)
    Z1Z1 = Z1 * Z1 % P
    U2 = x2 * Z1Z1 % P
    S2 = y2 * Z1 * Z1Z1 % P
    H = (U2 - X1) % P
    R = (S2 - Y1) % P
    if H == 0:
        return _jdouble(X1, Y1, Z1) if R == 0 else (0, 1, 0)
    HH = H * H % P
    HHH = H * HH % P
    V = X1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    Y3 = (R * (V - X3) - Y1 * HHH) % P
    Z3 = Z1 * H % P
    return (X3, Y3, Z3)


def _to_affine(X, Y, Z) -> Point:
    if Z == 0:
        return None
    zi = pow(Z, -1, P)
    zi2 = zi * zi % P
    return (X * zi2 % P, Y * zi2 * zi % P)


def mul(k: int, p: Point = G) -> Point:
    k %= N
    if k == 0 or p is None:
        return None
    X, Y, Z = 0, 1, 0
    x2, y2 = p
    for bit in bin(k)[2:]:
        X, Y, Z = _jdouble(X, Y, Z)
        if bit == "1":
            X, Y, Z = _jadd_mixed(X, Y, Z, x2, y2)
    return _to_affine(X, Y, Z)


def add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    X, Y, Z = _jadd_mixed(p[0], p[1], 1, q[0], q[1])
    return _to_affine(X, Y, Z)


def neg(p: Point) -> Point:
    return None if p is None else (p[0], (-p[1]) % P)


def sub(p: Point, q: Point) -> Point:
    return add(p, neg(q))


def point_bytes(p: Point) -> bytes:
    assert p is not None
    return p[0].to_bytes(32, "big") + p[1].to_bytes(32, "big")
