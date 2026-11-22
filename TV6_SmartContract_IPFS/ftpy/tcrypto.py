"""Mật mã của FileTrust cho đề tài camera (bản tham chiếu để TV6 đo và để TV4 đối chiếu).

Gồm: AES-256-GCM, IDA (Rabin, dùng zfec), DKG Pedersen + VSS Feldman, ElGamal ngưỡng dạng KEM-DEM
(băm-ElGamal trên secp256k1), bằng chứng Chaum-Pedersen, và bảo vệ lại cho Requester kiểu ECIES.

Khác biệt có chủ đích so với bài báo (cần TV4 xác nhận):
  * KEM: băm-ElGamal. C1 = r*G, S = r*PK, dòng khóa = HKDF(x(S), ctx). Không cần mã hóa khóa K vào nhóm
    như (c1, c2) trong bài báo, nên bớt được c2 trên chuỗi. Giải mã ngưỡng vẫn là sum(lambda_j * sk_j * C1).
  * Phần "DEM" XOR với dòng khóa HKDF, đúng cấu trúc ctSym = S_i XOR CID của bài báo (PT. 20-21).
  * Mục được bảo vệ gồm digest 32 byte của 6 CID (IPFS) và khóa AES-256-GCM của clip (mục thứ n+1).
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from zfec import easyfec

from . import ec
from .ec import G, N, Point

# ----------------------------------------------------------------------------- AES-256-GCM


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


# ----------------------------------------------------------------------------- IDA (Rabin)


def ida_disperse(data: bytes, n: int, t: int) -> tuple[list[bytes], int]:
    """Chia data thành n mảnh, đủ t mảnh để khôi phục. Trả về (mảnh, độ đệm)."""
    padlen = (-len(data)) % t
    return list(easyfec.Encoder(t, n).encode(data)), padlen


def ida_reconstruct(pieces: dict[int, bytes], n: int, t: int, padlen: int) -> bytes:
    """pieces: {chỉ số mảnh -> nội dung}, cần ít nhất t mảnh."""
    idx = sorted(pieces)[:t]
    assert len(idx) == t, "không đủ mảnh để khôi phục"
    return easyfec.Decoder(t, n).decode([pieces[i] for i in idx], idx, padlen)


# ----------------------------------------------------------------------------- KDF / ngữ cảnh


def context(data_id: bytes, batch_id: int, index: int) -> bytes:
    """Ràng buộc dòng khóa vào tệp, lô backup và chỉ số mục (ctx trong bài báo)."""
    return data_id + batch_id.to_bytes(8, "big") + index.to_bytes(2, "big")


def _stream(shared: Point, c1: Point, ctx: bytes, length: int) -> bytes:
    ikm = shared[0].to_bytes(32, "big")
    info = b"filetrust-kem-dem|" + ec.point_bytes(c1) + ctx
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _rand_scalar() -> int:
    while True:
        k = int.from_bytes(os.urandom(32), "big")
        if 1 <= k < N:
            return k


# ----------------------------------------------------------------------------- KEM-DEM


def kem_dem_encrypt(pk: Point, message: bytes, ctx: bytes) -> tuple[Point, bytes]:
    """Trả về (C1, ct). message dài 32 byte (digest CID hoặc khóa AES)."""
    r = _rand_scalar()
    c1 = ec.mul(r, G)
    shared = ec.mul(r, pk)
    return c1, _xor(message, _stream(shared, c1, ctx, len(message)))


def kem_dem_decrypt_with_shared(shared: Point, c1: Point, ct: bytes, ctx: bytes) -> bytes:
    return _xor(ct, _stream(shared, c1, ctx, len(ct)))


def kem_dem_decrypt(sk: int, c1: Point, ct: bytes, ctx: bytes) -> bytes:
    """Giải mã bằng khóa bí mật đầy đủ (dùng cho Requester, người có sk_R)."""
    return kem_dem_decrypt_with_shared(ec.mul(sk, c1), c1, ct, ctx)


# ----------------------------------------------------------------------------- DKG (Pedersen + Feldman VSS)


def _eval_poly(coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % N
    return acc


@dataclass
class DKGResult:
    n: int
    t: int
    sk: list[int]                 # sk[j-1] là mảnh bí mật của SH_j (chỉ để mô phỏng, thực tế mỗi SH tự giữ)
    vk: list[Point]               # khóa xác minh của từng SH
    commitments: list[Point]      # C_0..C_{t-1} gộp; PK = C_0
    pk: Point


def run_dkg(n: int, t: int) -> DKGResult:
    """Pedersen DKG: mỗi SH chia một đa thức bậc t-1 bằng VSS Feldman; mọi mảnh đều được kiểm tra."""
    polys = [[_rand_scalar() for _ in range(t)] for _ in range(n)]
    comm = [[ec.mul(a, G) for a in poly] for poly in polys]                      # C_{j,l} = a_{j,l} * G
    shares = [[_eval_poly(polys[j], i) for i in range(1, n + 1)] for j in range(n)]  # s_{j,i} = f_j(i)
    # Kiểm tra Feldman: s_{j,i} * G == sum_l i^l * C_{j,l}
    for j in range(n):
        for i in range(1, n + 1):
            lhs = ec.mul(shares[j][i - 1], G)
            rhs = None
            for l in range(t):
                rhs = ec.add(rhs, ec.mul(pow(i, l, N), comm[j][l]))
            assert lhs == rhs, f"mảnh của SH{j+1} gửi SH{i} không khớp cam kết"
    sk = [sum(shares[j][i - 1] for j in range(n)) % N for i in range(1, n + 1)]
    vk = [ec.mul(s, G) for s in sk]
    agg = []
    for l in range(t):
        acc = None
        for j in range(n):
            acc = ec.add(acc, comm[j][l])
        agg.append(acc)
    # vk_i phải khớp với cam kết gộp
    for i in range(1, n + 1):
        rhs = None
        for l in range(t):
            rhs = ec.add(rhs, ec.mul(pow(i, l, N), agg[l]))
        assert rhs == vk[i - 1]
    return DKGResult(n, t, sk, vk, agg, agg[0])


# ----------------------------------------------------------------------------- Giải mã một phần + Chaum-Pedersen


def _challenge(*pts: Point) -> int:
    h = hashlib.sha256(b"filetrust-dleq")
    for p in pts:
        h.update(ec.point_bytes(p))
    return int.from_bytes(h.digest(), "big") % N


def partial_decrypt(sk: int, vk: Point, c1: Point) -> tuple[Point, tuple[int, int]]:
    """D = sk * C1 kèm bằng chứng log_G(vk) = log_C1(D)."""
    d = ec.mul(sk, c1)
    w = _rand_scalar()
    a, b = ec.mul(w, G), ec.mul(w, c1)
    e = _challenge(G, c1, vk, d, a, b)
    z = (w + e * sk) % N
    return d, (e, z)


def verify_partial(vk: Point, c1: Point, d: Point, proof: tuple[int, int]) -> bool:
    e, z = proof
    a = ec.sub(ec.mul(z, G), ec.mul(e, vk))
    b = ec.sub(ec.mul(z, c1), ec.mul(e, d))
    return _challenge(G, c1, vk, d, a, b) == e


def lagrange_at_zero(indices: list[int]) -> dict[int, int]:
    lam = {}
    for i in indices:
        num, den = 1, 1
        for j in indices:
            if j != i:
                num = num * j % N
                den = den * (j - i) % N
        lam[i] = num * pow(den, -1, N) % N
    return lam


def combine(partials: dict[int, Point]) -> Point:
    """partials: {chỉ số SH (1..n) -> D_j}. Trả về S = r * PK."""
    lam = lagrange_at_zero(sorted(partials))
    acc = None
    for j, d in partials.items():
        acc = ec.add(acc, ec.mul(lam[j], d))
    return acc


def proofs_digest(proofs: list[tuple[int, int]]) -> bytes:
    h = hashlib.sha256()
    for e, z in proofs:
        h.update(e.to_bytes(32, "big") + z.to_bytes(32, "big"))
    return h.digest()


def keypair() -> tuple[int, Point]:
    sk = _rand_scalar()
    return sk, ec.mul(sk, G)
