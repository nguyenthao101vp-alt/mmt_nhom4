"""
================================================================================
THƯ VIỆN MẬT MÃ PYTHON - MỤC 1.3 & MODULE 2.3.2 (BẢO MẬT DỮ LIỆU CLIP)
================================================================================
Bao gồm đầy đủ các module chuẩn hóa cho TV4, TV5 (IPFS/Contract) và TV6 (Truy xuất):
1. AES-256-GCM: Mã hóa và xác thực dữ liệu clip (Confidentiality & Integrity Tag).
2. Rabin's IDA (Information Dispersal Algorithm) trên trường hữu hạn GF(2^8):
   - Chia thành n mảnh, đủ t mảnh để khôi phục.
   - Hỗ trợ cả tham số bài báo (n=6, t=4 -> giãn nở 1.5x, chịu mất 2 mảnh)
     và tham số tối ưu demo nhóm (n=4, t=3 -> giãn nở 1.33x, chịu mất 1 mảnh).
   - Lưu 8-byte header độ dài gốc để bảo toàn 100% file nhị phân (MP4/AES ciphertext).
3. Pedersen DKG & Feldman VSS:
   - Sinh khóa chung không cần bên tin cậy qua 2 vòng giao thức thực sự (không hardcode).
   - Hỗ trợ tham số bài báo (n=5, t=3) và tham số demo nhóm (n=3, t=2).
4. Threshold ElGamal + HKDF-SHA256 + KEM-DEM (Mục 2.2.4, Phương trình 19–22):
   - Phía KEM: Bọc khóa đối xứng K bằng ElGamal ngưỡng (tính toán đúng modulo q).
   - Phía KDF: Dẫn xuất khóa bọc KEK qua HKDF-SHA256.
   - Phía DEM: Mã hóa khóa K bằng AES-256-GCM.
5. Ví dụ số nhỏ (Small Number Examples) & Kiểm thử luồng End-to-End.
================================================================================
"""

import secrets
from typing import List, Tuple, Dict, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    raise ImportError("Vui lòng cài đặt thư viện cryptography: pip install cryptography")


# ==============================================================================
# CẤU HÌNH THAM SỐ NHÓM CYCLIC (RFC 3526 2048-BIT & THAM SỐ SỐ NHỎ)
# ==============================================================================

RFC3526_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
RFC3526_2048_Q = (RFC3526_2048_P - 1) // 2
RFC3526_2048_G = 4  # Phần tử sinh của nhóm con bậc nguyên tố q (4 = 2^2 mod p)
RFC3526_2048_H = pow(3, 2, RFC3526_2048_P)  # Phần tử sinh độc lập thứ hai cho cam kết Pedersen

# Bộ tham số số nhỏ (p = 47, q = 23) dùng cho ví dụ minh họa tay trong Mục 1.3
SMALL_P = 47
SMALL_Q = 23
SMALL_G = 4   # 4^23 mod 47 = 1
SMALL_H = 9   # 9^23 mod 47 = 1


# ==============================================================================
# 1. AES-256-GCM (MÃ HÓA VÀ XÁC THỰC DỮ LIỆU CLIP)
# ==============================================================================

class SymmetricCipher:
    """Xử lý sinh khóa 256-bit và mã hóa/giải mã xác thực AES-256-GCM."""

    @staticmethod
    def generate_key() -> bytes:
        """Sinh khóa đối xứng 256-bit (32 bytes) chuẩn CSPRNG (Mục 5.1 [FT])."""
        return secrets.token_bytes(32)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> Dict[str, bytes]:
        """Mã hóa và sinh thẻ xác thực GCM (16 bytes)."""
        if len(key) != 32:
            raise ValueError("Khóa AES-256 phải có độ dài đúng 32 bytes.")
        nonce = secrets.token_bytes(12)  # 96-bit IV chuẩn cho GCM
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        return {
            "ciphertext": ct_with_tag[:-16],
            "nonce": nonce,
            "tag": ct_with_tag[-16:],
        }

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """Giải mã và xác thực tính toàn vẹn dữ liệu."""
        if len(key) != 32:
            raise ValueError("Khóa AES-256 phải có độ dài đúng 32 bytes.")
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad)


# ==============================================================================
# 2. IDA CỦA RABIN TRÊN TRƯỜNG HỮU HẠN GF(2^8)
# ==============================================================================

class RabinIDA:
    """
    Phân tán dữ liệu chuẩn Rabin IDA trên GF(2^8) (đa thức bất khả quy 0x11B):
    - Gom mỗi khối đúng t byte (đa thức bậc t-1) -> hệ số giãn nở chính xác n/t
      (với n=6, t=4 dung lượng tăng đúng 1.5x và chịu mất tối đa 2 mảnh).
    - Gắn 8-byte header độ dài gốc giúp khôi phục chính xác file nhị phân có byte 0x00 ở cuối.
    """

    _GF_EXP = [0] * 512
    _GF_LOG = [0] * 256
    _INITIALIZED = False

    @classmethod
    def _init_gf256(cls) -> None:
        if cls._INITIALIZED:
            return
        # Phần tử sinh nguyên thủy 0x03 trên GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11B)
        x = 1
        for i in range(255):
            cls._GF_EXP[i] = x
            cls._GF_LOG[x] = i
            x_times_2 = (x << 1) ^ (0x11B if (x & 0x80) else 0)
            x = x_times_2 ^ x
        for i in range(255, 512):
            cls._GF_EXP[i] = cls._GF_EXP[i - 255]
        cls._INITIALIZED = True

    @classmethod
    def _gf_mul(cls, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return cls._GF_EXP[cls._GF_LOG[a] + cls._GF_LOG[b]]

    @classmethod
    def _gf_inv(cls, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("Không tồn tại nghịch đảo của 0 trong GF(2^8).")
        if a == 1:
            return 1
        return cls._GF_EXP[255 - cls._GF_LOG[a]]

    def __init__(self, n: int = 6, t: int = 4):
        if not (1 <= t <= n <= 255):
            raise ValueError("Yêu cầu 1 <= t <= n <= 255.")
        self._init_gf256()
        self.n = n
        self.t = t
        self.matrix = self._build_vandermonde_matrix(n, t)

    @classmethod
    def _build_vandermonde_matrix(cls, n: int, t: int) -> List[List[int]]:
        """Tạo ma trận phân tán Vandermonde n x t trên GF(2^8) đảm bảo mọi ma trận con t x t khả nghịch."""
        matrix = []
        for i in range(1, n + 1):
            row = []
            val = 1
            for _ in range(t):
                row.append(val)
                val = cls._gf_mul(val, i)
            matrix.append(row)
        return matrix

    @classmethod
    def _invert_matrix(cls, mat: List[List[int]]) -> List[List[int]]:
        """Nghịch đảo ma trận vuông t x t trên GF(2^8) bằng phương pháp khử Gauss-Jordan."""
        t = len(mat)
        aug = [row[:] + [1 if i == j else 0 for j in range(t)] for i, row in enumerate(mat)]

        for col in range(t):
            pivot = next((r for r in range(col, t) if aug[r][col] != 0), None)
            if pivot is None:
                raise ValueError("Ma trận con suy biến, không thể khôi phục dữ liệu.")
            aug[col], aug[pivot] = aug[pivot], aug[col]

            inv_pivot = cls._gf_inv(aug[col][col])
            for c in range(2 * t):
                aug[col][c] = cls._gf_mul(aug[col][c], inv_pivot)

            for r in range(t):
                if r != col and aug[r][col] != 0:
                    factor = aug[r][col]
                    for c in range(2 * t):
                        aug[r][c] ^= cls._gf_mul(factor, aug[col][c])

        return [row[t:] for row in aug]

    def distribute(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Chia dữ liệu thành n mảnh (index_1_based, share_bytes)."""
        orig_len = len(data)
        payload = orig_len.to_bytes(8, "big") + data
        pad_len = (self.t - (len(payload) % self.t)) % self.t
        payload += b"\x00" * pad_len

        num_cols = len(payload) // self.t
        shares: List[Tuple[int, bytes]] = []

        for row_idx in range(self.n):
            m_row = self.matrix[row_idx]
            mul_tables = [[self._gf_mul(m_row[r], b) for b in range(256)] for r in range(self.t)]
            share_buf = bytearray(num_cols)
            for c in range(num_cols):
                acc = 0
                for r in range(self.t):
                    acc ^= mul_tables[r][payload[r * num_cols + c]]
                share_buf[c] = acc
            shares.append((row_idx + 1, bytes(share_buf)))

        return shares

    def reconstruct(self, active_shares: List[Tuple[int, bytes]]) -> bytes:
        """Khôi phục nguyên vẹn dữ liệu gốc từ tối thiểu t mảnh bất kỳ."""
        if len(active_shares) < self.t:
            raise ValueError(f"Cần ít nhất {self.t} mảnh để khôi phục, hiện có {len(active_shares)}.")

        selected = active_shares[: self.t]
        sub_matrix = [self.matrix[idx - 1] for idx, _ in selected]
        inv_matrix = self._invert_matrix(sub_matrix)

        num_cols = len(selected[0][1])
        reconstructed = bytearray(num_cols * self.t)

        inv_tables = [
            [[self._gf_mul(inv_matrix[r][k], b) for b in range(256)] for k in range(self.t)]
            for r in range(self.t)
        ]

        for c in range(num_cols):
            for r in range(self.t):
                acc = 0
                for k in range(self.t):
                    acc ^= inv_tables[r][k][selected[k][1][c]]
                reconstructed[r * num_cols + c] = acc

        orig_len = int.from_bytes(reconstructed[:8], "big")
        return bytes(reconstructed[8 : 8 + orig_len])


# ==============================================================================
# 3. PEDERSEN DKG & FELDMAN VSS (SINH KHÓA PHÂN TÁN KHÔNG BÊN TIN CẬY)
# ==============================================================================

def _eval_polynomial(coeffs: List[int], x: int, q: int) -> int:
    """Tính giá trị đa thức f(x) = sum(a_k * x^k) mod q bằng lược đồ Horner."""
    res = 0
    for coeff in reversed(coeffs):
        res = (res * x + coeff) % q
    return res


class DKGNode:
    """Đại diện một nút đồng quản lý trong giao thức Pedersen DKG + Feldman VSS."""

    def __init__(self, node_id: int, n: int, t: int, p: int, q: int, g: int, h: int):
        self.id = node_id
        self.n = n
        self.t = t
        self.p = p
        self.q = q
        self.g = g
        self.h = h

        # Sinh 2 đa thức ngẫu nhiên bậc t-1 trên Z_q: f_i(x) và f'_i(x) (đa thức làm mù)
        self.f_coeffs = [secrets.randbelow(q - 1) + 1 for _ in range(t)]
        self.f_prime_coeffs = [secrets.randbelow(q - 1) + 1 for _ in range(t)]

        # Cam kết Pedersen C_{i,k} = g^{a_{i,k}} * h^{b_{i,k}} mod p
        self.pedersen_commitments = [
            (pow(g, a, p) * pow(h, b, p)) % p
            for a, b in zip(self.f_coeffs, self.f_prime_coeffs)
        ]
        # Cam kết Feldman A_{i,k} = g^{a_{i,k}} mod p để dựng khóa công khai chung Y
        self.feldman_commitments = [pow(g, a, p) for a in self.f_coeffs]

        self.received_shares: Dict[int, Tuple[int, int]] = {}
        self.sk_share: int = 0

    def create_share_for(self, target_id: int) -> Tuple[int, int]:
        return (
            _eval_polynomial(self.f_coeffs, target_id, self.q),
            _eval_polynomial(self.f_prime_coeffs, target_id, self.q),
        )

    def verify_and_accept_share(
        self, sender_id: int, share: Tuple[int, int], pedersen_comms: List[int]
    ) -> bool:
        """Kiểm chứng mảnh chia sẻ nhận được bằng cam kết Pedersen VSS."""
        s_ij, s_prime_ij = share
        lhs = (pow(self.g, s_ij, self.p) * pow(self.h, s_prime_ij, self.p)) % self.p

        rhs = 1
        x_pow = 1
        for c_k in pedersen_comms:
            rhs = (rhs * pow(c_k, x_pow, self.p)) % self.p
            x_pow = (x_pow * self.id) % self.q

        if lhs != rhs:
            return False
        self.received_shares[sender_id] = share
        return True

    def compute_final_secret_share(self) -> int:
        """Tổng hợp khóa bí mật thành phần x_j = sum_i s_{i,j} mod q."""
        self.sk_share = sum(s[0] for s in self.received_shares.values()) % self.q
        return self.sk_share


# ==============================================================================
# 4. THRESHOLD ELGAMAL, HKDF-SHA256 & KEM-DEM (MỤC 2.2.4, PT 19–22)
# ==============================================================================

class ThresholdCryptoSystem:
    """
    Hệ mật ngưỡng hoàn chỉnh kết nối Pedersen DKG -> Threshold ElGamal -> HKDF -> AES-256-GCM:
    - Mọi phép toán số mũ và nội suy Lagrange thực hiện chính xác trên trường Z_q.
    - KEM bọc khóa đối xứng K của clip bằng khóa công khai chung Y của nhóm đồng quản lý.
    """

    def __init__(
        self,
        n: int = 5,
        t: int = 3,
        p: int = RFC3526_2048_P,
        q: int = RFC3526_2048_Q,
        g: int = RFC3526_2048_G,
        h: int = RFC3526_2048_H,
    ):
        self.n = n
        self.t = t
        self.p = p
        self.q = q
        self.g = g
        self.h = h

    def generate_dkg_keys(self) -> Tuple[int, Dict[int, int]]:
        """Chạy giao thức DKG Pedersen 2 vòng giữa n nút, trả về (PK_chung, {node_id: sk_i})."""
        nodes = [DKGNode(i, self.n, self.t, self.p, self.q, self.g, self.h) for i in range(1, self.n + 1)]

        # Vòng 1: Phát tán mảnh và kiểm chứng VSS
        for sender in nodes:
            for receiver in nodes:
                share = sender.create_share_for(receiver.id)
                if not receiver.verify_and_accept_share(sender.id, share, sender.pedersen_commitments):
                    raise RuntimeError(f"Kiểm chứng VSS thất bại từ nút {sender.id} tới nút {receiver.id}.")

        # Vòng 2: Tổng hợp khóa bí mật thành phần và khóa công khai chung Y
        secret_shares = {node.id: node.compute_final_secret_share() for node in nodes}
        joint_public_key = 1
        for node in nodes:
            joint_public_key = (joint_public_key * node.feldman_commitments[0]) % self.p

        return joint_public_key, secret_shares

    def _derive_kek(self, shared_secret_z: int, info: bytes = b"FileTrust-KEM-DEM-v1") -> bytes:
        """KDF: Dẫn xuất khóa bọc KEK 256-bit từ bí mật chung Z = g^{r*x} mod p bằng HKDF-SHA256."""
        byte_len = (self.p.bit_length() + 7) // 8
        ikm = shared_secret_z.to_bytes(byte_len, "big")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(ikm)

    def kem_dem_encapsulate_key(self, joint_public_key: int, clip_aes_key: bytes) -> Dict[str, object]:
        """
        Đóng gói khóa đối xứng K của clip bằng KEM-DEM (Phương trình 19–22 [FT]):
        - Phía KEM: Sinh r ngẫu nhiên trong Z_q*, tính C1 = g^r mod p, Z = Y^r mod p -> KEK = HKDF(Z).
        - Phía DEM: Dùng KEK mã hóa AES-256-GCM khóa K tạo C_DEM.
        """
        r = secrets.randbelow(self.q - 1) + 1
        c1 = pow(self.g, r, self.p)
        shared_z = pow(joint_public_key, r, self.p)

        kek = self._derive_kek(shared_z)
        byte_len = (self.p.bit_length() + 7) // 8
        dem_pkg = SymmetricCipher.encrypt(clip_aes_key, kek, aad=c1.to_bytes(byte_len, "big"))

        return {
            "c1": c1,
            "c_dem": dem_pkg["ciphertext"],
            "nonce": dem_pkg["nonce"],
            "tag": dem_pkg["tag"],
        }

    def partial_decrypt(self, c1: int, node_id: int, sk_share: int) -> Tuple[int, int]:
        """Mỗi nút đồng quản lý tính mảnh giải mã từng phần d_i = C1^{sk_i} mod p khi phê duyệt."""
        return node_id, pow(c1, sk_share, self.p)

    def _lagrange_coeff(self, i: int, active_ids: List[int]) -> int:
        """Tính hệ số nội suy Lagrange lambda_i tại x = 0 trên trường Z_q (modulo q)."""
        num, den = 1, 1
        for j in active_ids:
            if i != j:
                num = (num * (-j)) % self.q
                den = (den * (i - j)) % self.q
        return (num * pow(den, -1, self.q)) % self.q

    def kem_dem_decapsulate_key(
        self, encapsulated_pkg: Dict[str, object], partial_shares: List[Tuple[int, int]]
    ) -> bytes:
        """
        Tái tạo khóa K từ t mảnh phê duyệt (Mục 2.4.3 - thời gian t_xh):
        Z = prod_{i in S} (d_i)^{lambda_i} mod p -> KEK = HKDF(Z) -> giải mã DEM khôi phục khóa K.
        """
        if len(partial_shares) < self.t:
            raise ValueError(f"Cần ít nhất {self.t} bên phê duyệt, hiện chỉ có {len(partial_shares)}.")

        selected = partial_shares[: self.t]
        active_ids = [nid for nid, _ in selected]

        shared_z = 1
        for nid, d_i in selected:
            lam = self._lagrange_coeff(nid, active_ids)
            shared_z = (shared_z * pow(d_i, lam, self.p)) % self.p

        kek = self._derive_kek(shared_z)
        byte_len = (self.p.bit_length() + 7) // 8
        return SymmetricCipher.decrypt(
            ciphertext=encapsulated_pkg["c_dem"],
            key=kek,
            nonce=encapsulated_pkg["nonce"],
            tag=encapsulated_pkg["tag"],
            aad=encapsulated_pkg["c1"].to_bytes(byte_len, "big"),
        )


# ==============================================================================
# 5. VÍ DỤ SỐ NHỎ & KIỂM THỬ TOÀN LUỒNG END-TO-END
# ==============================================================================

def demo_small_numbers() -> None:
    """Ví dụ số nhỏ (p = 47, q = 23, g = 4, h = 9) giúp cả nhóm kiểm tra toán học bằng tay."""
    print("=== [A] VÍ DỤ SỐ NHỎ MINH HỌA CHO BÁO CÁO MỤC 1.3 (p=47, q=23, n=5, t=3) ===")
    small_sys = ThresholdCryptoSystem(n=5, t=3, p=SMALL_P, q=SMALL_Q, g=SMALL_G, h=SMALL_H)
    joint_y, shares = small_sys.generate_dkg_keys()
    print(f"1. Pedersen DKG (5,3) sinh khóa công khai chung Y = {joint_y} (mod {SMALL_P})")
    print(f"   Khóa bí mật thành phần các nút (mod {SMALL_Q}): {shares}")

    clip_key = SymmetricCipher.generate_key()
    kem_pkg = small_sys.kem_dem_encapsulate_key(joint_y, clip_key)
    print(f"2. KEM-DEM đóng gói khóa K -> C1 = {kem_pkg['c1']}, C_DEM = {kem_pkg['c_dem'].hex()[:16]}...")

    # Chọn 3 nút bất kỳ phê duyệt: nút 1, 3, 5
    approvals = [small_sys.partial_decrypt(kem_pkg["c1"], nid, shares[nid]) for nid in [1, 3, 5]]
    recovered_key = small_sys.kem_dem_decapsulate_key(kem_pkg, approvals)
    assert recovered_key == clip_key
    print("3. Tái tạo khóa K từ 3/5 nút phê duyệt thành công 100%!\n")


def demo_full_production_pipeline() -> None:
    """Kiểm thử toàn luồng Upload (TV5) -> Truy xuất (TV6) với tham số bài báo [FT]."""
    print("=== [B] KIỂM THỬ TOÀN LUỒNG CHUẨN 2048-BIT: IDA(6,4) & DKG(5,3) ===")
    # Giả lập dữ liệu nhị phân kết thúc bằng nhiều byte 0x00 để kiểm chứng độ an toàn của IDA
    raw_clip = b"CAMERA_HANH_TRINH_2026_DATA_" * 1000 + b"\x00\x00\x00\x00"

    # Bước 1: TV4/TV5 mã hóa clip bằng AES-256-GCM
    k_clip = SymmetricCipher.generate_key()
    enc_clip = SymmetricCipher.encrypt(raw_clip, k_clip)

    # Bước 2: Phân mảnh ciphertext bằng Rabin IDA (6, 4) -> giãn nở đúng 1.5 lần
    ida = RabinIDA(n=6, t=4)
    shares = ida.distribute(enc_clip["ciphertext"])
    ratio = (len(shares) * len(shares[0][1])) / len(enc_clip["ciphertext"])
    print(f"1. Rabin IDA (6,4): {len(enc_clip['ciphertext'])}B -> 6 mảnh x {len(shares[0][1])}B (Hệ số giãn nở: {ratio:.2f}x)")

    # Bước 3: Bọc khóa K bằng KEM-DEM với khóa chung DKG (5, 3)
    crypto_sys = ThresholdCryptoSystem(n=5, t=3)
    joint_y, node_shares = crypto_sys.generate_dkg_keys()
    kem_pkg = crypto_sys.kem_dem_encapsulate_key(joint_y, k_clip)
    print("2. Đã đóng gói khóa K bằng KEM-DEM (HKDF-SHA256 + AES-256-GCM).")

    # Bước 4: TV6 truy xuất khi mất 2 mảnh IPFS (chỉ lấy mảnh 1, 2, 4, 6) & 3 nút phê duyệt (2, 4, 5)
    approvals = [crypto_sys.partial_decrypt(kem_pkg["c1"], nid, node_shares[nid]) for nid in [2, 4, 5]]
    recovered_k = crypto_sys.kem_dem_decapsulate_key(kem_pkg, approvals)

    available_4_shares = [shares[0], shares[1], shares[3], shares[5]]
    recovered_ct = ida.reconstruct(available_4_shares)
    recovered_clip = SymmetricCipher.decrypt(recovered_ct, recovered_k, enc_clip["nonce"], enc_clip["tag"])

    assert recovered_clip == raw_clip
    print("3. Khôi phục toàn vẹn 100% dữ liệu gốc (bao gồm cả các byte 0x00 ở cuối)!")


if __name__ == "__main__":
    demo_small_numbers()
    demo_full_production_pipeline()
