import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ==============================================================================
# 1. THAM SỐ HỆ THỐNG (NHÓM CYCLIC BẬC NGUYÊN TỐ q, SAFE PRIME p = 2q + 1)
# ==============================================================================
# RFC 3526 - 2048-bit MODP Group (Group 14)
RFC3526_P_HEX = (
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
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)


@dataclass(frozen=True)
class PublicParams:
    """Tham số công khai pp = (p, q, g) từ VSS.Setup(1^k) [Mục 2.2.2]."""
    p: int
    q: int
    g: int  # Phần tử sinh nhóm con G bậc q trong Z_p^*

    @classmethod
    def default_2048bit(cls) -> "PublicParams":
        p = int(RFC3526_P_HEX, 16)
        q = (p - 1) // 2
        g = 4  # 2^2 mod p luôn sinh nhóm con thặng dư bậc hai bậc q
        return cls(p=p, q=q, g=g)

    @classmethod
    def small_demo(cls) -> "PublicParams":
        """Tham số số nhỏ p=47, q=23, g=4 dùng để kiểm chứng ví dụ tính tay."""
        return cls(p=47, q=23, g=4)


# ==============================================================================
# 2. MÃ HÓA ĐỐI XỨNG XÁC THỰC (AES-256-GCM)
# ==============================================================================
class SymmetricCipher:
    """Mã hóa và xác thực toàn vẹn dữ liệu video gốc bằng AES-256-GCM."""

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)  # 256-bit key

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """Trả về (ciphertext, iv_nonce_12B, auth_tag_16B)."""
        if len(key) != 32:
            raise ValueError("Khóa AES-256-GCM phải dài đúng 32 bytes (256 bit).")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        return ct_with_tag[:-16], nonce, ct_with_tag[-16:]

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, aad: Optional[bytes] = None) -> bytes:
        """Giải mã và kiểm tra thẻ xác thực GCM. Ném InvalidTag nếu dữ liệu bị sửa đổi."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad)


# ==============================================================================
# 3. THUẬT TOÁN PHÂN TÁN THÔNG TIN RABIN IDA TRÊN TRƯỜNG GF(2^8)
# ==============================================================================
class GF256:
    """Số học trường hữu hạn GF(2^8) với đa thức bất khả quy AES: x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    EXP = [0] * 512
    LOG = [0] * 256

    @classmethod
    def _init_tables(cls):
        if cls.EXP[0] != 0:
            return
        x = 1
        for i in range(255):
            cls.EXP[i] = x
            cls.LOG[x] = i
            # Nhân x với phần tử sinh 0x03 trong GF(2^8)
            x_times_2 = ((x << 1) ^ 0x1B) & 0xFF if (x & 0x80) else (x << 1)
            x = x_times_2 ^ x
        for i in range(255, 512):
            cls.EXP[i] = cls.EXP[i - 255]

    @classmethod
    def mul(cls, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return cls.EXP[cls.LOG[a] + cls.LOG[b]]

    @classmethod
    def inv(cls, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("Không tồn tại nghịch đảo của 0 trong GF(2^8).")
        return cls.EXP[255 - cls.LOG[a]]


GF256._init_tables()


class RabinIDA:
    """
    Rabin's Information Dispersal Algorithm [Mục 2.1.1, Eqs. (1)-(2)].
    Phân tán dữ liệu D thành n mảnh P_i, khôi phục từ bất kỳ t mảnh nào.
    """

    def __init__(self, n: int = 6, t: int = 4):
        if not (1 <= t <= n <= 255):
            raise ValueError("Tham số IDA phải thỏa mãn 1 <= t <= n <= 255.")
        self.n = n
        self.t = t
        # Ma trận phân tán Cauchy E kích thước n x t trên GF(2^8) (mọi ma trận con t x t đều khả nghịch)
        self.encoding_matrix = self._build_cauchy_matrix(n, t)

    @staticmethod
    def _build_cauchy_matrix(n: int, t: int) -> List[List[int]]:
        # Chọn tập X = {0..n-1} và Y = {n..n+t-1} đôi một phân biệt trong GF(2^8)
        matrix = []
        for i in range(n):
            row = []
            for j in range(t):
                x_i = i
                y_j = n + j
                row.append(GF256.inv(x_i ^ y_j))
            matrix.append(row)
        return matrix

    def disperse(self, data: bytes) -> List[Tuple[int, bytes]]:
        """
        IDA.disperse(D, n, t) -> [(index_i, piece_P_i), ...] [Eq. (1)].
        Gắn 8 byte header lưu độ dài gốc để khôi phục chính xác file nhị phân.
        """
        payload = len(data).to_bytes(8, "big") + data
        pad_len = (-len(payload)) % self.t
        payload += b"\x00" * pad_len
        cols = len(payload) // self.t

        # Sắp xếp dữ liệu thành ma trận M kích thước t x cols
        M = [payload[r * cols : (r + 1) * cols] for r in range(self.t)]

        pieces = []
        for i in range(self.n):
            row_E = self.encoding_matrix[i]
            piece_bytes = bytearray(cols)
            for c in range(cols):
                acc = 0
                for r in range(self.t):
                    acc ^= GF256.mul(row_E[r], M[r][c])
                piece_bytes[c] = acc
            pieces.append((i + 1, bytes(piece_bytes)))
        return pieces

    def reconstruct(self, pieces: List[Tuple[int, bytes]]) -> bytes:
        """
        IDA.reconstruct({P_i}_{i in T}) -> D [Eq. (2)].
        Dùng khử Gauss-Jordan tìm nghịch đảo ma trận con E' kích thước t x t.
        """
        if len(pieces) < self.t:
            raise ValueError(f"Cần tối thiểu {self.t} mảnh để khôi phục, hiện chỉ có {len(pieces)}.")

        selected = pieces[: self.t]
        indices = [idx - 1 for idx, _ in selected]
        piece_data = [p for _, p in selected]
        cols = len(piece_data[0])

        # Trích xuất ma trận con E' (t x t) và tính nghịch đảo trên GF(2^8)
        sub_E = [list(self.encoding_matrix[idx]) for idx in indices]
        inv_E = self._invert_matrix_gf256(sub_E)

        # M = (E')^{-1} * [P_{i1}, ..., P_{it}]^T
        reconstructed_rows = []
        for r in range(self.t):
            row_bytes = bytearray(cols)
            for c in range(cols):
                acc = 0
                for k in range(self.t):
                    acc ^= GF256.mul(inv_E[r][k], piece_data[k][c])
                row_bytes[c] = acc
            reconstructed_rows.append(bytes(row_bytes))

        raw_padded = b"".join(reconstructed_rows)
        orig_len = int.from_bytes(raw_padded[:8], "big")
        return raw_padded[8 : 8 + orig_len]

    @staticmethod
    def _invert_matrix_gf256(mat: List[List[int]]) -> List[List[int]]:
        t = len(mat)
        aug = [mat[i] + [1 if i == j else 0 for j in range(t)] for i in range(t)]

        for col in range(t):
            pivot = next((r for r in range(col, t) if aug[r][col] != 0), None)
            if pivot is None:
                raise ValueError("Ma trận con suy biến, không thể nghịch đảo.")
            aug[col], aug[pivot] = aug[pivot], aug[col]

            inv_pivot = GF256.inv(aug[col][col])
            for c in range(2 * t):
                aug[col][c] = GF256.mul(aug[col][c], inv_pivot)

            for r in range(t):
                if r != col and aug[r][col] != 0:
                    factor = aug[r][col]
                    for c in range(2 * t):
                        aug[r][c] ^= GF256.mul(factor, aug[col][c])

        return [row[t:] for row in aug]


# ==============================================================================
# 4. FELDMAN VSS & PEDERSEN DKG 
# ==============================================================================
class FeldmanVSS:
    """Chia sẻ bí mật có thể kiểm chứng Feldman (VSS.Share, VSS.Verify, VSS.Reconstruct)."""

    @staticmethod
    def share(secret: int, t: int, n: int, pp: PublicParams) -> Tuple[Dict[int, int], List[int]]:
        """
        Sinh đa thức f(x) bậc t-1 với a_0 = secret, trả về:
        - shares: {j: f(j) mod q} cho j = 1..n
        - commitments: [C_0, ..., C_{t-1}] với C_l = g^{a_l} mod p
        """
        coeffs = [secret % pp.q] + [secrets.randbelow(pp.q - 1) + 1 for _ in range(t - 1)]
        commitments = [pow(pp.g, a_l, pp.p) for a_l in coeffs]

        shares = {}
        for j in range(1, n + 1):
            val = 0
            for power, coeff in enumerate(coeffs):
                val = (val + coeff * pow(j, power, pp.q)) % pp.q
            shares[j] = val
        return shares, commitments

    @staticmethod
    def verify(index_j: int, share_val: int, commitments: List[int], pp: PublicParams) -> bool:
        """Kiểm tra g^{s_j} == prod_{l=0}^{t-1} (C_l)^{j^l} mod p [Eq. (7) & Eq. (31)]."""
        lhs = pow(pp.g, share_val, pp.p)
        rhs = 1
        for l, c_l in enumerate(commitments):
            rhs = (rhs * pow(c_l, pow(index_j, l, pp.q), pp.p)) % pp.p
        return lhs == rhs


class ShareholderNode:
    """
    Đại diện một cổ đông SH_i trong giao thức Pedersen DKG và ElGamal ngưỡng [Mục 4.1].
    """

    def __init__(self, index: int, n_sh: int, t_sh: int, pp: PublicParams):
        self.index = index  # i in {1..n_sh}
        self.n_sh = n_sh
        self.t_sh = t_sh
        self.pp = pp

        # Bí mật đóng góp cục bộ s_i và đa thức f_i(x)
        self._secret_contrib = secrets.randbelow(pp.q - 1) + 1
        self.sent_shares, self.commitments = FeldmanVSS.share(
            self._secret_contrib, t_sh, n_sh, pp
        )

        self.sk_share: Optional[int] = None  # Mảnh khóa bí mật tổng hợp sk_j
        self.vk: Optional[int] = None        # Khóa xác minh công khai vk_j = g^{sk_j} mod p
        self.master_pk: Optional[int] = None # Khóa công khai chung PK

    def finalize_dkg(
        self,
        received_shares: Dict[int, int],
        all_commitments: Dict[int, List[int]],
    ) -> Tuple[int, int]:
        """
        Kiểm chứng chéo mọi mảnh s_{i,j} từ SH_i, tổng hợp sk_j, vk_j và PK [Eqs. (14)-(16)].
        """
        for sender_idx, s_ij in received_shares.items():
            if not FeldmanVSS.verify(self.index, s_ij, all_commitments[sender_idx], self.pp):
                raise ValueError(f"SH_{self.index} phát hiện mảnh gian lận từ SH_{sender_idx}!")

        self.sk_share = sum(received_shares.values()) % self.pp.q
        self.vk = pow(self.pp.g, self.sk_share, self.pp.p)

        pk = 1
        for sender_idx in range(1, self.n_sh + 1):
            pk = (pk * all_commitments[sender_idx][0]) % self.pp.p
        self.master_pk = pk
        return self.vk, self.master_pk

    def partial_decrypt(self, c1: int) -> Tuple[int, Tuple[int, int]]:
        """
        TElG.partdec(sk_i, (c1, c2)) -> (delta_i, pi_i) [Eqs. (23)-(24)].
        Tính mảnh giải mã từng phần delta_i = c1^{sk_i} mod p kèm bằng chứng ZKP Chaum-Pedersen.
        """
        if self.sk_share is None or self.vk is None:
            raise RuntimeError("Node chưa hoàn tất DKG.")
        delta_i = pow(c1, self.sk_share, self.pp.p)

        # Bằng chứng Chaum-Pedersen chứng minh log_g(vk_i) == log_{c1}(delta_i)
        w = secrets.randbelow(self.pp.q - 1) + 1
        A = pow(self.pp.g, w, self.pp.p)
        B = pow(c1, w, self.pp.p)
        e = self._chaum_pedersen_challenge(c1, self.vk, delta_i, A, B)
        z = (w + e * self.sk_share) % self.pp.q
        return delta_i, (e, z)

    def _chaum_pedersen_challenge(self, c1: int, vk_i: int, delta_i: int, A: int, B: int) -> int:
        h = hashlib.sha256()
        for val in (self.pp.g, c1, vk_i, delta_i, A, B):
            h.update(val.to_bytes((val.bit_length() + 7) // 8 or 1, "big"))
        return int.from_bytes(h.digest(), "big") % self.pp.q


def run_dkg_ceremony(n_sh: int, t_sh: int, pp: PublicParams) -> Tuple[List[ShareholderNode], int]:
    """Điều phối chạy thử nghi thức Pedersen DKG cho n_sh cổ đông."""
    nodes = [ShareholderNode(i, n_sh, t_sh, pp) for i in range(1, n_sh + 1)]
    all_commitments = {node.index: node.commitments for node in nodes}

    master_pk = 0
    for receiver in nodes:
        inbox = {sender.index: sender.sent_shares[receiver.index] for sender in nodes}
        _, pk = receiver.finalize_dkg(inbox, all_commitments)
        master_pk = pk
    return nodes, master_pk


# ==============================================================================
# 5. ELGAMAL NGƯỠNG (TElG) & LAI GHÉP KEM-DEM + HKDF-SHA256 [Mục 2.2.4, Eqs. (18)-(27)]
# ==============================================================================
class ThresholdElGamalKEMDEM:
    """
    Thực thi ElGamal ngưỡng (TElG) kết hợp KDF (HKDF-SHA256) và DEM:
    - Hỗ trợ đầy đủ phương trình (19)-(22) bảo vệ CID theo FileTrust.
    - Hỗ trợ phương trình (18)-(27) đóng gói khóa phiên K (256-bit) của video clip.
    """

    def __init__(self, pp: PublicParams):
        self.pp = pp

    def _encode_to_subgroup(self, key_bytes: bytes) -> int:
        """
        Ánh xạ khóa 256-bit (hoặc số nguyên < q) vào nhóm con G bậc q trong Z_p^*.
        Vì p = 2q + 1 là safe prime, với m_raw in [1, q-1], m_bar = (m_raw^2) mod p luôn thuộc G.
        """
        m_raw = (int.from_bytes(key_bytes, "big") % (self.pp.q - 2)) + 2
        return pow(m_raw, 2, self.pp.p), m_raw

    def _decode_from_subgroup(self, m_bar: int) -> int:
        """Lấy căn bậc hai chính tắc trong [2, q-1] khi p % 4 == 3."""
        # Với RFC 3526 p và p=47, p % 4 == 3 nên căn bậc hai modulo p là m_bar^{(p+1)/4} mod p
        root = pow(m_bar, (self.pp.p + 1) // 4, self.pp.p)
        return root if root <= self.pp.q else (self.pp.p - root)

    def _lagrange_coeff(self, i: int, subset_T: List[int]) -> int:
        """Tính hệ số nội suy Lagrange lambda_{i,T} tại x = 0 trên Z_q [Eq. (10)]."""
        num = 1
        den = 1
        for j in subset_T:
            if j != i:
                num = (num * j) % self.pp.q
                den = (den * (j - i)) % self.pp.q
        return (num * pow(den, -1, self.pp.q)) % self.pp.q

    def verify_partial_proof(self, c1: int, vk_i: int, delta_i: int, proof: Tuple[int, int]) -> bool:
        """Kiểm tra bằng chứng Chaum-Pedersen pi_i = (e, z) [Eq. (25)]."""
        e, z = proof
        inv_vk_e = pow(pow(vk_i, e, self.pp.p), -1, self.pp.p)
        inv_delta_e = pow(pow(delta_i, e, self.pp.p), -1, self.pp.p)

        A_check = (pow(self.pp.g, z, self.pp.p) * inv_vk_e) % self.pp.p
        B_check = (pow(c1, z, self.pp.p) * inv_delta_e) % self.pp.p

        h = hashlib.sha256()
        for val in (self.pp.g, c1, vk_i, delta_i, A_check, B_check):
            h.update(val.to_bytes((val.bit_length() + 7) // 8 or 1, "big"))
        e_check = int.from_bytes(h.digest(), "big") % self.pp.q
        return e == e_check

    # --- 5A. Đóng gói & Mở gói phần tử nhóm qua TElG [Eqs. (18), (26), (27)] ---
    def telg_encrypt(self, m_bar: int, master_pk: int) -> Tuple[int, int]:
        """TElG.enc(m_bar, PK) -> (c1, c2) [Eq. (18)]."""
        r = secrets.randbelow(self.pp.q - 1) + 1
        c1 = pow(self.pp.g, r, self.pp.p)
        c2 = (m_bar * pow(master_pk, r, self.pp.p)) % self.pp.p
        return c1, c2

    def telg_combine(
        self,
        c1: int,
        c2: int,
        partials: Dict[int, Tuple[int, Tuple[int, int]]],
        vks: Dict[int, int],
    ) -> int:
        """TElG.comb({(delta_i, pi_i)}_{i in T}, (c1, c2)) -> m_bar [Eqs. (26)-(27)]."""
        subset_T = list(partials.keys())
        delta = 1
        for i in subset_T:
            delta_i, pi_i = partials[i]
            if not self.verify_partial_proof(c1, vks[i], delta_i, pi_i):
                raise ValueError(f"Bằng chứng ZKP giải mã từng phần của SH_{i} không hợp lệ!")
            lam = self._lagrange_coeff(i, subset_T)
            delta = (delta * pow(delta_i, lam, self.pp.p)) % self.pp.p

        m_bar = (c2 * pow(delta, -1, self.pp.p)) % self.pp.p
        return m_bar

    # --- 5B. Cơ chế bảo vệ CID theo FileTrust [Eqs. (19)-(22)] ---
    @staticmethod
    def derive_kdf_stream(k_bytes: bytes, context: bytes, length: int) -> bytes:
        """S_i = KDF(K_i, ctx_i, |CID_i|) dùng HKDF-SHA256 [Eq. (20)]."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=context,
        )
        return hkdf.derive(k_bytes)

    def protect_cid_filetrust(
        self, cid_str: str, context: bytes, master_pk: int
    ) -> Dict[str, object]:
        """
        Thực thi trọn vẹn Phương trình (19)-(22) bảo vệ một CID:
        1. K_i <- {0,1}^256
        2. S_i = HKDF-SHA256(K_i, ctx_i, |CID_i|)
        3. ctSym_i = S_i XOR CID_i
        4. (c1, c2) = TElG.enc(encode(K_i), PK)
        """
        cid_bytes = cid_str.encode("utf-8")
        k_i = secrets.token_bytes(32)  # Eq. (19)
        s_i = self.derive_kdf_stream(k_i, context, len(cid_bytes))  # Eq. (20)
        ct_sym = bytes(a ^ b for a, b in zip(s_i, cid_bytes))  # Eq. (21)

        # Ánh xạ K_i (256-bit < q của nhóm 2048-bit) vào G để đóng gói TElG [Eq. (22)]
        k_int = int.from_bytes(k_i, "big")
        k_bar = pow(k_int, 2, self.pp.p)
        c1, c2 = self.telg_encrypt(k_bar, master_pk)

        return {"c1": c1, "c2": c2, "ctSym": ct_sym}

    def recover_cid_filetrust(
        self,
        protected_tuple: Dict[str, object],
        context: bytes,
        partials: Dict[int, Tuple[int, Tuple[int, int]]],
        vks: Dict[int, int],
    ) -> str:
        """Khôi phục CID gốc từ (c1, c2, ctSym) sau khi thu thập đủ t_SH mảnh giải mã."""
        c1 = int(protected_tuple["c1"])
        c2 = int(protected_tuple["c2"])
        ct_sym = bytes(protected_tuple["ctSym"])

        k_bar = self.telg_combine(c1, c2, partials, vks)
        k_int = self._decode_from_subgroup(k_bar)
        k_i = k_int.to_bytes(32, "big")

        s_i = self.derive_kdf_stream(k_i, context, len(ct_sym))
        cid_bytes = bytes(a ^ b for a, b in zip(ct_sym, s_i))
        return cid_bytes.decode("utf-8")

    # --- 5C. Cơ chế tối ưu của nhóm: Đóng gói duy nhất khóa video K qua KEM-DEM ---
    def encapsulate_clip_key(self, clip_key: bytes, master_pk: int, clip_id: str) -> Dict[str, object]:
        """
        Đóng gói khóa đối xứng K (32 bytes) của video bằng TElG + HKDF-SHA256 + AES-GCM:
        - KEM: sinh khóa bọc ngẫu nhiên Z_seed, đóng gói bằng TElG -> (c1, c2)
        - KDF: KEK = HKDF-SHA256(Z_seed, clip_id)
        - DEM: mã hóa xác thực clip_key bằng KEK (AAD = c1) -> (c_dem, iv_kem, tag_kem)
        """
        z_seed = secrets.token_bytes(32)
        z_int = int.from_bytes(z_seed, "big")
        z_bar = pow(z_int, 2, self.pp.p)
        c1, c2 = self.telg_encrypt(z_bar, master_pk)

        kek = self.derive_kdf_stream(z_seed, f"KEM-KEK:{clip_id}".encode(), 32)
        aad = c1.to_bytes((c1.bit_length() + 7) // 8, "big")
        c_dem, iv_kem, tag_kem = SymmetricCipher.encrypt(clip_key, kek, aad=aad)

        return {
            "c1": c1,
            "c2": c2,
            "c_dem": c_dem,
            "iv_kem": iv_kem,
            "tag_kem": tag_kem,
        }

    def decapsulate_clip_key(
        self,
        kem_package: Dict[str, object],
        clip_id: str,
        partials: Dict[int, Tuple[int, Tuple[int, int]]],
        vks: Dict[int, int],
    ) -> bytes:
        """Tái tạo khóa đối xứng K của video khi có đủ t_SH cổ đông phê duyệt."""
        c1 = int(kem_package["c1"])
        c2 = int(kem_package["c2"])
        z_bar = self.telg_combine(c1, c2, partials, vks)
        z_int = self._decode_from_subgroup(z_bar)
        z_seed = z_int.to_bytes(32, "big")

        kek = self.derive_kdf_stream(z_seed, f"KEM-KEK:{clip_id}".encode(), 32)
        aad = c1.to_bytes((c1.bit_length() + 7) // 8, "big")
        return SymmetricCipher.decrypt(
            bytes(kem_package["c_dem"]),
            kek,
            bytes(kem_package["iv_kem"]),
            bytes(kem_package["tag_kem"]),
            aad=aad,
        )


# ==============================================================================
# 6. KIỂM THỬ TOÀN BỘ LUỒNG HOẠT ĐỘNG (END-TO-END DEMO)
# ==============================================================================
if __name__ == "__main__":
    print("=== KHỞI TẠO HỆ THỐNG FILETRUST (2048-BIT SAFE PRIME) ===")
    pp = PublicParams.default_2048bit()

    # 1. Nghi thức Pedersen DKG cho (n_SH=5, t_SH=3) theo bài báo FileTrust
    n_sh, t_sh = 5, 3
    shareholders, master_pk = run_dkg_ceremony(n_sh, t_sh, pp)
    vks = {sh.index: sh.vk for sh in shareholders}
    print(f"[1] DKG hoàn tất với ({n_sh}, {t_sh}). Master PK bit-length: {master_pk.bit_length()} bits")

    # 2. Data Owner mã hóa video bằng chứng bằng AES-256-GCM và phân tán IDA (6, 4)
    raw_video = b"EVIDENCE_VIDEO_FRAME_DATA_" * 5000  # ~130 KB dữ liệu nhị phân
    clip_key = SymmetricCipher.generate_key()
    ciphertext, iv_clip, tag_clip = SymmetricCipher.encrypt(raw_video, clip_key)

    ida = RabinIDA(n=6, t=4)
    pieces = ida.disperse(ciphertext)
    # Giả lập IPFS băm nội dung từng mảnh thành CID
    ipfs_storage = {}
    cids = []
    for idx, piece_bytes in pieces:
        cid = "Qm" + hashlib.sha256(piece_bytes).hexdigest()[:44]
        ipfs_storage[cid] = piece_bytes
        cids.append(cid)
    print(f"[2] Đã phân tán thành {len(pieces)} mảnh IDA lên IPFS. Mẫu CID[0]: {cids[0]}")

    # 3. Bảo vệ khóa clip K bằng KEM-DEM (cách tối ưu on-chain của nhóm)
    kem_dem = ThresholdElGamalKEMDEM(pp)
    clip_id = "CAM04_20261125_001"
    kem_pkg = kem_dem.encapsulate_clip_key(clip_key, master_pk, clip_id)

    # Kiểm thử song song cơ chế bảo vệ từng CID theo đúng Eq. (19)-(22) của FileTrust
    ctx_0 = f"{clip_id}:batch1:0".encode()
    protected_cid0 = kem_dem.protect_cid_filetrust(cids[0], ctx_0, master_pk)
    print("[3] Đã đóng gói khóa K và bảo vệ CID theo KEM-DEM thành công.")

    # 4. Truy xuất bằng chứng với ngưỡng t_SH = 3 cổ đông (SH_1, SH_3, SH_5 phê duyệt)
    approving_nodes = [shareholders[0], shareholders[2], shareholders[4]]
    partials_clip = {sh.index: sh.partial_decrypt(kem_pkg["c1"]) for sh in approving_nodes}
    recovered_clip_key = kem_dem.decapsulate_clip_key(kem_pkg, clip_id, partials_clip, vks)
    assert recovered_clip_key == clip_key, "Lỗi khôi phục khóa clip!"

    partials_cid = {sh.index: sh.partial_decrypt(protected_cid0["c1"]) for sh in approving_nodes}
    recovered_cid0 = kem_dem.recover_cid_filetrust(protected_cid0, ctx_0, partials_cid, vks)
    assert recovered_cid0 == cids[0], "Lỗi khôi phục CID theo FileTrust Eq. (19)-(22)!"

    # 5. Tải 4/6 mảnh bất kỳ từ IPFS (giả lập mất mảnh 2 và 5) -> Khôi phục video gốc
    available_pieces = [
        (1, ipfs_storage[cids[0]]),
        (3, ipfs_storage[cids[2]]),
        (4, ipfs_storage[cids[3]]),
        (6, ipfs_storage[cids[5]]),
    ]
    reconstructed_ct = ida.reconstruct(available_pieces)
    recovered_video = SymmetricCipher.decrypt(reconstructed_ct, recovered_clip_key, iv_clip, tag_clip)
    assert recovered_video == raw_video, "Video khôi phục không khớp bản gốc!"
    print("[4] Truy xuất ngưỡng (3/5 SH) & Khôi phục IDA (4/6 mảnh) THÀNH CÔNG 100%!")
