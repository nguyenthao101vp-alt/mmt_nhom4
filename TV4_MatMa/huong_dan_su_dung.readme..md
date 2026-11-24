# Thư viện Mật mã FileTrust (`crypto_lib_filetrust.py`)

Thư viện Python cài đặt các nguyên thủy mật mã và giao thức lưu trữ phân tán theo kiến trúc của bài báo **FileTrust: A blockchain-based auditable backup solution for IoT-driven environments** (*Farahpoor et al., Ad Hoc Networks, 2026*), kết hợp tối ưu hóa **AES-256-GCM** và đóng gói một khóa phiên duy nhất cho hệ thống lưu trữ video bằng chứng phi tập trung.

---

## 1. Tính năng chính

* **Mã hóa đối xứng xác thực (`SymmetricCipher`):** Sử dụng thuật toán **AES-256-GCM** (khóa 256-bit, Nonce 96-bit, Authentication Tag 128-bit) để mã hóa và bảo vệ tính toàn vẹn dữ liệu video gốc.
* **Thuật toán phân tán thông tin (`RabinIDA`):** Cài đặt thuật toán Rabin IDA trên trường hữu hạn $GF(2^8)$ (đa thức $x^8 + x^4 + x^3 + x + 1$) sử dụng ma trận phân tán **Cauchy**. Chia dữ liệu thành $n$ mảnh và khôi phục nguyên vẹn từ bất kỳ $t$ mảnh nào thông qua khử Gauss-Jordan.
* **Chia sẻ bí mật kiểm chứng & Sinh khóa phân tán (`FeldmanVSS` & `ShareholderNode`):** Cài đặt nghi thức **Pedersen DKG** kết hợp cam kết đồng cấu **Feldman VSS** trên nhóm nhân cyclic bậc nguyên tố $q$ ($p = 2q + 1$, chuẩn RFC 3526 2048-bit). Cho phép $n_{SH}$ cổ đông cùng tạo khóa công khai chung $PK$ mà không bên nào nắm giữ khóa bí mật tổng $SK$.
* **ElGamal ngưỡng & Xác thực ZKP (`ThresholdElGamalKEMDEM`):** Giải mã từng phần ($\delta_i = c_1^{sk_i} \bmod p$) kèm bằng chứng không tiết lộ thông tin **Chaum–Pedersen** $\pi_i = (e, z)$ để chống gian lận, sau đó tổng hợp bằng nội suy Lagrange trên số mũ.
* **Cơ chế lai ghép KEM-DEM & KDF (`HKDF-SHA256`):**
  * Hỗ trợ luồng chuẩn theo bài báo FileTrust (Phương trình 19–22): bảo vệ từng $CID_i$ bằng luồng XOR dẫn xuất từ `HKDF-SHA256`.
  * Hỗ trợ luồng tối ưu của nhóm: chỉ đóng gói một khóa đối xứng duy nhất $K$ của video clip bằng `TElG` + `HKDF-SHA256` + `AES-256-GCM`, giúp giảm chi phí gas và dung lượng lưu trữ on-chain trên Smart Contract.

---

## 2. Yêu cầu hệ thống & Cài đặt

### Yêu cầu môi trường
* **Python:** Phiên bản `3.9` trở lên.
* **Thư viện phụ thuộc:** `cryptography` (dùng cho AES-256-GCM và HKDF-SHA256).

### Cài đặt
Tải tệp `crypto_lib_filetrust.py` vào thư mục dự án của bạn và cài đặt gói `cryptography`:

```bash
pip install "cryptography>=42.0.0"
```

---

## 3. Hướng dẫn sử dụng nhanh (Quick Start)

### Bước 1: Khởi tạo tham số công khai và chạy nghi thức DKG
Thiết lập nhóm mật mã 2048-bit (`PublicParams.default_2048bit()`) và khởi tạo hội đồng $n_{SH} = 5$ cổ đông với ngưỡng phê duyệt $t_{SH} = 3$:

```python
from crypto_lib_filetrust import PublicParams, run_dkg_ceremony

# Khởi tạo tham số công khai pp = (p, q, g)
pp = PublicParams.default_2048bit()

# Chạy Pedersen DKG cho cấu hình (n_SH=5, t_SH=3)
n_sh, t_sh = 5, 3
shareholders, master_pk = run_dkg_ceremony(n_sh, t_sh, pp)

# Lưu danh sách khóa xác minh công khai vk_i của từng cổ đông
vks = {sh.index: sh.vk for sh in shareholders}
```
*(Ghi chú: Bạn có thể dùng `PublicParams.small_demo()` với $p=47, q=23, g=4$ để kiểm thử nhanh các phép tính tay).*

---

### Bước 2: Mã hóa video và phân tán dữ liệu bằng IDA
Phía **Data Owner (DO)** mã hóa tệp video bằng chứng bằng AES-256-GCM, sau đó chia bản mã thành $n_{IDA} = 6$ mảnh với ngưỡng khôi phục $t_{IDA} = 4$:

```python
import hashlib
from crypto_lib_filetrust import SymmetricCipher, RabinIDA

raw_video = b"DU_LIEU_VIDEO_BANG_CHUNG_NHI_PHAN..."

# 1. Mã hóa video gốc bằng AES-256-GCM
clip_key = SymmetricCipher.generate_key()
ciphertext, iv_clip, tag_clip = SymmetricCipher.encrypt(raw_video, clip_key)

# 2. Phân tán bản mã thành 6 mảnh (ngưỡng 4 mảnh)
ida = RabinIDA(n=6, t=4)
pieces = ida.disperse(ciphertext)  # Trả về [(1, piece_1), ..., (6, piece_6)]

# 3. Đẩy các mảnh lên IPFS và thu thập danh sách CID
cids = []
for idx, piece_bytes in pieces:
    # Thay thế dòng dưới bằng lời gọi API IPFS thực tế (ví dụ: ipfshttpclient)
    cid = "Qm" + hashlib.sha256(piece_bytes).hexdigest()[:44]
    cids.append(cid)
```

---

### Bước 3: Bảo vệ khóa phiên $K$ bằng KEM-DEM
Đóng gói khóa đối xứng `clip_key` dưới khóa công khai chung `master_pk` để ghi lên Smart Contract (`DataVault`):

```python
from crypto_lib_filetrust import ThresholdElGamalKEMDEM

kem_dem = ThresholdElGamalKEMDEM(pp)
clip_id = "CAM04_20261125_001"

# Đóng gói duy nhất khóa K của clip (Luồng tối ưu của nhóm)
kem_pkg = kem_dem.encapsulate_clip_key(clip_key, master_pk, clip_id)

# Các dữ liệu cần ghi lên Smart Contract gồm:
# - cids: danh sách [CID_1, ..., CID_6]
# - iv_clip, tag_clip: tham số giải mã video
# - kem_pkg: dictionary chứa {c1, c2, c_dem, iv_kem, tag_kem}
```

*(Tùy chọn)* Nếu muốn mã hóa từng `CID` riêng lẻ theo đúng **Phương trình (19)–(22)** của bài báo FileTrust:
```python
ctx_0 = f"{clip_id}:batch1:0".encode()
protected_cid0 = kem_dem.protect_cid_filetrust(cids[0], ctx_0, master_pk)
# Trả về {"c1": ..., "c2": ..., "ctSym": ...}
```

---

### Bước 4: Phê duyệt ngưỡng và khôi phục video bằng chứng
Khi **Requester (R)** gửi yêu cầu truy xuất hợp lệ và được ít nhất $t_{SH} = 3$ cổ đông đồng ý:

```python
# 1. Giả sử 3 cổ đông (SH_1, SH_3, SH_5) thực hiện giải mã từng phần kèm bằng chứng ZKP
approving_nodes = [shareholders[0], shareholders[2], shareholders[4]]
partials = {
    sh.index: sh.partial_decrypt(kem_pkg["c1"])
    for sh in approving_nodes
}

# 2. Tổng hợp các mảnh giải mã, kiểm tra ZKP Chaum-Pedersen và khôi phục khóa K
recovered_clip_key = kem_dem.decapsulate_clip_key(kem_pkg, clip_id, partials, vks)

# 3. Tải bất kỳ 4/6 mảnh khả dụng từ IPFS và ghép lại bản mã bằng Rabin IDA
available_pieces = [pieces[0], pieces[2], pieces[3], pieces[5]]  # Mất mảnh 2 và 5
reconstructed_ct = ida.reconstruct(available_pieces)

# 4. Giải mã AES-256-GCM và xác thực toàn vẹn video gốc
recovered_video = SymmetricCipher.decrypt(
    reconstructed_ct, recovered_clip_key, iv_clip, tag_clip
)
assert recovered_video == raw_video
```

---

## 4. Tham chiếu API chính

| Lớp / Hàm | Phương thức tiêu biểu | Mô tả chức năng |
| :--- | :--- | :--- |
| `PublicParams` | `default_2048bit()`, `small_demo()` | Quản lý bộ tham số nhóm cyclic $(p, q, g)$ với $p = 2q + 1$. |
| `SymmetricCipher` | `generate_key()`, `encrypt()`, `decrypt()` | Mã hóa/giải mã xác thực dữ liệu bằng AES-256-GCM. |
| `RabinIDA` | `disperse(data)`, `reconstruct(pieces)` | Phân mảnh và khôi phục dữ liệu trên trường $GF(2^8)$ bằng ma trận Cauchy. |
| `FeldmanVSS` | `share()`, `verify()` | Chia sẻ bí mật đa thức và tạo/kiểm tra cam kết đồng cấu $C_l = g^{a_l} \bmod p$. |
| `ShareholderNode` | `finalize_dkg()`, `partial_decrypt(c1)` | Đại diện cổ đông $SH_i$, tổng hợp khóa DKG và tạo mảnh giải mã $\delta_i$ kèm ZKP $\pi_i$. |
| `ThresholdElGamalKEMDEM` | `encapsulate_clip_key()`, `decapsulate_clip_key()` | Đóng gói/mở gói khóa clip $K$ qua lai ghép `TElG` + `HKDF-SHA256` + `AES-GCM`. |
| `ThresholdElGamalKEMDEM` | `protect_cid_filetrust()`, `recover_cid_filetrust()` | Bảo vệ/khôi phục từng $CID_i$ qua luồng XOR từ `HKDF-SHA256` theo bài báo FileTrust. |

---

## 5. Chạy kiểm thử tích hợp

Thư viện đi kèm sẵn kịch bản kiểm thử toàn trình (*end-to-end*) ở cuối tệp. Bạn có thể chạy trực tiếp bằng lệnh:

```bash
python crypto_lib_filetrust.py
```

Kết quả đầu ra kỳ vọng:
```text
=== KHỞI TẠO HỆ THỐNG FILETRUST (2048-BIT SAFE PRIME) ===
[1] DKG hoàn tất với (5, 3). Master PK bit-length: 2048 bits
[2] Đã phân tán thành 6 mảnh IDA lên IPFS. Mẫu CID[0]: Qm...
[3] Đã đóng gói khóa K và bảo vệ CID theo KEM-DEM thành công.
[4] Truy xuất ngưỡng (3/5 SH) & Khôi phục IDA (4/6 mảnh) THÀNH CÔNG 100%!
```
