# Thư viện Mật mã Python – Bảo mật & Phân tán Dữ liệu Clip

Thư viện hiện thực hóa toàn bộ lõi toán học và mật mã cho **Mục 1.3** và **Module 2.3.2** của dự án, phục vụ quy trình mã hóa, phân mảnh lưu trữ phân tán trên IPFS và quản lý khóa theo ngưỡng không cần bên tin cậy (dựa trên kiến trúc của *FileTrust* \[FT\]).

## 1. Tính năng & Cơ sở toán học

Thư viện bao gồm 4 lớp xử lý chính:

1. **`SymmetricCipher` (AES-256-GCM):**

   * Sinh khóa đối xứng ngẫu nhiên chuẩn CSPRNG 256-bit (`secrets.token_bytes(32)`).

   * Mã hóa nội dung video clip gốc kèm thẻ xác thực toàn vẹn 16-byte (Authentication Tag) với Nonce 96-bit.

2. **`RabinIDA` (Information Dispersal Algorithm trên** $GF(2^8)$**):**

   * Phân tán bản mã thành $n$ mảnh, chỉ cần tối thiểu $t$ mảnh bất kỳ để khôi phục nguyên vẹn.

   * Sử dụng ma trận Vandermonde trên trường hữu hạn $GF(2^8)$ với đa thức bất khả quy $x^8 + x^4 + x^3 + x + 1$ (`0x11B`).

   * Hỗ trợ tham số bài báo $(n=6, t=4)$ (hệ số giãn nở đúng $1.5\times$, chịu mất tối đa 2 mảnh) và tham số demo nhóm $(n=4, t=3)$ (giãn nở $1.33\times$, chịu mất 1 mảnh).

   * Tự động gắn 8-byte header độ dài gốc giúp bảo toàn 100% các tệp nhị phân có byte `0x00` ở cuối.

3. **`DKGNode` & `ThresholdCryptoSystem` (Pedersen DKG + Feldman VSS):**

   * Thực thi giao thức 2 vòng sinh khóa phân tán không cần bên tin cậy (Trusted Dealer).

   * Các nút đồng quản lý tự sinh đa thức bí mật $f_i(x)$ và đa thức làm mù $f'_i(x)$ trên $\mathbb{Z}_q$, công bố cam kết và kiểm chứng tính hợp lệ của từng mảnh chia sẻ trước khi tổng hợp khóa công khai chung $Y$.

4. **Threshold ElGamal + HKDF-SHA256 + KEM-DEM:**

   * **Phía KEM:** Dùng khóa công khai chung $Y$ (nhóm cyclic 2048-bit chuẩn RFC 3526 Group 14) để đóng gói bí mật chia sẻ $Z = Y^r \pmod p$ kèm bản mã $C_1 = g^r \pmod p$.

   * **Phía KDF:** Dẫn xuất khóa bọc `KEK` 256-bit từ $Z$ thông qua `HKDF-SHA256`.

   * **Phía DEM:** Mã hóa khóa đối xứng $K$ của clip bằng `AES-256-GCM` với khóa `KEK`.

   * **Giải mã ngưỡng:** Cần tối thiểu $t$ nút đồng quản lý tính mảnh giải mã từng phần $d_i = C_1^{sk_i} \pmod p$, sau đó nội suy Lagrange trên trường $\mathbb{Z}_q$ để tái tạo khóa $K$.

## 2. Yêu cầu hệ thống & Cài đặt

* **Python:** Phiên bản `3.9` trở lên.

* **Thư viện phụ thuộc:** `cryptography`

Cài đặt thư viện cần thiết bằng lệnh:

```
pip install cryptography

```

## 3. Chạy kiểm thử tích hợp sẵn

Tệp `crypto_lib_fixed_3.py` tích hợp sẵn hai kịch bản chạy thử:

1. **`demo_small_numbers()`**: Chạy với bộ tham số số nhỏ ($p=47, q=23, g=4, h=9$) và ngưỡng $(5, 3)$ để cả nhóm dễ dàng kiểm chứng kết quả toán học bằng tay cho báo cáo Mục 1.3.

2. **`demo_full_production_pipeline()`**: Chạy toàn bộ quy trình thực tế với nhóm 2048-bit, mã hóa dữ liệu nhị phân, phân mảnh IDA $(6, 4)$, bọc khóa KEM-DEM và giả lập mất 2 mảnh IPFS khi khôi phục.

Chạy trực tiếp từ terminal:

```
python crypto_lib_fixed_3.py

```

## 4. Hướng dẫn tích hợp API cho các thành viên (TV5 & TV6)

### A. Quy trình tải lên dữ liệu (Dành cho TV5 – IPFS & Smart Contract)

```
from crypto_lib_fixed_3 import SymmetricCipher, RabinIDA, ThresholdCryptoSystem

# 1. Khởi tạo hệ mật ngưỡng (ví dụ cấu hình demo nhóm n=3, t=2 hoặc bài báo n=5, t=3)
crypto_sys = ThresholdCryptoSystem(n=3, t=2)
joint_public_key, node_secret_shares = crypto_sys.generate_dkg_keys()

# 2. Mã hóa file clip gốc bằng AES-256-GCM
clip_bytes = open("clip_demo.mp4", "rb").read()
k_clip = SymmetricCipher.generate_key()
enc_clip = SymmetricCipher.encrypt(clip_bytes, k_clip)

# 3. Phân tán bản mã thành n mảnh bằng Rabin IDA để tải lên IPFS
ida = RabinIDA(n=4, t=3)
shares = ida.distribute(enc_clip["ciphertext"])
# -> TV5 tải từng (index, share_bytes) lên IPFS để lấy danh sách CID_1 ... CID_n

# 4. Đóng gói khóa K bằng KEM-DEM để ghi lên Smart Contract
kem_pkg = crypto_sys.kem_dem_encapsulate_key(joint_public_key, k_clip)
# -> TV5 lưu lên Smart Contract: CIDs, enc_clip["nonce"], enc_clip["tag"],
#    kem_pkg["c1"], kem_pkg["c_dem"], kem_pkg["nonce"], kem_pkg["tag"]

```

### B. Quy trình truy xuất & giải mã bằng chứng (Dành cho TV6 – UI & Truy xuất)

```
# 1. Lấy dữ liệu từ Smart Contract và gửi kem_pkg["c1"] tới t nút đồng quản lý phê duyệt
partial_approvals = [
    crypto_sys.partial_decrypt(kem_pkg["c1"], node_id=1, sk_share=node_secret_shares[1]),
    crypto_sys.partial_decrypt(kem_pkg["c1"], node_id=3, sk_share=node_secret_shares[3]),
]

# 2. Tái tạo khóa đối xứng K từ các mảnh phê duyệt (đo thời gian t_xh tại bước này)
recovered_k = crypto_sys.kem_dem_decapsulate_key(kem_pkg, partial_approvals)

# 3. Tải đủ t=3 mảnh bất kỳ từ IPFS và ghép lại bằng Rabin IDA
downloaded_shares = [shares[0], shares[2], shares[3]]  # Giả sử mảnh số 2 bị mất
recovered_ciphertext = ida.reconstruct(downloaded_shares)

# 4. Giải mã và xác thực tính toàn vẹn file clip gốc
original_clip = SymmetricCipher.decrypt(
    ciphertext=recovered_ciphertext,
    key=recovered_k,
    nonce=enc_clip["nonce"],
    tag=enc_clip["tag"],
)

```

## 5. Lưu ý quan trọng khi triển khai & Benchmark

* **Tối ưu hiệu năng IDA:** Khi tích hợp với tệp video lớn (vài chục MB), nên sử dụng tham số nhóm `RabinIDA(n=4, t=3)` và `ThresholdCryptoSystem(n=3, t=2)` để tối ưu tốc độ xử lý trên Python thuần.

* **Đo lường thời gian tái tạo khóa (**$t_{xh}$**):** Khi thực hiện benchmark cho Mục 2.4.3, hãy đo thời gian thực thi của cụm hàm `partial_decrypt()` (cho $t$ nút) cộng với `kem_dem_decapsulate_key()` trên bộ tham số mặc định 2048-bit (`RFC3526_2048_P`) với cấu hình $(n=5, t=3)$ để đối chiếu trực tiếp với Bảng 14 của bài báo *FileTrust*.