# TV6 → TV1, TV5: Client IPFS + Web3 Smart Contract

Giải nén vào một thư mục (giữ nguyên `ftpy/`, `contracts/`). Cần: `pip install vyper web3 eth-tester py-evm zfec cryptography`.

## Dùng nhanh
```python
from client_api import FileTrustClient
cli = FileTrustClient(mode="local").setup()     # 1 lần: deploy 4 contract, 4 nút IPFS, DKG 5/3, tự xuất contracts_info.json
bk  = cli.backup(clip_bytes, "cam01-evt001")    # BackupResult: batch_id, cids, sizes, timings
out = cli.access(bk)                            # AccessResult: ok, data, timings (có t_xh)
cli.gas_report()                                # gas thực tế từng giao dịch
```
Mô phỏng mạng (TV1): `FileTrustClient(bandwidth_mbps=10, rtt_ms=50)` (độ trễ áp lên bước nút Requester tải khối, không áp lên bước upload).

## 2 chế độ chạy
- `mode="local"` (mặc định): py-evm + IPFS mô phỏng, chạy ngay trên Windows. `config_path="config.json"` (của TV2) nạp `bandwidth_mbps`, `rtt_ms = 2*delay_ms`.
- `mode="remote"`: `FileTrustClient(mode="remote", config_path="config.json")` đọc `storage_ip:tcp_port` (10.0.2.10:5001) và `blockchain_ip:blockchain_port` (10.0.2.20:8545), hoặc truyền `rpc_url=`, `ipfs_api=`. Cần node EVM có >= 8 tài khoản mở khóa (Hardhat/Ganache) và Kubo thật. **Chưa kiểm thử trên testbed thật.**

## 4 hàm theo Thuật toán 1, 4, 5 [FT]
| Hàm | Trả về |
|---|---|
| `upload_shares(shares)` | `cids` (6 CIDv0), `digests` (6 bytes32), `elapsed_s` |
| `download_shares(cids, min_shares=4)` | `shares` {chỉ số: bytes}, `elapsed_s` (nhận CIDv0 hoặc bytes32) |
| `backup_to_chain(meta, enc_items_7)` | `batch_id`, `gas_total`, `elapsed_s` — `meta={"data_id": bytes32}`; `enc_items_7=[((c1x,c1y),ct),...]` |
| `request_and_reenc(batch_id, pk_req, reenc_items_7, proofs_hash)` | `req_id`, `gas_total`, `elapsed_s` |

## Hàm mức cao (gom sẵn cả quy trình, dùng cho đo thời gian từng bước)
| Hàm | Vai trò | Khóa `timings` chính |
|---|---|---|
| `backup(data, label)` | Edge/Data Owner | aes_encrypt, ida_disperse, ipfs_upload(+_per_share), tx_createBatch, protect_items, tx_addEncCids, backup_total |
| `request_access(batch_id)` → (req_id, sk_R) | Requester | — |
| `approve(req_id)` | 3/5 Shareholder | — |
| `reencrypt(batch_id, req_id, pk_R)` | SH + bên kết hợp | partial_per_sh, verify_proofs, combine, reprotect, **t_xh**, tx_submitReenc |
| `retrieve(batch_id, req_id, sk_R)` | Requester | read_chain, ipfs_download, ida_reconstruct, aes_decrypt, requester_total |
| `access(bk)` | cả quy trình | tất cả trên + access_total_compute |

## Lưu ý quan trọng
1. **Chuỗi chạy trong tiến trình** (py-evm). Địa chỉ trong `contracts_info.json` chỉ để ghi báo cáo/đối chiếu ABI; hãy `import client_api`, đừng kết nối từ tiến trình khác.
2. **Mạng IPFS là mô phỏng Python** (không có DHT/Bitswap/libp2p, không qua cổng 4001). `rtt_ms`/`bandwidth_mbps` chỉ là `sleep` ở bước tải khối; muốn đo bằng iperf3/Wireshark/tc netem như kế hoạch TV1 thì cần Kubo thật trong Docker (chưa có trong gói này).
3. Contract viết bằng **Vyper**, không phải Solidity/Hardhat như mục 2.3.1 của đề cương; mục 2.3.2 cần ghi rõ.
4. Tham số cố định: IDA (6,4), DKG (5,3), secp256k1, 7 mục on-chain/clip (6 digest CID + 1 khóa AES).
5. `t_xh` = SH chậm nhất (SH chạy song song) + kiểm tra bằng chứng + kết hợp; `partial_decrypt` chạy tuần tự trong 1 tiến trình nên đã lấy `max`.
6. `ec.py` là bản Python thuần: chậm hơn coincurve nhiều, số đo `protect_items`/`t_xh` sẽ lớn; ghi chú khi đối chiếu [FT] Bảng 14.
