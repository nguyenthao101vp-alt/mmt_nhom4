"""Kiểm thử client_api.py. Chạy tại thư mục gốc repo:  python3 test_client_api.py
Thoát mã 0 nếu tất cả PASS. Dùng clip chuẩn 7,5 MB nếu có results/clip.mp4, nếu không dùng 7,5 MB ngẫu nhiên."""
import os, sys, traceback
from pathlib import Path
import hashlib
from client_api import FileTrustClient
from ftpy import tcrypto as tc
from ftpy.ipfs_py import cid_to_digest

def load_clip() -> bytes:
    p = Path("results/clip.mp4")
    return p.read_bytes() if p.exists() else os.urandom(7_500_000)

def main() -> int:
    results = []
    def check(name, fn):
        try:
            fn(); results.append((name, True, "")); print(f"PASS  {name}")
        except Exception as e:
            results.append((name, False, repr(e))); print(f"FAIL  {name}: {e!r}"); traceback.print_exc()

    clip = load_clip(); S = {}
    def t_setup():
        S["cli"] = FileTrustClient(mode="local").setup()
        assert S["cli"].chain.dkg.functions.currentEpoch(S["cli"].chain.do).call() == 1
    def t_backup():
        bk = S["cli"].backup(clip, "test-001"); S["bk"] = bk
        assert len(bk.cids) == 6 and bk.sizes["onchain_items"] == 7 and bk.batch_id >= 1
    def t_access():
        r = S["cli"].access(S["bk"]); assert r.ok and r.data == clip, r.reason
        assert r.timings["t_xh"] > 0 and r.timings["access_total_compute"] > 0
    def t_spec_api():
        """4 hàm theo Thuật toán 1, 4, 5 [FT]: upload_shares -> backup_to_chain -> request_and_reenc -> download_shares."""
        cli = S["cli"]; data = clip[:200_000]
        data_id = hashlib.sha256(b"spec-api").digest(); key = os.urandom(32)
        blob = tc.aes_encrypt(key, data, data_id); framed = len(blob).to_bytes(8, "big") + blob
        pieces, _ = tc.ida_disperse(framed, 6, 4)
        up = cli.upload_shares(pieces)
        assert len(up["cids"]) == 6 and all(len(d) == 32 for d in up["digests"])
        dn = cli.download_shares(up["cids"], min_shares=4); assert len(dn["shares"]) >= 4
        dn2 = cli.download_shares(up["digests"], min_shares=4); assert len(dn2["shares"]) >= 4   # nhận cả bytes32
        bid_guess = cli.chain.vault.functions.nextBatchId().call()
        items = up["digests"] + [key]
        enc = lambda pk, ctx_b: [tc.kem_dem_encrypt(pk, m, tc.context(data_id, ctx_b, i)) for i, m in enumerate(items)]
        bc = cli.backup_to_chain({"data_id": data_id}, enc(cli.dkg.pk, bid_guess))
        assert bc["batch_id"] == bid_guess and bc["gas_total"] > 0
        sk_r, pk_r = tc.keypair()
        rr = cli.request_and_reenc(bc["batch_id"], pk_r, enc(pk_r, bc["batch_id"]), tc.proofs_digest([]))
        assert rr["gas_total"] > 0
        r = cli.retrieve(bc["batch_id"], rr["req_id"], sk_r, hashlib.sha256(data).hexdigest())
        assert r.ok and r.data == data, r.reason
    def t_fault_tolerance():
        cli = S["cli"]; b = cli.backup(clip, "test-fault")
        cli.net.nodes[1].kill()                                  # mất 2/6 mảnh, còn 4 = t -> vẫn khôi phục được
        assert cli.access(b, available_only=True, fetch_timeout_ms=1000).ok
        cli.net.nodes[2].kill()                                  # mất 4/6 mảnh, còn 2 < t -> phải thất bại
        b2 = cli.backup(clip, "test-fault-2")
        assert not cli.access(b2, available_only=True, fetch_timeout_ms=1000).ok
    def t_gas():
        g = S["cli"].gas_report(); assert "DV.createBatch" in g and g["DV.createBatch"]["mean"] > 0
    def t_export():
        assert Path("contracts_info.json").exists(), "setup() phải tự xuất contracts_info.json"
        info = S["cli"].export_contracts_info("contracts_info.json")
        assert set(info["contracts"]) == {"AccessControl", "DKG", "DataVault", "TElG"}
        assert all(v["address"] and v["abi"] for v in info["contracts"].values())
        assert info["params"]["ida"] == {"n": 6, "t": 4} and info["params"]["dkg"] == {"n": 5, "t": 3}

    for n, f in [("setup (deploy + DKG 5/3)", t_setup), ("backup clip -> IPFS + on-chain", t_backup),
                 ("access: 3/5 duyệt -> giải mã -> khớp SHA", t_access),
                 ("4 hàm spec: upload/download/backup_to_chain/request_and_reenc", t_spec_api),
                 ("chịu lỗi: 2 nút chết / 4 nút chết", t_fault_tolerance),
                 ("gas_report", t_gas), ("export contracts_info.json", t_export)]:
        if n != "setup (deploy + DKG 5/3)" and "cli" not in S: print(f"SKIP  {n}"); continue
        check(n, f)
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results)-len(bad)}/{len(results)} PASS"); return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
