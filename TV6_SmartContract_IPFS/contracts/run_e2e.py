"""Chạy end-to-end toàn bộ pipeline FileTrust-camera trên testbed và đo thời gian, gas, dung lượng.

    cd pyonly && python3 run_e2e.py --runs 10 --out results/e2e.json
(bản Python thuần: Vyper + py-evm + mạng IPFS Python, không cần Node/Hardhat)

Các bước (khớp mục 2.2.2 của đề cương):
  Backup (Data Owner / Edge):  AES-256-GCM -> IDA (6,4) -> upload IPFS -> bảo vệ 7 mục bằng KEM-DEM -> ghi on-chain
  Sinh khóa (một lần):         DKG 5 SH, ngưỡng 3 -> lưu cam kết on-chain
  Truy xuất (Requester):       yêu cầu -> 3/5 SH phê duyệt -> giải mã một phần + bằng chứng -> bảo vệ lại -> tải mảnh -> IDA -> AES
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import statistics as st
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ftpy import ec, tcrypto as tc
from ftpy.chain_py import ChainPy
from ftpy.ipfs_py import IpfsNetworkPy, NodePy, cid_to_digest, digest_to_cid

N_IDA, T_IDA = 6, 4       # IDA như bài báo (Bảng 8)
N_SH, T_SH = 5, 3         # DKG như bài báo (Bảng 8)
perf = time.perf_counter


class Scenario:
    def __init__(self, net: IpfsNetworkPy, chain: ChainPy, nodes: list[NodePy]):
        self.net, self.chain, self.nodes = net, chain, nodes
        self.storage = nodes[:3]     # 3 nút lưu trữ, mỗi nút giữ 2 mảnh
        self.requester_node = nodes[3]

    # ------------------------------------------------------------------ sinh khóa (một lần)
    def keygen(self) -> dict:
        c = self.chain
        T = {}
        t0 = perf()
        self.dkg = tc.run_dkg(N_SH, T_SH)
        T["dkg_offchain_total"] = perf() - t0          # cả 5 SH chạy tuần tự trong một tiến trình
        auth = hashlib.sha256(b"auth" + os.urandom(16)).digest()
        t0 = perf()
        c.send("ACL.requestKeyGen", c.acl.functions.requestKeyGen(auth), c.do)
        rid = c.request_count() - 1
        for sh in c.shs[:T_SH]:
            c.send("ACL.approve(keygen)", c.acl.functions.approve(rid), sh)
        flat = [v for pt in self.dkg.commitments for v in pt]
        c.send("DKG.storeKeyCommit", c.dkg.functions.storeKeyCommit(rid, T_SH, N_SH, flat), c.shs[0])
        T["keygen_onchain_total"] = perf() - t0
        assert c.dkg.functions.currentEpoch(c.do).call() == 1
        return T

    # ------------------------------------------------------------------ backup
    def backup(self, data: bytes, label: str) -> dict:
        c, T = self.chain, {}
        data_id = hashlib.sha256(label.encode()).digest()
        key = os.urandom(32)

        t0 = perf(); blob = tc.aes_encrypt(key, data, data_id); T["aes_encrypt"] = perf() - t0
        framed = len(blob).to_bytes(8, "big") + blob
        t0 = perf(); pieces, pad = tc.ida_disperse(framed, N_IDA, T_IDA); T["ida_disperse"] = perf() - t0

        cids, per_share = [], []
        t0 = perf()
        for i, piece in enumerate(pieces):
            s = perf(); cids.append(self.storage[i % 3].add(piece)); per_share.append(perf() - s)
        T["ipfs_upload"] = perf() - t0
        T["ipfs_upload_per_share"] = per_share

        t0 = perf()
        c.send("DV.createBatch", c.vault.functions.createBatch(data_id, N_IDA, T_IDA, 1), c.do)
        T["tx_createBatch"] = perf() - t0
        batch_id = c.vault.functions.nextBatchId().call() - 1

        items = [cid_to_digest(x) for x in cids] + [key]      # 6 digest CID + 1 khóa AES
        t0 = perf()
        prot = []
        for idx, m in enumerate(items):
            c1, ct = tc.kem_dem_encrypt(self.dkg.pk, m, tc.context(data_id, batch_id, idx))
            prot.append((c1, ct))
        T["protect_items"] = perf() - t0

        t0 = perf()
        c.send(f"DV.addEncCids(batch {len(items)})",
               c.vault.functions.addEncCids(batch_id, [p[0][0] for p in prot], [p[0][1] for p in prot], [p[1] for p in prot]), c.do)
        T["tx_addEncCids"] = perf() - t0
        T["backup_compute"] = T["aes_encrypt"] + T["ida_disperse"] + T["protect_items"]
        T["backup_total"] = T["backup_compute"] + T["ipfs_upload"] + T["tx_createBatch"] + T["tx_addEncCids"]
        sizes = {"clip": len(data), "encrypted": len(blob), "shares": [len(p) for p in pieces],
                 "shares_total": sum(len(p) for p in pieces), "onchain_items": len(items)}
        return {"batch_id": batch_id, "sha": hashlib.sha256(data).hexdigest(), "cids": cids, "T": T, "sizes": sizes}

    # ------------------------------------------------------------------ truy xuất
    def access(self, bk: dict, available_only: bool = False, fetch_timeout_ms: int = 30000) -> dict:
        c, T = self.chain, {}
        batch_id = bk["batch_id"]
        sk_r, pk_r = tc.keypair()

        t0 = perf()
        c.send("DV.requestDataAccess", c.vault.functions.requestDataAccess(batch_id, pk_r[0], pk_r[1]), c.req)
        T["tx_requestAccess"] = perf() - t0
        req_id = c.request_count() - 1
        t0 = perf()
        for sh in c.shs[:T_SH]:
            c.send("ACL.approve(access)", c.acl.functions.approve(req_id), sh)
        T["tx_approvals"] = perf() - t0

        # --- phía Shareholder: đọc EncCid, giải mã một phần + bằng chứng cho từng mục
        c1x, c1y, cts = c.vault.functions.getEncCids(batch_id).call()
        data_id = c.vault.functions.getBatch(batch_id).call()[4]
        n_items = len(cts)
        c1s = list(zip(c1x, c1y))
        subset = [1, 2, 3]
        partials: dict[int, dict[int, tuple]] = {i: {} for i in range(n_items)}
        per_sh = []
        for j in subset:
            t0 = perf()
            for i in range(n_items):
                partials[i][j] = tc.partial_decrypt(self.dkg.sk[j - 1], self.dkg.vk[j - 1], c1s[i])
            per_sh.append(perf() - t0)
        T["partial_per_sh"] = per_sh                 # mỗi SH chạy song song ở máy riêng
        # --- bên kết hợp: kiểm tra bằng chứng, tái tạo khóa theo ngưỡng, bảo vệ lại cho Requester
        t0 = perf()
        for i in range(n_items):
            for j in subset:
                d, pr = partials[i][j]
                assert tc.verify_partial(self.dkg.vk[j - 1], c1s[i], d, pr), "bằng chứng Chaum-Pedersen sai"
        T["verify_proofs"] = perf() - t0
        t0 = perf()
        plain = []
        for i in range(n_items):
            shared = tc.combine({j: partials[i][j][0] for j in subset})
            plain.append(tc.kem_dem_decrypt_with_shared(shared, c1s[i], cts[i], tc.context(data_id, batch_id, i)))
        T["combine"] = perf() - t0
        t0 = perf()
        reenc = [tc.kem_dem_encrypt(pk_r, plain[i], tc.context(data_id, batch_id, i)) for i in range(n_items)]
        T["reprotect"] = perf() - t0
        # t_xh: khóa được tái tạo theo ngưỡng = SH chậm nhất (song song) + kiểm tra + kết hợp
        T["t_xh"] = max(per_sh) + T["verify_proofs"] + T["combine"]
        proofs = [partials[i][j][1] for i in range(n_items) for j in subset]
        t0 = perf()
        c.send(f"TElG.submitReencResult({n_items} items)",
               c.telg.functions.submitReencResult(req_id, [r[0][0] for r in reenc], [r[0][1] for r in reenc],
                                                  [r[1] for r in reenc], tc.proofs_digest(proofs)), c.shs[0])
        T["tx_submitReenc"] = perf() - t0

        # --- phía Requester
        t0 = perf()
        rx, ry, rct = c.vault.functions.getRequesterCids(req_id).call()
        T["read_chain"] = perf() - t0
        t0 = perf()
        items = [tc.kem_dem_decrypt(sk_r, (rx[i], ry[i]), rct[i], tc.context(data_id, batch_id, i)) for i in range(n_items)]
        T["requester_decrypt_items"] = perf() - t0
        digests, key = items[:-1], items[-1]
        cids = [digest_to_cid(d) for d in digests]
        assert cids == bk["cids"], "CID khôi phục không khớp CID đã upload"

        t0 = perf()
        order = list(range(N_IDA))
        if not available_only:
            random.shuffle(order)
            order = order[:T_IDA]                    # chỉ cần t = 4 mảnh bất kỳ
        got: dict[int, bytes] = {}

        def fetch(i):
            s = perf()
            try:
                return i, self.requester_node.cat(cids[i], fetch_timeout_ms), perf() - s
            except Exception:
                return i, None, perf() - s
        with ThreadPoolExecutor(len(order)) as ex:
            res = list(ex.map(fetch, order))
        for i, b, dt in res:
            if b is not None:
                got[i] = b
        T["ipfs_download"] = perf() - t0
        T["ipfs_download_per_share"] = [r[2] for r in res]
        T["shares_fetched"] = sorted(got)
        if len(got) < T_IDA:
            return {"ok": False, "reason": f"chỉ lấy được {len(got)}/{T_IDA} mảnh", "T": T}
        t0 = perf(); framed = tc.ida_reconstruct(got, N_IDA, T_IDA, 0); T["ida_reconstruct"] = perf() - t0
        L = int.from_bytes(framed[:8], "big")
        t0 = perf(); data = tc.aes_decrypt(key, framed[8:8 + L], data_id); T["aes_decrypt"] = perf() - t0
        ok = hashlib.sha256(data).hexdigest() == bk["sha"]
        T["requester_total"] = (T["read_chain"] + T["requester_decrypt_items"] + T["ipfs_download"]
                                + T["ida_reconstruct"] + T["aes_decrypt"])
        # từ lúc đủ phê duyệt đến lúc mở được clip (không tính thời gian người duyệt và xác nhận khối)
        T["access_total_compute"] = (max(per_sh) + T["verify_proofs"] + T["combine"] + T["reprotect"]
                                     + T["tx_submitReenc"] + T["requester_total"])
        return {"ok": ok, "T": T}


def make_clip(path: Path):
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    if not shutil.which("ffmpeg"):                      # không có ffmpeg: dùng byte ngẫu nhiên cố định cỡ ~7,5 MB
        path.write_bytes(random.Random(7).randbytes(7_500_000)); return
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=15",
                    "-vf", "noise=alls=25:allf=t+u", "-t", "15", "-c:v", "libx264", "-preset", "veryfast",
                    "-b:v", "4M", "-maxrate", "4M", "-bufsize", "8M", "-pix_fmt", "yuv420p", str(path)], check=True)


def stat(xs):
    return {"mean": st.mean(xs), "sd": st.stdev(xs) if len(xs) > 1 else 0.0, "min": min(xs), "max": max(xs), "n": len(xs)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--clip", default=str(Path(__file__).resolve().parents[0] / "results" / "clip.mp4"))
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[0] / "results" / "e2e.json"))
    ap.add_argument("--sweep-mb", default="1,5,10,25")
    ap.add_argument("--sweep-runs", type=int, default=3)
    args = ap.parse_args()

    clip = Path(args.clip); make_clip(clip); clip_bytes = clip.read_bytes()
    out: dict = {"meta": {"clip_bytes": len(clip_bytes), "n_ida": N_IDA, "t_ida": T_IDA, "n_sh": N_SH, "t_sh": T_SH}}
    try:
        chain = ChainPy(); chain.setup()
        net = IpfsNetworkPy(4)
        sc = Scenario(net, chain, net.nodes)
        out["keygen"] = sc.keygen()

        # khởi động nóng (không tính)
        w = sc.backup(clip_bytes, "warmup"); r = sc.access(w); assert r["ok"]
        for k in list(chain.gas):
            if k.startswith(("DV.", "TElG.", "ACL.approve(access)")):
                chain.gas[k].clear()

        runs = []
        for i in range(args.runs):
            bk = sc.backup(clip_bytes, f"cam01-run{i}")
            ac = sc.access(bk)
            assert ac["ok"], ac
            runs.append({"backup": bk["T"], "access": ac["T"], "sizes": bk["sizes"]})
            print(f"run {i+1}/{args.runs}: backup {bk['T']['backup_total']:.2f}s, access {ac['T']['access_total_compute']:.2f}s, t_xh {ac['T']['t_xh']:.2f}s", flush=True)
        out["runs"] = runs

        sweep = []
        for mb in [int(x) for x in args.sweep_mb.split(",") if x]:
            data = os.urandom(mb * 1_000_000)
            for j in range(args.sweep_runs):
                bk = sc.backup(data, f"sweep-{mb}-{j}"); ac = sc.access(bk); assert ac["ok"], ac
                sweep.append({"mb": mb, "backup": bk["T"], "access": ac["T"], "sizes": bk["sizes"],
                              "gas_createBatch": chain.gas["DV.createBatch"][-1],
                              "gas_addEncCids": chain.gas["DV.addEncCids(batch 7)"][-1]})
            print(f"sweep {mb} MB xong", flush=True)
        out["sweep"] = sweep

        # --- chịu lỗi: 2 nút lưu trữ mất thì sao?
        b1 = sc.backup(clip_bytes, "fault-1"); b2 = sc.backup(clip_bytes, "fault-2")
        net.nodes[1].kill()                                   # mất 2/6 mảnh -> còn 4 = t
        r1 = sc.access(b1, available_only=True, fetch_timeout_ms=8000)
        net.nodes[2].kill()                                   # mất tiếp 2/6 mảnh -> còn 2 < t
        r2 = sc.access(b2, available_only=True, fetch_timeout_ms=8000)
        out["fault"] = {"one_node_down": {"ok": r1["ok"], "shares": r1["T"].get("shares_fetched")},
                        "two_nodes_down": {"ok": r2["ok"], "reason": r2.get("reason"), "shares": r2["T"].get("shares_fetched")}}
        print("fault:", out["fault"], flush=True)

        out["gas"] = {k: v for k, v in chain.gas.items()}
        out["tx_time"] = {k: v for k, v in chain.tx_time.items()}
    finally:
        pass
    Path(args.out).write_text(json.dumps(out, indent=2, default=str))
    print("đã ghi", args.out)


if __name__ == "__main__":
    main()
