"""client_api.py — API gọn cho TV1 (đo mạng) và TV5 (script điều phối) gọi pipeline FileTrust-camera.

Đặt file này ở THƯ MỤC GỐC repo (cùng cấp với ftpy/ và contracts/).

    from client_api import FileTrustClient
    cli = FileTrustClient(mode="local").setup()     # deploy 4 contract + mạng IPFS + DKG 5/3 (một lần)
    bk  = cli.backup(clip_bytes, "cam01-evt001")    # AES-GCM -> IDA(6,4) -> IPFS -> KEM-DEM -> on-chain
    out = cli.access(bk)                            # yêu cầu -> 3/5 SH duyệt -> giải mã ngưỡng -> tải -> IDA -> AES
    assert out.data == clip_bytes
    print(bk.timings, out.timings["t_xh"], cli.gas_report())

Mọi thời gian tính bằng giây (time.perf_counter). Tên khóa trong `timings` trùng run_e2e.py để đối chiếu mục 2.4.
LƯU Ý: chuỗi là py-evm/eth-tester chạy TRONG TIẾN TRÌNH Python -> địa chỉ contract chỉ có hiệu lực trong tiến trình
đã deploy; TV1/TV5 phải `import client_api` chứ không kết nối từ tiến trình khác tới địa chỉ trong contracts_info.json.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from ftpy import tcrypto as tc
from ftpy.chain_py import ChainPy, compile_contract
from ftpy.ipfs_py import IpfsNetworkPy, cid_to_digest, digest_to_cid

perf = time.perf_counter
CONTRACT_NAMES = ["AccessControl", "DKG", "DataVault", "TElG"]



class KuboNode:
    """Nút IPFS thật qua Kubo HTTP API (chế độ remote). Cùng giao diện add()/cat() với NodePy."""
    def __init__(self, api: str):
        self.api = api.rstrip("/")

    def add(self, data: bytes) -> str:
        import requests
        r = requests.post(f"{self.api}/api/v0/add", params={"cid-version": 0, "pin": "true"},
                          files={"file": data}, timeout=120)
        r.raise_for_status()
        return r.json()["Hash"]

    def cat(self, cid: str, timeout_ms: int = 30000) -> bytes:
        import requests
        r = requests.post(f"{self.api}/api/v0/cat", params={"arg": cid}, timeout=timeout_ms / 1000)
        r.raise_for_status()
        return r.content


def _as_cid(x) -> str:
    return digest_to_cid(x) if isinstance(x, (bytes, bytearray)) else x


@dataclass
class BackupResult:
    batch_id: int
    data_id: bytes
    sha256: str
    cids: list[str]
    sizes: dict
    timings: dict


@dataclass
class AccessResult:
    ok: bool
    data: bytes | None
    req_id: int
    timings: dict
    reason: str | None = None


class FileTrustClient:
    def __init__(self, mode: str = "local", config_path: str | None = None,
                 n_ida: int = 6, t_ida: int = 4, n_sh: int = 5, t_sh: int = 3, n_ipfs: int = 4,
                 bandwidth_mbps: float | None = None, rtt_ms: float = 0.0,
                 rpc_url: str | None = None, ipfs_api: str | None = None,
                 info_path: str | None = "contracts_info.json"):
        """mode="local": py-evm + mạng IPFS Python (chạy ngay trên Windows).
        mode="remote": EVM JSON-RPC (Hardhat/Ganache) + Kubo HTTP API, địa chỉ lấy từ config.json của TV2
        (storage_ip:tcp_port, blockchain_ip:blockchain_port) hoặc truyền rpc_url / ipfs_api. CHƯA kiểm thử trên testbed thật."""
        assert mode in ("local", "remote")
        self.mode, self.info_path = mode, info_path
        self.n_ida, self.t_ida, self.n_sh, self.t_sh = n_ida, t_ida, n_sh, t_sh
        self.n_ipfs, self.bandwidth_mbps, self.rtt_ms = n_ipfs, bandwidth_mbps, rtt_ms
        self.rpc_url, self.ipfs_api = rpc_url, ipfs_api
        if config_path:
            cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
            if mode == "local":      # nạp tham số mạng mô phỏng từ config TV2
                self.bandwidth_mbps = cfg.get("bandwidth_mbps", bandwidth_mbps)
                if "delay_ms" in cfg:
                    self.rtt_ms = 2 * cfg["delay_ms"]
            else:
                self.ipfs_api = ipfs_api or f"http://{cfg['storage_ip']}:{cfg.get('tcp_port', 5001)}"
                self.rpc_url = rpc_url or f"http://{cfg['blockchain_ip']}:{cfg.get('blockchain_port', 8545)}"
        self.chain: ChainPy | None = None
        self.net: IpfsNetworkPy | None = None
        self.dkg = None
        self.keygen_timings: dict = {}
        self._sha: dict[int, str] = {}
        self._pk_cache: dict[int, tuple] = {}

    # ------------------------------------------------------------------ khởi tạo
    def setup(self) -> "FileTrustClient":
        """Deploy 4 contract, dựng IPFS, DKG 5/3, rồi tự xuất contracts_info.json (nếu info_path != None)."""
        self.chain = ChainPy()
        if self.mode == "remote":
            assert self.rpc_url and self.ipfs_api, "remote cần rpc_url/ipfs_api hoặc config_path"
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            assert w3.is_connected(), f"không kết nối được {self.rpc_url}"
            a = w3.eth.accounts
            assert len(a) >= 8, "cần >= 8 tài khoản mở khóa (owner, DO, 5 SH, Requester)"
            self.chain.w3 = w3
            self.chain.owner, self.chain.do, self.chain.shs, self.chain.req = a[0], a[1], a[2:7], a[7]
            self.net = None
            self.storage = [KuboNode(self.ipfs_api)] * 3
            self.requester_node = KuboNode(self.ipfs_api)
        else:
            assert self.n_ipfs >= 4, "cần >= 4 nút IPFS (3 nút lưu trữ + 1 nút Requester)"
            self.net = IpfsNetworkPy(self.n_ipfs, self.bandwidth_mbps, self.rtt_ms)
            self.storage = self.net.nodes[:3]            # mỗi nút giữ 2/6 mảnh
            self.requester_node = self.net.nodes[3]
        self.chain.setup(self.t_sh)
        self.keygen_timings = self._keygen()
        if self.info_path:
            self.export_contracts_info(self.info_path)
        return self

    def _keygen(self) -> dict:
        c, T = self.chain, {}
        t0 = perf(); self.dkg = tc.run_dkg(self.n_sh, self.t_sh); T["dkg_offchain_total"] = perf() - t0
        auth = hashlib.sha256(b"auth" + os.urandom(16)).digest()
        t0 = perf()
        c.send("ACL.requestKeyGen", c.acl.functions.requestKeyGen(auth), c.do)
        rid = c.request_count() - 1
        for sh in c.shs[:self.t_sh]:
            c.send("ACL.approve(keygen)", c.acl.functions.approve(rid), sh)
        flat = [v for pt in self.dkg.commitments for v in pt]
        c.send("DKG.storeKeyCommit", c.dkg.functions.storeKeyCommit(rid, self.t_sh, self.n_sh, flat), c.shs[0])
        T["keygen_onchain_total"] = perf() - t0
        assert c.dkg.functions.currentEpoch(c.do).call() == 1
        return T

    # ------------------------------------------------------------------ backup (Data Owner / Edge box)
    def backup(self, data: bytes, label: str) -> BackupResult:
        c, T = self.chain, {}
        data_id = hashlib.sha256(label.encode()).digest()
        key = os.urandom(32)
        t0 = perf(); blob = tc.aes_encrypt(key, data, data_id); T["aes_encrypt"] = perf() - t0
        framed = len(blob).to_bytes(8, "big") + blob
        t0 = perf(); pieces, _pad = tc.ida_disperse(framed, self.n_ida, self.t_ida); T["ida_disperse"] = perf() - t0

        cids, per_share = [], []
        t0 = perf()
        for i, piece in enumerate(pieces):
            s = perf(); cids.append(self.storage[i % 3].add(piece)); per_share.append(perf() - s)
        T["ipfs_upload"] = perf() - t0
        T["ipfs_upload_per_share"] = per_share

        t0 = perf()
        c.send("DV.createBatch", c.vault.functions.createBatch(data_id, self.n_ida, self.t_ida, 1), c.do)
        T["tx_createBatch"] = perf() - t0
        batch_id = c.vault.functions.nextBatchId().call() - 1

        items = [cid_to_digest(x) for x in cids] + [key]       # n digest CID + 1 khóa AES
        t0 = perf()
        prot = [tc.kem_dem_encrypt(self.dkg.pk, m, tc.context(data_id, batch_id, i)) for i, m in enumerate(items)]
        T["protect_items"] = perf() - t0
        t0 = perf()
        c.send(f"DV.addEncCids(batch {len(items)})",
               c.vault.functions.addEncCids(batch_id, [p[0][0] for p in prot], [p[0][1] for p in prot], [p[1] for p in prot]), c.do)
        T["tx_addEncCids"] = perf() - t0
        T["backup_compute"] = T["aes_encrypt"] + T["ida_disperse"] + T["protect_items"]
        T["backup_total"] = T["backup_compute"] + T["ipfs_upload"] + T["tx_createBatch"] + T["tx_addEncCids"]
        sizes = {"clip": len(data), "encrypted": len(blob), "shares": [len(p) for p in pieces],
                 "shares_total": sum(len(p) for p in pieces), "onchain_items": len(items)}
        sha = hashlib.sha256(data).hexdigest()
        self._sha[batch_id] = sha
        return BackupResult(batch_id, data_id, sha, cids, sizes, T)

    # ------------------------------------------------------------------ truy xuất, chia từng bước để TV1 đo riêng
    def request_access(self, batch_id: int) -> tuple[int, int]:
        """Requester gửi yêu cầu + khóa công khai. Trả về (req_id, sk_requester)."""
        c = self.chain
        sk_r, pk_r = tc.keypair()
        c.send("DV.requestDataAccess", c.vault.functions.requestDataAccess(batch_id, pk_r[0], pk_r[1]), c.req)
        rid = c.request_count() - 1
        self._pk_cache[rid] = pk_r
        return rid, sk_r

    def approve(self, req_id: int, n_approvers: int | None = None) -> None:
        """Các Shareholder phê duyệt (mặc định đúng t_sh phiếu)."""
        c = self.chain
        for sh in c.shs[: (n_approvers or self.t_sh)]:
            c.send("ACL.approve(access)", c.acl.functions.approve(req_id), sh)

    def reencrypt(self, batch_id: int, req_id: int, pk_requester, subset=(1, 2, 3)) -> dict:
        """Phía SH + bên kết hợp: giải mã một phần + bằng chứng, tái tạo theo ngưỡng, bảo vệ lại cho Requester, ghi on-chain."""
        c, T = self.chain, {}
        c1x, c1y, cts = c.vault.functions.getEncCids(batch_id).call()
        data_id = c.vault.functions.getBatch(batch_id).call()[4]
        n_items = len(cts)
        c1s = list(zip(c1x, c1y))
        subset = list(subset)
        assert len(subset) >= self.t_sh
        partials = {i: {} for i in range(n_items)}
        per_sh = []
        for j in subset:
            t0 = perf()
            for i in range(n_items):
                partials[i][j] = tc.partial_decrypt(self.dkg.sk[j - 1], self.dkg.vk[j - 1], c1s[i])
            per_sh.append(perf() - t0)
        T["partial_per_sh"] = per_sh
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
        reenc = [tc.kem_dem_encrypt(pk_requester, plain[i], tc.context(data_id, batch_id, i)) for i in range(n_items)]
        T["reprotect"] = perf() - t0
        T["t_xh"] = max(per_sh) + T["verify_proofs"] + T["combine"]     # SH chạy song song -> lấy SH chậm nhất
        proofs = [partials[i][j][1] for i in range(n_items) for j in subset]
        t0 = perf()
        c.send(f"TElG.submitReencResult({n_items} items)",
               c.telg.functions.submitReencResult(req_id, [r[0][0] for r in reenc], [r[0][1] for r in reenc],
                                                  [r[1] for r in reenc], tc.proofs_digest(proofs)), c.shs[0])
        T["tx_submitReenc"] = perf() - t0
        return T

    def retrieve(self, batch_id: int, req_id: int, sk_requester: int, expected_sha: str | None = None,
                 available_only: bool = False, fetch_timeout_ms: int = 30000) -> AccessResult:
        """Requester: đọc EncCid đã bảo vệ lại -> giải mã -> tải >= t mảnh từ IPFS -> IDA -> AES-GCM."""
        c, T = self.chain, {}
        data_id = c.vault.functions.getBatch(batch_id).call()[4]
        t0 = perf(); rx, ry, rct = c.vault.functions.getRequesterCids(req_id).call(); T["read_chain"] = perf() - t0
        t0 = perf()
        items = [tc.kem_dem_decrypt(sk_requester, (rx[i], ry[i]), rct[i], tc.context(data_id, batch_id, i)) for i in range(len(rct))]
        T["requester_decrypt_items"] = perf() - t0
        cids = [digest_to_cid(d) for d in items[:-1]]
        key = items[-1]

        order = list(range(self.n_ida))
        if not available_only:
            random.shuffle(order); order = order[: self.t_ida]
        got: dict[int, bytes] = {}

        def fetch(i):
            s = perf()
            try:
                return i, self.requester_node.cat(cids[i], fetch_timeout_ms), perf() - s
            except Exception:
                return i, None, perf() - s
        t0 = perf()
        with ThreadPoolExecutor(len(order)) as ex:
            res = list(ex.map(fetch, order))
        T["ipfs_download"] = perf() - t0
        T["ipfs_download_per_share"] = [r[2] for r in res]
        got = {i: b for i, b, _ in res if b is not None}
        T["shares_fetched"] = sorted(got)
        if len(got) < self.t_ida:
            return AccessResult(False, None, req_id, T, f"chỉ lấy được {len(got)}/{self.t_ida} mảnh")
        t0 = perf(); framed = tc.ida_reconstruct(got, self.n_ida, self.t_ida, 0); T["ida_reconstruct"] = perf() - t0
        L = int.from_bytes(framed[:8], "big")
        t0 = perf(); data = tc.aes_decrypt(key, framed[8:8 + L], data_id); T["aes_decrypt"] = perf() - t0
        sha = expected_sha or self._sha.get(batch_id)
        ok = sha is None or hashlib.sha256(data).hexdigest() == sha
        T["requester_total"] = (T["read_chain"] + T["requester_decrypt_items"] + T["ipfs_download"]
                                + T["ida_reconstruct"] + T["aes_decrypt"])
        return AccessResult(ok, data, req_id, T, None if ok else "SHA-256 không khớp")

    def access(self, bk: BackupResult, available_only: bool = False, fetch_timeout_ms: int = 30000) -> AccessResult:
        """Chạy trọn quy trình truy xuất bằng chứng cho một batch."""
        T = {}
        t0 = perf(); req_id, sk_r = self.request_access(bk.batch_id); T["tx_requestAccess"] = perf() - t0
        t0 = perf(); self.approve(req_id); T["tx_approvals"] = perf() - t0
        pk_r = self._pk_of_request(req_id)
        T.update(self.reencrypt(bk.batch_id, req_id, pk_r))
        r = self.retrieve(bk.batch_id, req_id, sk_r, bk.sha256, available_only, fetch_timeout_ms)
        T.update(r.timings)
        if r.ok:
            T["access_total_compute"] = (max(T["partial_per_sh"]) + T["verify_proofs"] + T["combine"] + T["reprotect"]
                                         + T["tx_submitReenc"] + T["requester_total"])
        return AccessResult(r.ok, r.data, req_id, T, r.reason)

    def _pk_of_request(self, req_id: int):
        # DataVault.access là biến nội bộ (không có getter) -> lưu pk Requester phía client khi gọi request_access
        return self._pk_cache[req_id]

    # ------------------------------------------------------------------ 4 hàm theo Thuật toán 1, 4, 5 [FT]
    def _gas_total(self) -> int:
        return sum(sum(v) for v in self.chain.gas.values())

    def upload_shares(self, shares: list[bytes]) -> dict:
        """Đẩy các mảnh IDA lên IPFS (mảnh i -> nút lưu trữ i%3). Trả về cids, digests (bytes32), elapsed_s."""
        t0 = perf()
        cids = [self.storage[i % 3].add(p) for i, p in enumerate(shares)]
        return {"cids": cids, "digests": [cid_to_digest(x) for x in cids], "elapsed_s": perf() - t0}

    def download_shares(self, cids: list, min_shares: int | None = None, timeout_ms: int = 30000) -> dict:
        """Tải song song, dừng khi đủ min_shares (mặc định t_ida) mảnh. cids nhận CIDv0 hoặc bytes32.
        Trả về shares {chỉ số: bytes}, elapsed_s."""
        need = min_shares or self.t_ida
        t0 = perf()
        got: dict[int, bytes] = {}
        ex = ThreadPoolExecutor(len(cids))
        futs = {ex.submit(self.requester_node.cat, _as_cid(c), timeout_ms): i for i, c in enumerate(cids)}
        try:
            for f in as_completed(futs):
                try:
                    got[futs[f]] = f.result()
                except Exception:
                    continue
                if len(got) >= need:
                    break
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        if len(got) < need:
            raise RuntimeError(f"chỉ lấy được {len(got)}/{need} mảnh")
        return {"shares": got, "elapsed_s": perf() - t0}

    def backup_to_chain(self, meta: dict, enc_items_7: list) -> dict:
        """Gọi DataVault.createBatch + addEncCids.
        meta = {"data_id": bytes32, "file_type": 1 (tùy chọn), "n": 6, "t": 4 (tùy chọn)}
        enc_items_7 = [((c1x, c1y), ct_bytes32), ...] (6 digest CID + 1 khóa AES, đã KEM-DEM bằng tcrypto.kem_dem_encrypt).
        Trả về batch_id, gas_total, elapsed_s."""
        c = self.chain
        g0, t0 = self._gas_total(), perf()
        c.send("DV.createBatch", c.vault.functions.createBatch(
            meta["data_id"], meta.get("n", self.n_ida), meta.get("t", self.t_ida), meta.get("file_type", 1)), c.do)
        batch_id = c.vault.functions.nextBatchId().call() - 1
        c.send(f"DV.addEncCids(batch {len(enc_items_7)})", c.vault.functions.addEncCids(
            batch_id, [p[0][0] for p in enc_items_7], [p[0][1] for p in enc_items_7], [p[1] for p in enc_items_7]), c.do)
        return {"batch_id": batch_id, "gas_total": self._gas_total() - g0, "elapsed_s": perf() - t0}

    def request_and_reenc(self, batch_id: int, pk_req: tuple, reenc_items_7: list, proofs_hash: bytes) -> dict:
        """Requester gửi yêu cầu (pk_req = (x, y)) -> t_sh Shareholder phê duyệt -> TElG.submitReencResult.
        reenc_items_7 = [((c1x, c1y), ct), ...] đã bảo vệ lại cho pk_req; proofs_hash = tcrypto.proofs_digest(...).
        Trả về req_id, gas_total, elapsed_s."""
        c = self.chain
        g0, t0 = self._gas_total(), perf()
        c.send("DV.requestDataAccess", c.vault.functions.requestDataAccess(batch_id, pk_req[0], pk_req[1]), c.req)
        req_id = c.request_count() - 1
        self._pk_cache[req_id] = pk_req
        self.approve(req_id)
        c.send(f"TElG.submitReencResult({len(reenc_items_7)} items)", c.telg.functions.submitReencResult(
            req_id, [r[0][0] for r in reenc_items_7], [r[0][1] for r in reenc_items_7],
            [r[1] for r in reenc_items_7], proofs_hash), c.shs[0])
        return {"req_id": req_id, "gas_total": self._gas_total() - g0, "elapsed_s": perf() - t0}

    # ------------------------------------------------------------------ báo cáo gas / xuất thông tin contract
    def gas_report(self) -> dict:
        """{nhãn: {n, mean, min, max}} — gas thực tế từ receipt (cho mục 2.4.3)."""
        return {k: {"n": len(v), "mean": sum(v) / len(v), "min": min(v), "max": max(v)}
                for k, v in self.chain.gas.items() if v}

    def export_contracts_info(self, path: str | Path = "contracts_info.json") -> dict:
        c = self.chain
        contracts = {}
        for name, obj in zip(CONTRACT_NAMES, [c.acl, c.dkg, c.vault, c.telg]):
            contracts[name] = {"address": obj.address, "abi": compile_contract(name)["abi"],
                               "deploy_gas": c.gas.get(f"deploy:{name}", [None])[0]}
        info = {
            "note": ("Chuỗi py-evm/eth-tester chạy trong tiến trình; địa chỉ chỉ hợp lệ trong tiến trình đã deploy."
                     if self.mode == "local" else f"Contract deploy trên {self.rpc_url}"),
            "mode": self.mode,
            "params": {"ida": {"n": self.n_ida, "t": self.t_ida}, "dkg": {"n": self.n_sh, "t": self.t_sh},
                       "curve": "secp256k1", "ipfs_nodes": self.n_ipfs if self.mode == "local" else None},
            "accounts": {"owner": c.owner, "data_owner": c.do, "shareholders": list(c.shs), "requester": c.req},
            "roles": {"1": "DATA_OWNER", "2": "SHAREHOLDER", "3": "REQUESTER"},
            "contracts": contracts,
            "dkg_public_key": {"x": hex(self.dkg.pk[0]), "y": hex(self.dkg.pk[1])},
        }
        Path(path).write_text(json.dumps(info, indent=2, ensure_ascii=False))
        return info
