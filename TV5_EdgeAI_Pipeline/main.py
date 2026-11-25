from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TV4_DIR = REPO_ROOT / "TV4_MatMa"
TV5_DIR = REPO_ROOT / "TV5_EdgeAI_Pipeline"
TV6_DIR = REPO_ROOT / "TV6_SmartContract_IPFS"
TV6_FILES_DIR = TV6_DIR / "files"
for folder in (REPO_ROOT, TV4_DIR, TV5_DIR, TV6_DIR, TV6_FILES_DIR):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from TV4_MatMa.crypto_lib_filetrust import RabinIDA, SymmetricCipher
from TV5_EdgeAI_Pipeline.analyze_video import analyze_video
from TV6_SmartContract_IPFS.files.client_api import FileTrustClient
from TV6_SmartContract_IPFS.ftpy import tcrypto as tv6_crypto
from TV6_SmartContract_IPFS.ftpy.ipfs_py import digest_to_cid


def timed_call(func, *args: Any, **kwargs: Any):
    started = time.perf_counter()
    result = func(*args, **kwargs)
    return result, time.perf_counter() - started


def safe_event_id(value: str) -> str:
    import re
    result = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._")[:120]
    if not result:
        raise ValueError("event_id khong hop le")
    return result


def verify_backup_roundtrip(
    client: FileTrustClient,
    clip_bytes: bytes,
    data_id: bytes,
    batch_id: int,
    ida: RabinIDA,
) -> tuple[dict[str, Any], dict[str, float]]:
    chain = client.chain
    if chain is None or client.dkg is None:
        raise RuntimeError("FileTrustClient.setup() must complete before verifying recovery")

    timings: dict[str, float] = {}
    started = time.perf_counter()
    gas_before_recovery = client._gas_total()
    requester_sk, requester_pk = tv6_crypto.keypair()
    if requester_pk is None:
        raise RuntimeError("Khong tao duoc khoa cong khai requester")

    t0 = time.perf_counter()
    chain.send(
        "DV.requestDataAccess",
        chain.vault.functions.requestDataAccess(batch_id, requester_pk[0], requester_pk[1]),
        chain.req,
    )
    req_id = chain.request_count() - 1
    timings["tv6_request_access"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    client.approve(req_id)
    timings["tv6_approve_access"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    reencrypt_timings = client.reencrypt(batch_id, req_id, requester_pk)
    timings["tv6_threshold_reencrypt"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    c1x, c1y, ciphertexts = chain.vault.functions.getRequesterCids(req_id).call()
    if len(ciphertexts) != 7:
        raise RuntimeError(f"Can 7 muc duoc tai ma hoa lai, nhan duoc {len(ciphertexts)}")
    items = [
        tv6_crypto.kem_dem_decrypt(
            requester_sk,
            (c1x[index], c1y[index]),
            ciphertext,
            tv6_crypto.context(data_id, batch_id, index),
        )
        for index, ciphertext in enumerate(ciphertexts)
    ]
    timings["tv6_requester_decrypt"] = time.perf_counter() - t0

    if any(len(digest) != 32 for digest in items[:6]) or len(items[6]) != 32:
        raise RuntimeError("Du lieu CID digest hoac khoa AES sau khi giai ma khong hop le")
    cids = [digest_to_cid(digest) for digest in items[:6]]
    t0 = time.perf_counter()
    downloaded = client.download_shares(cids, min_shares=4)
    timings["tv6_ipfs_download"] = time.perf_counter() - t0
    shares = downloaded["shares"]
    if len(shares) < 4:
        raise RuntimeError(f"Can 4 manh IDA de khoi phuc, nhan duoc {len(shares)}")

    t0 = time.perf_counter()
    encrypted_payload = ida.reconstruct(
        [(index + 1, piece) for index, piece in shares.items()]
    )
    timings["tv4_ida_reconstruct"] = time.perf_counter() - t0
    if len(encrypted_payload) < 28:
        raise RuntimeError("Payload AES-GCM sau khi khoi phuc qua ngan")

    t0 = time.perf_counter()
    recovered_clip = SymmetricCipher.decrypt(
        encrypted_payload[12:-16],
        items[6],
        encrypted_payload[:12],
        encrypted_payload[-16:],
        data_id,
    )
    timings["tv4_aes_gcm_decrypt"] = time.perf_counter() - t0
    expected_sha256 = hashlib.sha256(clip_bytes).hexdigest()
    recovered_sha256 = hashlib.sha256(recovered_clip).hexdigest()
    if recovered_sha256 != expected_sha256:
        raise RuntimeError("SHA-256 clip sau khi khoi phuc khong khop voi dau vao")

    timings["tv6_reencrypt_contract"] = reencrypt_timings["tx_submitReenc"]
    timings["tv6_recovery_gas"] = client._gas_total() - gas_before_recovery
    timings["tv6_roundtrip_total"] = time.perf_counter() - started
    return {
        "access_req_id": int(req_id),
        "round_trip_verified": True,
        "recovered_sha256": recovered_sha256,
    }, timings


def backup_event(client: FileTrustClient, clip_path: str | Path, event_id: str,
                 output_dir: str | Path) -> dict:
    clip_path = Path(clip_path)
    if not clip_path.is_file():
        raise FileNotFoundError(f"Khong tim thay clip: {clip_path}")
    clip_bytes = clip_path.read_bytes()
    if not clip_bytes:
        raise ValueError(f"Clip rong: {clip_path}")

    chain = client.chain
    dkg = client.dkg
    if chain is None or dkg is None:
        raise RuntimeError("FileTrustClient.setup() must complete before backing up events")

    safe_id = safe_event_id(event_id)
    data_id = hashlib.sha256(str(event_id).encode("utf-8")).digest()
    timings: dict[str, float] = {"clip_size_bytes": len(clip_bytes)}

    aes_key, timings["tv4_keygen"] = timed_call(SymmetricCipher.generate_key)
    (ciphertext, nonce, auth_tag), timings["tv4_aes_gcm"] = timed_call(
        SymmetricCipher.encrypt, clip_bytes, aes_key, data_id)
    # IDA phan tan ca ciphertext, nonce va tag de co the giai ma/xac thuc ve sau.
    encrypted_payload = nonce + ciphertext + auth_tag
    ida = RabinIDA(n=6, t=4)
    shares, timings["tv4_ida_6_4"] = timed_call(ida.disperse, encrypted_payload)
    share_bytes = [piece for _, piece in shares]

    uploaded, timings["tv6_ipfs_upload"] = timed_call(client.upload_shares, share_bytes)
    cids = uploaded["cids"]
    digests = uploaded["digests"]
    if len(cids) != 6 or len(digests) != 6:
        raise RuntimeError(f"Can 6 CID va digest, nhan duoc {len(cids)} va {len(digests)}")

    # Tao batch truoc de batch_id duoc dua vao context KEM-DEM.
    gas_before_backup = client._gas_total()
    t0 = time.perf_counter()
    chain.send("DV.createBatch", chain.vault.functions.createBatch(data_id, 6, 4, 1), chain.do)
    batch_id = chain.vault.functions.nextBatchId().call() - 1
    timings["tv6_create_batch"] = time.perf_counter() - t0

    items = list(digests) + [aes_key]
    t0 = time.perf_counter()
    protected = [tv6_crypto.kem_dem_encrypt(
        dkg.pk, item, tv6_crypto.context(data_id, batch_id, index)
    ) for index, item in enumerate(items)]
    c1_points = []
    ciphertexts = []
    for c1, ciphertext in protected:
        if c1 is None:
            raise RuntimeError("KEM-DEM generated a point at infinity")
        c1_points.append(c1)
        ciphertexts.append(ciphertext)
    timings["tv6_kem_dem"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    chain.send(
        "DV.addEncCids(7 items)",
        chain.vault.functions.addEncCids(
            batch_id,
            [point[0] for point in c1_points],
            [point[1] for point in c1_points],
            ciphertexts,
        ),
        chain.do,
    )
    timings["tv6_add_enc_cids"] = time.perf_counter() - t0
    timings["tv6_onchain_total"] = timings["tv6_create_batch"] + timings["tv6_add_enc_cids"]
    timings["gas_total"] = client._gas_total() - gas_before_backup
    timings["total_backup"] = sum(
        value for key, value in timings.items()
        if key not in {"clip_size_bytes", "gas_total", "tv6_onchain_total"}
    )

    verification, verification_timings = verify_backup_roundtrip(
        client, clip_bytes, data_id, batch_id, ida
    )
    timings.update(verification_timings)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "event_id": str(event_id), "batch_id": int(batch_id),
        "clip_path": str(clip_path.resolve()), "clip_size_bytes": len(clip_bytes),
        "encrypted_payload_size": len(encrypted_payload), "ida_n": 6, "ida_t": 4,
        "cids": cids, "timings": timings, **verification,
        "backup_gas": timings["gas_total"],
        "roundtrip_gas": client._gas_total() - gas_before_backup - timings["gas_total"],
        "architecture": "TV4 AES-256-GCM + IDA(6,4); TV6 IPFS + secp256k1 KEM-DEM + Smart Contract",
        "crypto_metadata": {"nonce_hex": nonce.hex(), "auth_tag_hex": auth_tag.hex(),
                            "aad_event_id_sha256": data_id.hex()},
    }
    (out_dir / f"{safe_id}_backup.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return record


def main():
    parser = argparse.ArgumentParser(description="TV5 orchestration: Edge AI -> TV4 crypto -> TV6 IPFS/Blockchain")
    default_video = TV5_DIR / "data" / "clip_tv2.mp4"
    parser.add_argument(
        "--video",
        default=str(default_video),
        help=f"Duong dan video dau vao (mac dinh: {default_video})",
    )
    parser.add_argument("--results", default=str(TV5_DIR / "results"))
    parser.add_argument("--mode", choices=["local", "remote"], default="local")
    parser.add_argument("--config", default=None, help="config.json cua TV2 neu can")
    parser.add_argument("--sample-every", type=int, default=5)
    parser.add_argument("--threshold", type=float, default=0.363)
    parser.add_argument("--cooldown", type=float, default=15.0)
    parser.add_argument("--camera-id", default="CAM_EDGE_01")
    args = parser.parse_args()

    if args.sample_every < 1:
        parser.error("--sample-every phai >= 1")
    if not -1.0 <= args.threshold <= 1.0:
        parser.error("--threshold phai nam trong [-1, 1]")
    if args.cooldown < 0:
        parser.error("--cooldown phai >= 0")

    video_path = Path(args.video).expanduser().resolve()
    if not video_path.is_file():
        parser.error(f"Khong tim thay video dau vao: {video_path}")

    results = Path(args.results)
    clips_dir = results / "clips"
    events_json = results / "tv5_events.json"
    csv_path = results / "face_events.csv"
    results.mkdir(parents=True, exist_ok=True)

    _, t_ai = timed_call(
        analyze_video, video_path, csv_path,
        sample_every=args.sample_every, threshold=args.threshold,
        clip_dir=clips_dir, events_json=events_json,
        cooldown_sec=args.cooldown, camera_id=args.camera_id,
    )
    events = json.loads(events_json.read_text(encoding="utf-8")) if events_json.exists() else []
    if not isinstance(events, list):
        raise RuntimeError(f"File event khong dung dinh dang danh sach: {events_json}")
    print(f"\n[TV5] AI + FFmpeg: {t_ai:.3f}s; so su kien: {len(events)}")
    if not events:
        with csv_path.open(newline="", encoding="utf-8-sig") as event_csv:
            has_unclipped_unknown = any(
                row.get("status") == "not_in_whitelist" and not row.get("clip_path")
                for row in csv.DictReader(event_csv)
            )
        if has_unclipped_unknown:
            raise RuntimeError(
                "Phat hien khuon mat chua co trong whitelist nhung khong tao duoc clip; "
                "kiem tra FFmpeg va log phan tich video."
            )
        summary = {
            "status": "no_events",
            "video": str(video_path),
            "ai_ffmpeg_seconds": t_ai,
            "event_count": 0,
            "backup_success": 0,
            "backups": [],
            "note": "Khong co su kien can backup.",
        }
        (results / "pipeline_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[INFO] Khong co clip su kien de backup. Da luu tong hop: {results / 'pipeline_summary.json'}")
        return

    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise RuntimeError(f"Event thu {index} khong phai object")
        clip_path = event.get("clip_path")
        if not clip_path:
            raise RuntimeError(f"Event thu {index} thieu clip_path")
        if not Path(clip_path).is_file():
            raise FileNotFoundError(f"Clip event khong ton tai: {clip_path}")

    client, t_setup = timed_call(
        lambda: FileTrustClient(mode=args.mode, config_path=args.config,
                                n_ida=6, t_ida=4, n_sh=5, t_sh=3,
                                info_path=None).setup()
    )
    print(f"[TV6] Setup blockchain/IPFS/DKG: {t_setup:.3f}s")

    reports = []
    for index, event in enumerate(events, start=1):
        clip_path = event.get("clip_path")
        event_id = event.get("event_id") or f"{args.camera_id}_{index}"
        report = backup_event(client, clip_path, event_id, results / "backups")
        reports.append(report)
        print(f"[OK] {event_id} -> batch {report['batch_id']} | "
              f"IPFS 6 shares | round-trip=OK | gas={report['timings']['gas_total']} | "
              f"backup={report['timings']['total_backup']:.3f}s")

    summary = {
        "status": "completed",
        "video": str(video_path), "ai_ffmpeg_seconds": t_ai,
        "tv6_setup_seconds": t_setup, "event_count": len(events),
        "backup_success": len(reports), "backups": reports,
        "gas_report": client.gas_report(),
        "note": "Moi backup duoc kiem tra request/approval/reencryption, tai 4/6 IPFS shares va khop SHA-256 khi khoi phuc.",
    }
    if summary["backup_success"] != summary["event_count"]:
        raise RuntimeError("So backup thanh cong khong khop so su kien")
    (results / "pipeline_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[FINISH] Da luu tong hop: {results / 'pipeline_summary.json'}")


if __name__ == "__main__":
    main()
