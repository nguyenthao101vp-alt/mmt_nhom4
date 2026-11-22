import argparse
import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import cv2

from face_engine import FaceEngine
from ffmpeg_processor import FFmpegError, cut_and_compress_clip
from whitelist_manager import Whitelist


def analyze_video(
    video_path,
    output_csv,
    sample_every=5,
    threshold=0.363,
    clip_dir="results/clips",
    events_json="results/tv4_events.json",
    cooldown_sec=15.0,
    camera_id="CAM_EDGE_01",
):
    engine = FaceEngine()
    whitelist = Whitelist()

    video_path = Path(video_path)
    cap = cv2.VideoCapture(str(video_path))
    if not cap.isOpened():
        raise RuntimeError(f"Khong mo duoc video: {video_path}")

    fps = cap.get(cv2.CAP_PROP_FPS) or 0.0
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    print(f"[INFO] FPS={fps:.2f}, frames={total_frames}, sample_every={sample_every}")
    print(f"[INFO] So nguoi trong whitelist: {len(whitelist.entries)}")

    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    clip_folder = Path(clip_dir) if clip_dir else None
    if clip_folder:
        clip_folder.mkdir(parents=True, exist_ok=True)

    frame_index = 0
    sampled = 0
    detected_count = 0
    unknown_count = 0
    clips_created = 0
    last_clip_time = -cooldown_sec
    tv4_payloads = []
    started = time.perf_counter()

    with output_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "frame", "timestamp_sec", "face_index", "bbox",
                "detection_confidence", "status", "person_id",
                "display_name", "cosine_similarity", "clip_path"
            ],
        )
        writer.writeheader()

        while True:
            ok, frame = cap.read()
            if not ok:
                break

            if frame_index % sample_every == 0:
                sampled += 1
                timestamp = frame_index / fps if fps > 0 else 0.0
                faces = engine.detect_and_embed(frame)

                for face_index, face in enumerate(faces):
                    detected_count += 1
                    result = whitelist.match(face["embedding"], threshold)
                    saved_clip = ""

                    if result["status"] == "not_in_whitelist":
                        unknown_count += 1
                        if clip_folder and (timestamp - last_clip_time) >= cooldown_sec:
                            clip_name = f"event_{camera_id}_f{frame_index}_t{timestamp:.1f}s.mp4"
                            target_clip = clip_folder / clip_name
                            try:
                                cut_and_compress_clip(
                                    input_path=video_path,
                                    output_path=target_clip,
                                    event_timestamp=timestamp,
                                )
                                saved_clip = str(target_clip.resolve())
                                last_clip_time = timestamp
                                clips_created += 1

                                file_size_mb = round(target_clip.stat().st_size / 1_000_000, 3)
                                print(
                                    f"[CLIP] Cat su kien tai {timestamp:.2f}s -> "
                                    f"{target_clip.name} ({file_size_mb} MB)"
                                )

                                tv4_payloads.append({
                                    "event_id": f"{camera_id}_{frame_index}_{int(time.time())}",
                                    "camera_id": camera_id,
                                    "source_video": str(video_path.resolve()),
                                    "clip_path": saved_clip,
                                    "clip_size_mb": file_size_mb,
                                    "event_timestamp_sec": round(timestamp, 3),
                                    "frame_index": frame_index,
                                    "detection_confidence": round(face["confidence"], 4),
                                    "max_whitelist_similarity": (
                                        round(result["similarity"], 4)
                                        if result["similarity"] is not None else None
                                    ),
                                    "status": "not_in_whitelist",
                                    "created_at_utc": datetime.now(timezone.utc).isoformat(),
                                })
                            except FFmpegError as exc:
                                print(f"[WARN] Loi cat clip tai {timestamp:.2f}s: {exc}")

                    writer.writerow({
                        "frame": frame_index,
                        "timestamp_sec": round(timestamp, 3),
                        "face_index": face_index,
                        "bbox": str(face["bbox"]),
                        "detection_confidence": round(face["confidence"], 4),
                        "status": result["status"],
                        "person_id": result["person_id"] or "",
                        "display_name": result["display_name"] or "",
                        "cosine_similarity": (
                            round(result["similarity"], 4)
                            if result["similarity"] is not None else ""
                        ),
                        "clip_path": saved_clip,
                    })

            frame_index += 1

    cap.release()
    elapsed = time.perf_counter() - started

    if events_json:
        json_path = Path(events_json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with json_path.open("w", encoding="utf-8") as jf:
            json.dump(tv4_payloads, jf, ensure_ascii=False, indent=2)

    print("\n===== KET QUA PHAN TICH =====")
    print(f"Tong frame video: {frame_index}")
    print(f"Frame da phan tich: {sampled}")
    print(f"Luot phat hien khuon mat: {detected_count}")
    print(f"Luot khong khop whitelist: {unknown_count}")
    if clip_folder:
        print(f"So clip su kien da cat: {clips_created}")
    print(f"Thoi gian xu ly: {elapsed:.3f} giay")
    print(f"CSV ket qua: {output_csv.resolve()}")
    if events_json:
        print(f"JSON cho TV4: {Path(events_json).resolve()}")
    print(
        "\nLuu y: 'not_in_whitelist' chi co nghia la khong khop du lieu dang ky; "
        "khong khang dinh danh tinh hay hanh vi cua nguoi do."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Phan tich video, doi chieu whitelist va cat clip su kien."
    )
    parser.add_argument("--video", required=True, help="Duong dan video dau vao")
    parser.add_argument("--output", default="results/face_events.csv")
    parser.add_argument("--sample-every", type=int, default=5,
                        help="Chi phan tich moi N frame; mac dinh 5")
    parser.add_argument("--threshold", type=float, default=0.363,
                        help="Nguong cosine SFace tham khao; can danh gia tren du lieu test")
    parser.add_argument("--clip-dir", default="results/clips",
                        help="Thu muc luu clip su kien (truyen rong '' de tat cat clip)")
    parser.add_argument("--events-json", default="results/tv4_events.json",
                        help="File JSON metadata su kien xuat cho module TV4")
    parser.add_argument("--cooldown", type=float, default=15.0,
                        help="Thoi gian cho (giay) giua 2 lan cat clip lien tiep")
    parser.add_argument("--camera-id", default="CAM_EDGE_01",
                        help="Ma dinh danh camera gan vao metadata su kien")
    args = parser.parse_args()

    if args.sample_every < 1:
        parser.error("--sample-every phai >= 1")
    if not -1.0 <= args.threshold <= 1.0:
        parser.error("--threshold phai nam trong [-1, 1]")
    if args.cooldown < 0:
        parser.error("--cooldown phai >= 0")

    analyze_video(
        video_path=args.video,
        output_csv=args.output,
        sample_every=args.sample_every,
        threshold=args.threshold,
        clip_dir=args.clip_dir or None,
        events_json=args.events_json or None,
        cooldown_sec=args.cooldown,
        camera_id=args.camera_id,
    )


if __name__ == "__main__":
    main()