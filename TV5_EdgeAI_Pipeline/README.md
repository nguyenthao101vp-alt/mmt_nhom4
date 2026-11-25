# TV5 - Edge AI Face Module & FFmpeg Event Clipper

Module phat hien khuon mat (YuNet), tao vector dac trung (SFace), doi chieu whitelist cuc bo, tu dong cat/nen clip su kien (15s, H.264, 4 Mbps) bang FFmpeg va xuat metadata JSON cho module TV4.

## 1. Cau truc thu muc

```text
TV5_EdgeAI_Pipeline/
├── models/                  # ONNX models (khong commit len Git)
├── whitelist/               # known_faces.json (khong commit len Git)
├── data/                    # anh dang ky va video test
├── results/                 # CSV, JSON metadata va thu muc clips/
├── face_engine.py           # YuNet detector + SFace embedding
├── whitelist_manager.py     # Quan ly whitelist cuc bo
├── enroll.py                # CLI dang ky / xem / xoa whitelist
├── ffmpeg_processor.py      # Module cat va nen clip H.264 4 Mbps
├── analyze_video.py         # Luong chinh: phan tich video + cat clip + xuat JSON
├── download_models.py       # Tai model tu OpenCV Zoo
└── requirements.txt
```

## Chay pipeline

Tu thu muc goc repo, chay voi video mac dinh `TV5_EdgeAI_Pipeline/data/clip_tv2.mp4`:

```powershell
python TV5_EdgeAI_Pipeline/main.py
```

Truyen video khac bang `--video`; duong dan co khoang trang can dat trong dau ngoac kep:

```powershell
python TV5_EdgeAI_Pipeline/main.py --video "C:\duong dan\video.mp4"
```