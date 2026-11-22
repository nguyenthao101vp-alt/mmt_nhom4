from pathlib import Path
from urllib.request import urlretrieve

MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

MODELS = {
    "face_detection_yunet_2023mar.onnx":
        "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
    "face_recognition_sface_2021dec.onnx":
        "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
}

for filename, url in MODELS.items():
    destination = MODEL_DIR / filename
    if destination.exists() and destination.stat().st_size > 0:
        print(f"[OK] Da co: {destination}")
        continue
    print(f"[DOWNLOAD] {filename}")
    try:
        urlretrieve(url, destination)
        if destination.stat().st_size < 10_000:
            destination.unlink(missing_ok=True)
            raise RuntimeError("File tai ve qua nho, co the link model da thay doi.")
        print(f"[OK] Da luu: {destination}")
    except Exception as exc:
        destination.unlink(missing_ok=True)
        print(f"[ERROR] Khong tai duoc {filename}: {exc}")
        print("Hay tai model tu OpenCV Zoo va dat dung ten file trong thu muc models/.")
        raise

print("Da tai xong hai model.")
