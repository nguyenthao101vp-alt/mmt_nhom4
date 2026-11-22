from pathlib import Path
import cv2
import numpy as np


class FaceEngine:
    """Phat hien khuon mat bang YuNet va tao embedding bang SFace."""

    def __init__(
        self,
        detector_path=None,
        recognizer_path=None,
        detection_threshold=0.85,
        nms_threshold=0.30,
        top_k=5000,
    ):
        module_dir = Path(__file__).resolve().parent
        detector_path = (
            Path(detector_path)
            if detector_path
            else module_dir / "models/face_detection_yunet_2023mar.onnx"
        )
        recognizer_path = (
            Path(recognizer_path)
            if recognizer_path
            else module_dir / "models/face_recognition_sface_2021dec.onnx"
        )

        for model_path in (detector_path, recognizer_path):
            if not model_path.exists():
                raise FileNotFoundError(
                    f"Thieu model: {model_path}. Hay chay: python download_models.py"
                )

        if not hasattr(cv2, "FaceDetectorYN") or not hasattr(cv2, "FaceRecognizerSF"):
            raise RuntimeError(
                "OpenCV hien tai chua ho tro FaceDetectorYN/FaceRecognizerSF. "
                "Hay cai opencv-python >= 4.10.0 va khong cai dong thoi "
                "opencv-contrib-python."
            )

        self.detector = cv2.FaceDetectorYN.create(
            str(detector_path),
            "",
            (320, 320),
            detection_threshold,
            nms_threshold,
            top_k,
        )
        self.recognizer = cv2.FaceRecognizerSF.create(
            str(recognizer_path), ""
        )

    def detect_and_embed(self, frame):
        """Tra ve list cac khuon mat: bbox, confidence, embedding."""
        height, width = frame.shape[:2]
        self.detector.setInputSize((width, height))
        _, faces = self.detector.detect(frame)

        results = []
        if faces is None:
            return results

        for face in faces:
            # YuNet: x, y, w, h, 5 landmarks, confidence
            confidence = float(face[-1])
            aligned = self.recognizer.alignCrop(frame, face)
            feature = self.recognizer.feature(aligned).flatten().astype(np.float32)

            norm = np.linalg.norm(feature)
            if norm > 0:
                feature = feature / norm

            x, y, w, h = [int(round(v)) for v in face[:4]]
            results.append({
                "bbox": (x, y, w, h),
                "confidence": confidence,
                "embedding": feature,
            })
        return results
