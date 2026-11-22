from pathlib import Path
import json
import cv2
import numpy as np


class Whitelist:
    """Whitelist cuc bo: chi luu ten/ma va vector dac trung, khong luu anh goc."""

    def __init__(self, path=None):
        self.path = (
            Path(path)
            if path is not None
            else Path(__file__).resolve().parent / "whitelist/known_faces.json"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries = self._load()

    def _load(self):
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        return [
            {
                "person_id": item["person_id"],
                "display_name": item["display_name"],
                "embedding": np.asarray(item["embedding"], dtype=np.float32),
            }
            for item in raw
        ]

    def save(self):
        payload = [
            {
                "person_id": item["person_id"],
                "display_name": item["display_name"],
                "embedding": item["embedding"].astype(float).tolist(),
            }
            for item in self.entries
        ]
        temp_path = self.path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        temp_path.replace(self.path)

    def add_from_image(self, image_path, person_id, display_name, engine):
        image = cv2.imread(str(image_path))
        if image is None:
            raise ValueError(f"Khong doc duoc anh: {image_path}")

        faces = engine.detect_and_embed(image)
        if len(faces) != 1:
            raise ValueError(
                f"Anh dang ky phai co dung 1 khuon mat; hien phat hien {len(faces)}."
            )

        embedding = faces[0]["embedding"]
        self.entries = [e for e in self.entries if e["person_id"] != person_id]
        self.entries.append({
            "person_id": str(person_id),
            "display_name": str(display_name),
            "embedding": embedding,
        })
        self.save()
        print(f"[OK] Da them/cap nhat {display_name} ({person_id})")

    def match(self, query_embedding, threshold=0.363):
        """So cosine similarity voi whitelist. Threshold can duoc hieu chinh."""
        best = None
        best_score = -1.0

        for item in self.entries:
            known = item["embedding"]
            denom = float(np.linalg.norm(query_embedding) * np.linalg.norm(known))
            score = float(np.dot(query_embedding, known) / denom) if denom else -1.0

            if score > best_score:
                best_score = score
                best = item

        if best is not None and best_score >= threshold:
            return {
                "status": "whitelist_match",
                "person_id": best["person_id"],
                "display_name": best["display_name"],
                "similarity": best_score,
            }

        return {
            "status": "not_in_whitelist",
            "person_id": None,
            "display_name": None,
            "similarity": best_score if best is not None else None,
        }
