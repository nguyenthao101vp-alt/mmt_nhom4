import argparse
from face_engine import FaceEngine
from whitelist_manager import Whitelist


def main():
    parser = argparse.ArgumentParser(
        description="Dang ky mot anh vao whitelist cuc bo (can su dong y cua nguoi trong anh)."
    )
    parser.add_argument("--image", required=True, help="Duong dan anh co dung 1 khuon mat")
    parser.add_argument("--id", required=True, help="Ma dinh danh tu quy uoc cua nhom")
    parser.add_argument("--name", required=True, help="Ten hien thi/ten gia lap")
    args = parser.parse_args()

    engine = FaceEngine()
    whitelist = Whitelist()
    whitelist.add_from_image(args.image, args.id, args.name, engine)


if __name__ == "__main__":
    main()
