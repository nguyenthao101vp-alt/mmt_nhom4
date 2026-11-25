import argparse
from face_engine import FaceEngine
from whitelist_manager import Whitelist


def main():
    parser = argparse.ArgumentParser(
        description="Quan ly whitelist cuc bo (dang ky, xem danh sach, xoa)."
    )
    parser.add_argument("--image", help="Duong dan anh co dung 1 khuon mat")
    parser.add_argument("--id", help="Ma dinh danh tu quy uoc cua nhom")
    parser.add_argument("--name", help="Ten hien thi/ten gia lap")
    parser.add_argument("--list", action="store_true", help="Hien thi danh sach trong whitelist")
    parser.add_argument("--remove", help="Xoa nguoi dung khoi whitelist theo ID")
    args = parser.parse_args()

    whitelist = Whitelist()

    if args.list:
        whitelist.list_entries()
        return

    if args.remove:
        whitelist.remove_by_id(args.remove)
        return

    if not (args.image and args.id and args.name):
        parser.error("Can truyen du --image, --id, --name de dang ky (hoac dung --list / --remove).")

    engine = FaceEngine()
    whitelist.add_from_image(args.image, args.id, args.name, engine)


if __name__ == "__main__":
    main()