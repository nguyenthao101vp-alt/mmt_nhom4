#!/usr/bin/env bash
# Chạy tại thư mục gốc repo TV6:  bash make_handoff.sh
# Test -> xuất contracts_info.json -> nén TV6_Client_Handoff.zip. Dừng ngay nếu test lỗi.
set -euo pipefail
python3 test_client_api.py                       # tạo luôn contracts_info.json nếu PASS
test -s contracts_info.json || { echo "THIẾU contracts_info.json"; exit 1; }
rm -f TV6_Client_Handoff.zip
FILES="client_api.py contracts_info.json HANDOFF_README.md test_client_api.py ftpy contracts"
[ -f results/e2e.json ] && FILES="$FILES results/e2e.json"
zip -r TV6_Client_Handoff.zip $FILES -x "*/__pycache__/*" "*.pyc"
ls -lh TV6_Client_Handoff.zip && echo "Xong -> gửi cho TV1, TV5"
