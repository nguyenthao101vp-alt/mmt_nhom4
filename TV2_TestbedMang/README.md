# IoT Network TV2

Dự án thực nghiệm mạng cho thành viên 2 của đề tài Hybrid Blockchain–IPFS và camera phát hiện người lạ.

# Giai đoạn 1: Đo luồng
- Thay đổi file mp4 tại thư mục /video, (có thể add nhiều video).
- Tại Terminal của thư mục gốc, chạy lệnh sau cho 1 video test.mp4:
  python src/video_storage.py --video video/test.mp4  
- Hoặc để phân tích tất cả MP4 trong thư mục:
  python src/video_storage.py --dir video