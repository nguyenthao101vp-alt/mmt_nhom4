"""
ffmpeg_processor.py
TV5 - Module cắt và nén clip sự kiện bằng FFmpeg.

Mục tiêu cấu hình theo kế hoạch nhóm:
- Thời lượng clip: 15 giây
- Video codec: H.264 (libx264)
- Bitrate video: 4 Mbps
- Không mã hóa âm thanh để giữ cấu hình dung lượng video gần mức 7,5 MB
  (dung lượng thực tế còn phụ thuộc container và nội dung video).

Lưu ý: Đây là module độc lập. Chưa tích hợp với module mã hóa TV4/IPFS/Smart Contract.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


DEFAULT_DURATION = 15.0
DEFAULT_PRE_EVENT = 5.0
DEFAULT_BITRATE = "4M"


class FFmpegError(RuntimeError):
    """Lỗi khi gọi FFmpeg hoặc xử lý video."""


def check_ffmpeg() -> str:
    """Kiểm tra FFmpeg có thể được gọi từ PATH hay không."""
    executable = shutil.which("ffmpeg")
    if executable is None:
        raise FFmpegError(
            "Không tìm thấy ffmpeg. Hãy kiểm tra FFmpeg đã cài và PATH đã được cấu hình."
        )
    return executable


def get_video_duration(input_path: str | Path) -> float:
    """Đọc thời lượng video bằng ffprobe đi kèm FFmpeg."""
    ffmpeg_path = check_ffmpeg()
    ffprobe = str(Path(ffmpeg_path).with_name("ffprobe.exe" if ffmpeg_path.lower().endswith(".exe") else "ffprobe"))

    if shutil.which("ffprobe") is None and not Path(ffprobe).exists():
        raise FFmpegError("Không tìm thấy ffprobe đi kèm FFmpeg.")

    source = Path(input_path)
    if not source.is_file():
        raise FileNotFoundError(f"Không tìm thấy video đầu vào: {source}")

    command = [
        ffprobe,
        "-v", "error",
        "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1",
        str(source),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise FFmpegError(result.stderr.strip() or "Không đọc được thời lượng video.")

    try:
        return float(result.stdout.strip())
    except ValueError as exc:
        raise FFmpegError("FFprobe trả về thời lượng video không hợp lệ.") from exc


def cut_and_compress_clip(
    input_path: str | Path,
    output_path: str | Path,
    event_timestamp: float,
    duration: float = DEFAULT_DURATION,
    pre_event: float = DEFAULT_PRE_EVENT,
    video_bitrate: str = DEFAULT_BITRATE,
) -> Path:
    """
    Cắt clip quanh thời điểm sự kiện và mã hóa H.264.

    event_timestamp: thời điểm sự kiện tính bằng giây kể từ đầu video.
    pre_event: số giây lấy trước thời điểm sự kiện.
    duration: tổng thời lượng clip đầu ra.
    """
    ffmpeg = check_ffmpeg()
    source = Path(input_path)
    destination = Path(output_path)

    if not source.is_file():
        raise FileNotFoundError(f"Không tìm thấy video đầu vào: {source}")
    if event_timestamp < 0:
        raise ValueError("event_timestamp phải lớn hơn hoặc bằng 0.")
    if duration <= 0:
        raise ValueError("duration phải lớn hơn 0.")
    if pre_event < 0:
        raise ValueError("pre_event không được âm.")

    total_duration = get_video_duration(source)
    start_time = max(0.0, event_timestamp - pre_event)

    if start_time >= total_duration:
        raise ValueError("Thời điểm sự kiện nằm ngoài thời lượng video.")

    actual_duration = min(duration, total_duration - start_time)
    if actual_duration <= 0:
        raise ValueError("Không còn dữ liệu video để cắt tại thời điểm đã chọn.")

    destination.parent.mkdir(parents=True, exist_ok=True)

    command = [
        ffmpeg,
        "-y",
        "-i", str(source),
        "-ss", f"{start_time:.3f}",
        "-t", f"{actual_duration:.3f}",
        "-map", "0:v:0",
        "-an",
        "-c:v", "libx264",
        "-preset", "medium",
        "-b:v", video_bitrate,
        "-maxrate", video_bitrate,
        "-bufsize", "8M",
        "-pix_fmt", "yuv420p",
        "-movflags", "+faststart",
        str(destination),
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise FFmpegError(result.stderr.strip() or "FFmpeg xử lý video thất bại.")

    if not destination.is_file() or destination.stat().st_size == 0:
        raise FFmpegError("FFmpeg không tạo được file đầu ra hợp lệ.")

    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cắt clip 15 giây quanh sự kiện và nén H.264 4 Mbps."
    )
    parser.add_argument("--input", required=True, help="Đường dẫn video đầu vào")
    parser.add_argument("--output", required=True, help="Đường dẫn clip đầu ra")
    parser.add_argument(
        "--event-time",
        required=True,
        type=float,
        help="Thời điểm sự kiện tính bằng giây kể từ đầu video",
    )
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    parser.add_argument("--pre-event", type=float, default=DEFAULT_PRE_EVENT)
    parser.add_argument("--bitrate", default=DEFAULT_BITRATE)
    args = parser.parse_args()

    try:
        output = cut_and_compress_clip(
            input_path=args.input,
            output_path=args.output,
            event_timestamp=args.event_time,
            duration=args.duration,
            pre_event=args.pre_event,
            video_bitrate=args.bitrate,
        )
        print(f"Đã tạo clip: {output}")
        print(f"Dung lượng: {output.stat().st_size / 1_000_000:.2f} MB")
    except (FFmpegError, FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
