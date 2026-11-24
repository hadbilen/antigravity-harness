#!/usr/bin/env python3
"""
skills/media-studio/scripts/media_qc.py — Deterministic audio/video probe, quality gate & EBU R128 mastering CLI
Part of Plumbwork (https://github.com/hadbilen/plumbwork)
Python standard library + system ffmpeg (>= 5.1 recommended; automatic -vsync fallback on < 5.1) / ffprobe; runs on Python 3.10 and later.

Rule families (enforced by `check`):
  MEDIA-1  Stream & duration integrity    (missing/empty file, unreadable container, 0 streams, or duration <= 0s)
  MEDIA-2  Stream geometry & sync drift   (audio/video duration drift > 100ms, or odd dimensions on yuv420p video)
  MEDIA-3  Audio true-peak & silence      (True Peak > --max-true-peak dBTP, or silent audio track <= -70 LUFS / Peak dBFS under --game-sfx)
  MEDIA-4  Loudness target compliance     (Integrated loudness outside --target-lufs +/- --lufs-tolerance LU; skipped <0.5s under --game-sfx)
  MEDIA-5  Audio DC offset guard          (Absolute DC offset > --max-dc-offset)
  MEDIA-6  Decoder pixel-format safety    (H.264 MP4 using non-yuv420p chroma subsampling without --allow-high-chroma)
  MEDIA-7  Black or frozen video guard    (Video stream >= 90% black frames or >= 95% frozen frames on >1s clips)
  GAME-1   Opt-in audio loop seam guard   (--check-loop: normalized wrap step <= --max-seam-step and slope impulse <= --max-seam-impulse)
  GAME-2   Opt-in pixel-art guard         (--pixel-art: semi-transparent fringe <= 1%; compare integer scale & uniform kxk blocks)
  GAME-3   Opt-in sprite-atlas guard      (--sprite-atlas / --tile-size / --require-pot / --check-alpha-bleed geometry, halos & gutter edges)

Subcommands:
  probe         Inspect container and stream metadata (codec, pix_fmt, color space, VFR/CFR, duration, channels)
  check         Run EBU R128, astats, blackdetect, freezedetect & still-image decode QC (MEDIA-1..MEDIA-7, optional GAME-1..GAME-3)
  salvage       Non-destructively recover truncated headers or damaged container indices via stream-copy first
  compare       Compute objective SSIM, PSNR, aspect-ratio fidelity & optional pixel-art integer scaling against reference
  ab-sheet      Render a side-by-side Reference vs. Enhanced PNG sheet (LANCZOS or --pixel-art nearest-neighbor)
  master-audio  Execute Two-Pass EBU R128 loudnorm or --game-sfx/--peak-db linear peak mastering (--ogg-codec, --trim-loop)
  keyframes     Extract a tiled keyframe contact-sheet PNG for visual inspection (read_file)

Exit codes: 0 clean / passed, 1 quality findings or threshold failure, 2 argument or runtime tool error.
"""

from __future__ import annotations

import argparse
import array
import contextlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    fix_hint: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


_DISALLOWED_DEMUX_FORMATS = frozenset({"hls", "applehttp", "dash", "concat", "sdp", "rtsp", "rtp"})
_PLAYLIST_HEADER_PREFIXES = (b"#extm3u", b"ffconcat", b"rtsp/", b"<mpd")
DEFAULT_SUBPROCESS_TIMEOUT = float(os.environ.get("MEDIA_QC_TIMEOUT_SEC", "120"))
MAX_AB_CANVAS_DIM = 8192
MAX_AB_CANVAS_PIXELS = 33_554_432
MAX_GAME_AUDIO_SEC = 300.0
MAX_GAME_AUDIO_SR = 384_000
MAX_GAME_AUDIO_BYTES = 268_435_456
MAX_GAME_VISUAL_PIXELS = 67_108_864
_TILE_SIZE_RE = re.compile(r"^\s*(\d+)\s*[xX]\s*(\d+)\s*$")


def _run_media_subprocess(
    cmd: Sequence[str],
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess[str]:
    eff_timeout = DEFAULT_SUBPROCESS_TIMEOUT if timeout is None else float(timeout)
    _require_finite_param("timeout", eff_timeout)
    if eff_timeout <= 0:
        raise ValueError(f"Parameter 'timeout' must be > 0 (got {eff_timeout!r}).")
    try:
        return subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=eff_timeout,
        )
    except subprocess.TimeoutExpired as exc:
        tool_name = Path(cmd[0]).name if cmd else "subprocess"
        raise TimeoutError(f"{tool_name} timed out after {eff_timeout:.1f}s") from exc


def _run_media_subprocess_bounded_bytes(
    cmd: Sequence[str],
    max_bytes: int,
    timeout: Optional[float] = None,
) -> Tuple[int, bytes, bytes]:
    eff_timeout = DEFAULT_SUBPROCESS_TIMEOUT if timeout is None else float(timeout)
    _require_finite_param("timeout", eff_timeout)
    if eff_timeout <= 0:
        raise ValueError(f"Parameter 'timeout' must be > 0 (got {eff_timeout!r}).")
    if max_bytes <= 0:
        raise ValueError(f"Parameter 'max_bytes' must be > 0 (got {max_bytes!r}).")
    tool_name = Path(cmd[0]).name if cmd else "subprocess"
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    stderr_chunks: List[bytes] = []
    stdout_chunks: List[bytes] = []
    total_stdout = 0
    timed_out = threading.Event()
    overflowed = False

    def _on_timeout() -> None:
        timed_out.set()
        try:
            proc.kill()
        except OSError:
            pass

    def _drain_stderr() -> None:
        if proc.stderr is None:
            return
        err_total = 0
        try:
            while True:
                chunk = proc.stderr.read(8192)
                if not chunk:
                    break
                if err_total < 65536:
                    stderr_chunks.append(chunk)
                    err_total += len(chunk)
        except OSError:
            pass

    timer = threading.Timer(eff_timeout, _on_timeout)
    timer.daemon = True
    err_thread = threading.Thread(target=_drain_stderr, daemon=True)
    timer.start()
    err_thread.start()
    try:
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            total_stdout += len(chunk)
            if total_stdout > max_bytes:
                overflowed = True
                try:
                    proc.kill()
                except OSError:
                    pass
                break
            stdout_chunks.append(chunk)
        returncode = proc.wait(timeout=max(0.5, eff_timeout))
    except subprocess.TimeoutExpired as exc:
        timed_out.set()
        try:
            proc.kill()
            proc.wait(timeout=1.0)
        except OSError:
            pass
        raise TimeoutError(f"{tool_name} timed out after {eff_timeout:.1f}s") from exc
    finally:
        timer.cancel()
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
        err_thread.join(timeout=2.0)
        if proc.stderr is not None:
            try:
                proc.stderr.close()
            except OSError:
                pass

    if timed_out.is_set():
        raise TimeoutError(f"{tool_name} timed out after {eff_timeout:.1f}s")
    if overflowed:
        raise ValueError(f"Decoded stream from {tool_name} exceeded {max_bytes}-byte safety ceiling.")
    return returncode, b"".join(stdout_chunks), b"".join(stderr_chunks)


def _require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"Required binary '{name}' not found on PATH.")
    return resolved


def _safe_media_arg(path: Path) -> str:
    raw = str(path)
    if path.is_absolute():
        return raw
    if raw.startswith(("./", ".\\", "../", "..\\")):
        return raw
    return f".{os.sep}{raw}"


def _guard_local_media_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Media file does not exist: {path}")
    try:
        with path.open("rb") as fh:
            head = fh.read(512)
    except OSError as exc:
        raise RuntimeError(f"Unable to read media file '{path}': {exc}") from exc
    stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if any(stripped.startswith(prefix) for prefix in _PLAYLIST_HEADER_PREFIXES):
        raise ValueError(f"Refusing playlist or network manifest input: {path}")


def _check_output_target_safety(output_path: Path, forbidden_sources: Sequence[Path]) -> None:
    if os.path.islink(output_path):
        raise ValueError(f"Refusing to write media output through symlink: {output_path}")
    sys_roots = {
        Path("/"),
        Path("/tmp"),
        Path("/var"),
        Path("/private"),
        Path("/private/tmp"),
        Path("/private/var"),
        Path(os.path.abspath(tempfile.gettempdir())),
    }
    anc = Path(os.path.abspath(output_path)).parent
    while anc not in sys_roots and anc.parent != anc:
        if os.path.islink(anc):
            raise ValueError(f"Refusing to write through symlinked parent directory: {anc}")
        anc = anc.parent

    out_resolved = output_path.resolve()
    out_exists = output_path.exists()
    for src in forbidden_sources:
        if out_resolved == src.resolve():
            raise ValueError("Non-destructive rule violation: output path must differ from input path.")
        if out_exists and src.exists() and os.path.samefile(output_path, src):
            raise ValueError("Non-destructive rule violation: output path shares hardlink inode with input path.")


@contextlib.contextmanager
def _staged_output(
    output_path: Path,
    forbidden_sources: Sequence[Path],
) -> Iterator[Tuple[Path, Callable[[], None]]]:
    _check_output_target_safety(output_path, forbidden_sources)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=".media_qc_stage_", dir=str(output_path.parent)))
    os.chmod(stage_dir, 0o700)
    staged_file = stage_dir / f"staged{output_path.suffix}"

    def _commit() -> None:
        if os.path.islink(staged_file) or not staged_file.is_file() or staged_file.stat().st_size == 0:
            raise RuntimeError(f"Staged output was not created or is empty: {staged_file}")
        _check_output_target_safety(output_path, forbidden_sources)
        os.replace(staged_file, output_path)

    try:
        yield staged_file, _commit
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)


def _require_finite_param(name: str, val: Optional[float]) -> None:
    if val is not None and (not isinstance(val, (int, float)) or not math.isfinite(float(val))):
        raise ValueError(f"Parameter '{name}' must be a finite number (got {val!r}).")


def _parse_fraction(val: Optional[str]) -> Optional[float]:
    if not val:
        return None
    norm = str(val).strip()
    if not norm or norm.lower() in ("0/0", "0:0", "n/a", "nan", "-nan", "+nan"):
        return None
    if "/" in norm:
        num_s, den_s = norm.split("/", 1)
        try:
            num, den = float(num_s), float(den_s)
            if den == 0.0:
                return None
            res = num / den
            return res if math.isfinite(res) else None
        except ValueError:
            return None
    try:
        res = float(norm)
        return res if math.isfinite(res) else None
    except ValueError:
        return None


def _safe_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    if isinstance(val, str):
        norm = val.strip().lower()
        if not norm or norm in ("n/a", "nan", "-nan", "+nan"):
            return None
        if norm in ("inf", "+inf"):
            return float("inf")
        if norm == "-inf":
            return float("-inf")
    try:
        res = float(val)
        return None if math.isnan(res) else res
    except (TypeError, ValueError):
        return None


def _parse_stream_duration(stream: Dict[str, Any]) -> Optional[float]:
    direct = _safe_float(stream.get("duration"))
    if direct is not None and math.isfinite(direct) and direct >= 0.0:
        return direct
    tags = stream.get("tags") or {}
    tag_dur = tags.get("DURATION") or tags.get("duration")
    if isinstance(tag_dur, str):
        m = re.match(r"^(\d+):(\d+):(\d+(?:\.\d+)?)", tag_dur.strip())
        if m:
            sec = round(int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3)), 6)
            return sec if math.isfinite(sec) and sec >= 0.0 else None
    return None


def _extract_rotation_deg(obj: Dict[str, Any]) -> int:
    tags = obj.get("tags") or {}
    rot_tag = _safe_float(tags.get("rotate"))
    if rot_tag is not None and math.isfinite(rot_tag):
        return int(round(rot_tag)) % 360
    for sd in obj.get("side_data_list") or []:
        if isinstance(sd, dict) and "rotation" in sd:
            rot_sd = _safe_float(sd.get("rotation"))
            if rot_sd is not None and math.isfinite(rot_sd):
                return int(round(rot_sd)) % 360
    return 0


def _probe_first_frame_rotation(ffprobe: str, safe_arg: str, timeout: Optional[float] = None) -> int:
    cmd = [
        ffprobe,
        "-v",
        "error",
        "-protocol_whitelist",
        "file",
        "-read_intervals",
        "%+#1",
        "-select_streams",
        "v:0",
        "-show_frames",
        "-show_entries",
        "frame=side_data_list",
        "-of",
        "json",
        "-i",
        safe_arg,
    ]
    try:
        proc = _run_media_subprocess(cmd, timeout=timeout)
    except TimeoutError:
        return 0
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return 0
    try:
        frames = (json.loads(proc.stdout) or {}).get("frames") or []
    except ValueError:
        return 0
    return _extract_rotation_deg(frames[0]) if frames and isinstance(frames[0], dict) else 0


def probe_media(path: Path, timeout: Optional[float] = None) -> Dict[str, Any]:
    ffprobe = _require_tool("ffprobe")
    if not path.is_file():
        raise FileNotFoundError(f"Media file does not exist: {path}")
    size_bytes = path.stat().st_size
    if size_bytes == 0:
        raise ValueError(f"Media file is empty (0 bytes): {path}")
    _guard_local_media_file(path)

    safe_arg = _safe_media_arg(path)
    cmd = [
        ffprobe,
        "-v",
        "error",
        "-protocol_whitelist",
        "file",
        "-show_format",
        "-show_streams",
        "-of",
        "json",
        "-i",
        safe_arg,
    ]
    proc = _run_media_subprocess(cmd, timeout=timeout)
    if proc.returncode != 0:
        err_text = (proc.stderr or proc.stdout or "unknown ffprobe error").strip()
        raise RuntimeError(f"ffprobe failed on '{path}': {err_text}")
    if not (proc.stdout or "").strip():
        raise RuntimeError(f"ffprobe returned empty metadata output for '{path}'.")

    raw = json.loads(proc.stdout)
    if not isinstance(raw, dict) or ("format" not in raw and "streams" not in raw):
        raise RuntimeError(f"ffprobe returned incomplete metadata JSON for '{path}'.")
    fmt = raw.get("format") or {}
    fmt_name = str(fmt.get("format_name") or "")
    fmt_tokens = {tok.strip().lower() for tok in fmt_name.split(",") if tok.strip()}
    if fmt_tokens & _DISALLOWED_DEMUX_FORMATS:
        raise ValueError(f"Refusing playlist or network container format '{fmt_name}' in '{path}'.")
    streams = raw.get("streams") or []

    video_streams: List[Dict[str, Any]] = []
    audio_streams: List[Dict[str, Any]] = []

    for s in streams:
        codec_type = s.get("codec_type")
        if codec_type == "video":
            r_fps = _parse_fraction(s.get("r_frame_rate"))
            avg_fps = _parse_fraction(s.get("avg_frame_rate"))
            is_vfr = False
            if r_fps and avg_fps and r_fps > 0 and avg_fps > 0:
                is_vfr = abs(r_fps - avg_fps) / max(r_fps, avg_fps) > 0.03
            rot_deg = _extract_rotation_deg(s)
            video_streams.append(
                {
                    "index": s.get("index"),
                    "codec_name": s.get("codec_name"),
                    "profile": s.get("profile"),
                    "width": s.get("width"),
                    "height": s.get("height"),
                    "rotation": rot_deg,
                    "pix_fmt": s.get("pix_fmt"),
                    "field_order": s.get("field_order", "unknown"),
                    "color_space": s.get("color_space", "unknown"),
                    "color_transfer": s.get("color_transfer", "unknown"),
                    "color_primaries": s.get("color_primaries", "unknown"),
                    "sample_aspect_ratio": s.get("sample_aspect_ratio", "1:1"),
                    "display_aspect_ratio": s.get("display_aspect_ratio"),
                    "r_frame_rate": s.get("r_frame_rate"),
                    "avg_frame_rate": s.get("avg_frame_rate"),
                    "fps": round(avg_fps or r_fps or 0.0, 4),
                    "is_vfr": is_vfr,
                    "duration": _parse_stream_duration(s),
                    "nb_frames": int(s["nb_frames"]) if str(s.get("nb_frames", "")).isdigit() else None,
                }
            )
        elif codec_type == "audio":
            audio_streams.append(
                {
                    "index": s.get("index"),
                    "codec_name": s.get("codec_name"),
                    "sample_rate": int(s["sample_rate"]) if str(s.get("sample_rate", "")).isdigit() else None,
                    "channels": s.get("channels"),
                    "channel_layout": s.get("channel_layout", "unknown"),
                    "sample_fmt": s.get("sample_fmt"),
                    "bits_per_raw_sample": s.get("bits_per_raw_sample"),
                    "duration": _parse_stream_duration(s),
                    "bit_rate": int(s["bit_rate"]) if str(s.get("bit_rate", "")).isdigit() else None,
                }
            )

    if video_streams and video_streams[0].get("rotation", 0) == 0 and (
        bool(fmt_tokens & {"image2", "jpeg_pipe", "mjpeg", "tiff_pipe", "webp_pipe", "png_pipe"})
        or path.suffix.lower() in (".jpg", ".jpeg", ".tif", ".tiff", ".webp")
    ):
        video_streams[0]["rotation"] = _probe_first_frame_rotation(ffprobe, safe_arg, timeout=timeout)

    container_duration = _safe_float(fmt.get("duration"))
    if container_duration is not None and (not math.isfinite(container_duration) or container_duration < 0.0):
        container_duration = None
    stream_durations = [
        d
        for d in ([v.get("duration") for v in video_streams] + [a.get("duration") for a in audio_streams])
        if d is not None and math.isfinite(d) and d >= 0.0
    ]
    effective_duration = (
        container_duration
        if container_duration is not None
        else (max(stream_durations) if stream_durations else 0.0)
    )

    av_drift_sec: Optional[float] = None
    v_durs = [v["duration"] for v in video_streams if v.get("duration") is not None]
    a_durs = [a["duration"] for a in audio_streams if a.get("duration") is not None]
    if v_durs and a_durs:
        av_drift_sec = round(max(abs(vd - ad) for vd in v_durs for ad in a_durs), 4)

    return {
        "path": str(path),
        "size_bytes": size_bytes,
        "format_name": fmt.get("format_name"),
        "duration_sec": effective_duration,
        "bit_rate": int(fmt["bit_rate"]) if str(fmt.get("bit_rate", "")).isdigit() else None,
        "video_streams": video_streams,
        "audio_streams": audio_streams,
        "av_drift_sec": av_drift_sec,
    }


def _analyze_audio_signal(path: Path, timeout: Optional[float] = None) -> Dict[str, Any]:
    ffmpeg = _require_tool("ffmpeg")
    _guard_local_media_file(path)
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-nostdin",
        "-err_detect",
        "explode",
        "-protocol_whitelist",
        "file",
        "-i",
        _safe_media_arg(path),
        "-map",
        "0:a:0",
        "-vn",
        "-sn",
        "-dn",
        "-af",
        "astats=reset=0,ebur128=peak=true",
        "-f",
        "null",
        "-",
    ]
    try:
        proc = _run_media_subprocess(cmd, timeout=timeout)
    except TimeoutError as exc:
        return {
            "decode_error": True,
            "timeout_error": str(exc),
            "integrated_lufs": None,
            "lra_lu": None,
            "true_peak_dbtp": None,
            "dc_offset": None,
            "peak_level_db": None,
            "rms_level_db": None,
            "flat_factor_db": None,
        }
    log = (proc.stderr or "") + "\n" + (proc.stdout or "")

    # Extract EBU R128 summary metrics strictly from the final Summary block
    summary_blocks = log.split("Summary:")
    has_summary = len(summary_blocks) > 1
    ebur_block = summary_blocks[-1] if has_summary else ""

    m_i = re.search(r"\bI:\s*([+-]?\d+(?:\.\d+)?|-inf|inf)\s*LUFS", ebur_block)
    m_lra = re.search(r"\bLRA:\s*([+-]?\d+(?:\.\d+)?)\s*LU", ebur_block)
    m_tp = re.search(r"True peak:.*?Peak:\s*([+-]?\d+(?:\.\d+)?|-inf|inf)\s*dBFS", ebur_block, re.DOTALL)

    # Extract Overall astats metrics strictly after the last "Overall" header
    overall_blocks = re.split(r"\[Parsed_astats[^\]]*\]\s*Overall", log)
    has_overall = len(overall_blocks) > 1
    astats_block = overall_blocks[-1] if has_overall else ""

    m_dc = re.search(r"DC offset:\s*([+-]?\d+(?:\.\d+)?)", astats_block)
    m_peak_db = re.search(r"Peak level dB:\s*([+-]?\d+(?:\.\d+)?|-inf|inf)", astats_block)
    m_rms_db = re.search(r"RMS level dB:\s*([+-]?\d+(?:\.\d+)?|-inf|inf)", astats_block)
    m_flat = re.search(r"Flat factor:\s*([+-]?\d+(?:\.\d+)?)", astats_block)

    return {
        "decode_error": proc.returncode != 0 or not has_summary or not has_overall,
        "integrated_lufs": _safe_float(m_i.group(1)) if m_i else None,
        "lra_lu": _safe_float(m_lra.group(1)) if m_lra else None,
        "true_peak_dbtp": _safe_float(m_tp.group(1)) if m_tp else None,
        "dc_offset": _safe_float(m_dc.group(1)) if m_dc else None,
        "peak_level_db": _safe_float(m_peak_db.group(1)) if m_peak_db else None,
        "rms_level_db": _safe_float(m_rms_db.group(1)) if m_rms_db else None,
        "flat_factor_db": _safe_float(m_flat.group(1)) if m_flat else None,
    }


def _analyze_video_signal(path: Path, duration_sec: float, fps: float, timeout: Optional[float] = None) -> Dict[str, Any]:
    ffmpeg = _require_tool("ffmpeg")
    _guard_local_media_file(path)
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-nostdin",
        "-err_detect",
        "explode",
        "-protocol_whitelist",
        "file",
        "-i",
        _safe_media_arg(path),
        "-an",
        "-vf",
        "signalstats=stat=brng,metadata=mode=print,blackdetect=d=0.1:pix_th=0.05,freezedetect=n=0.003:d=0.5",
        "-f",
        "null",
        "-",
    ]
    try:
        proc = _run_media_subprocess(cmd, timeout=timeout)
    except TimeoutError as exc:
        return {
            "decode_error": True,
            "timeout_error": str(exc),
            "max_brng_pixels": 0,
            "black_duration_sec": 0.0,
            "black_ratio": 0.0,
            "freeze_duration_sec": 0.0,
            "freeze_ratio": 0.0,
        }
    log = (proc.stderr or "") + "\n" + (proc.stdout or "")

    brng_values = [int(x) for x in re.findall(r"lavfi\.signalstats\.BRNG=(\d+)", log)]
    max_brng = max(brng_values) if brng_values else 0

    black_durations = [float(x) for x in re.findall(r"black_duration:([0-9.]+)", log)]
    total_black = sum(black_durations)

    # Freezedetect logs freeze_start, and freeze_duration when freeze ends before EOF.
    freeze_starts = [float(x) for x in re.findall(r"freeze_start:\s*([0-9.]+)", log)]
    freeze_ends = [float(x) for x in re.findall(r"freeze_end:\s*([0-9.]+)", log)]
    freeze_durations = [float(x) for x in re.findall(r"freeze_duration:\s*([0-9.]+)", log)]
    total_freeze = sum(freeze_durations)
    if len(freeze_starts) > len(freeze_ends) and duration_sec > 0 and math.isfinite(duration_sec):
        unclosed_start = freeze_starts[-1]
        if duration_sec > unclosed_start:
            total_freeze += duration_sec - unclosed_start

    # Account for last-frame PTS being (duration - 1/fps)
    frame_step = (1.0 / fps) if (fps > 0 and math.isfinite(fps)) else 0.04
    if duration_sec > 0 and math.isfinite(duration_sec):
        effective_span = (
            max(0.001, duration_sec - frame_step) if duration_sec > frame_step * 2 else max(0.001, duration_sec)
        )
        black_ratio = min(1.0, total_black / effective_span)
        freeze_ratio = min(1.0, total_freeze / effective_span)
    else:
        black_ratio = 0.0
        freeze_ratio = 0.0

    return {
        "decode_error": proc.returncode != 0 or len(brng_values) == 0,
        "max_brng_pixels": max_brng,
        "black_duration_sec": round(total_black, 4),
        "black_ratio": round(black_ratio, 4),
        "freeze_duration_sec": round(total_freeze, 4),
        "freeze_ratio": round(freeze_ratio, 4),
    }


_STILL_OR_ANIM_FORMATS = frozenset(
    {
        "gif",
        "webp",
        "webp_pipe",
        "apng",
        "image2",
        "png_pipe",
        "jpeg_pipe",
        "mjpeg",
        "tiff_pipe",
        "bmp_pipe",
        "ppm_pipe",
    }
)
_STILL_OR_ANIM_SUFFIXES = frozenset({".gif", ".webp", ".apng", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"})
_SINGLE_FRAME_BITMAP_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"})
_AUDIO_ONLY_SUFFIXES = frozenset({".wav", ".flac", ".ogg", ".opus", ".mp3", ".m4a", ".aac"})


def _is_still_or_anim_container(info: Dict[str, Any]) -> bool:
    fmt_name = str(info.get("format_name") or "")
    fmt_tokens = {tok.strip().lower() for tok in fmt_name.split(",") if tok.strip()}
    return bool(info.get("video_streams")) and not bool(info.get("audio_streams")) and bool(
        fmt_tokens & _STILL_OR_ANIM_FORMATS
    )


def _verify_stream_decode(path: Path, include_audio: bool, timeout: Optional[float] = None) -> Tuple[bool, List[str]]:
    ffmpeg = _require_tool("ffmpeg")
    ffprobe = _require_tool("ffprobe")
    try:
        _guard_local_media_file(path)
    except Exception as exc:
        return False, [str(exc)]

    safe_arg = _safe_media_arg(path)
    pkt_cmd = [
        ffprobe,
        "-v",
        "error",
        "-protocol_whitelist",
        "file",
        "-count_packets",
        "-show_entries",
        "stream=index,codec_type,nb_read_packets",
        "-of",
        "json",
        "-i",
        safe_arg,
    ]
    try:
        pkt_proc = _run_media_subprocess(pkt_cmd, timeout=timeout)
    except TimeoutError as exc:
        return False, [str(exc)]
    if pkt_proc.returncode != 0:
        errs = [ln.strip() for ln in (pkt_proc.stderr or "").splitlines() if ln.strip()]
        return False, errs or ["ffprobe packet verification failed"]
    try:
        pkt_streams = (json.loads(pkt_proc.stdout or "{}") or {}).get("streams") or []
    except ValueError as exc:
        return False, [f"invalid ffprobe packet JSON: {exc}"]

    allowed_types = {"video", "audio"} if include_audio else {"video"}
    checked = [s for s in pkt_streams if s.get("codec_type") in allowed_types]
    if not checked:
        return False, ["container holds zero decodable media streams"]
    for s in checked:
        raw_pkts = str(s.get("nb_read_packets") or "")
        if not raw_pkts.isdigit() or int(raw_pkts) < 1:
            return False, [f"{s.get('codec_type')} stream #{s.get('index')} decoded 0 packets"]

    map_args = ["-map", "0:v?", "-map", "0:a?"] if include_audio else ["-map", "0:v?", "-an"]
    cmd = (
        [
            ffmpeg,
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-err_detect",
            "explode",
            "-xerror",
            "-protocol_whitelist",
            "file",
            "-i",
            safe_arg,
        ]
        + map_args
        + ["-f", "null", "-"]
    )
    try:
        proc = _run_media_subprocess(cmd, timeout=timeout)
    except TimeoutError as exc:
        return False, [str(exc)]
    err_lines = [ln.strip() for ln in (proc.stderr or "").splitlines() if ln.strip()]
    return (proc.returncode == 0 and len(err_lines) == 0), err_lines


def _verify_visual_decode(path: Path) -> Tuple[bool, List[str]]:
    return _verify_stream_decode(path, include_audio=False)


def _verify_full_decode(path: Path) -> Tuple[bool, List[str]]:
    return _verify_stream_decode(path, include_audio=True)


def _parse_tile_size(tile_size: Optional[str]) -> Optional[Tuple[int, int]]:
    if tile_size is None:
        return None
    m = _TILE_SIZE_RE.match(str(tile_size))
    if not m:
        raise ValueError(f"Invalid --tile-size '{tile_size}'; expected 'WxH' with positive integers (e.g. 32x32).")
    tw, th = int(m.group(1)), int(m.group(2))
    if tw <= 0 or th <= 0:
        raise ValueError(f"Tile dimensions must be > 0 (got {tw}x{th}).")
    return tw, th


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _decode_audio_f32le(
    path: Path,
    sample_rate: Optional[int] = None,
    pre_filter: Optional[str] = None,
    max_duration_sec: float = MAX_GAME_AUDIO_SEC,
    timeout: Optional[float] = None,
) -> Tuple[array.array, int, int, Dict[str, Any]]:
    ffmpeg = _require_tool("ffmpeg")
    _guard_local_media_file(path)
    info = probe_media(path, timeout=timeout)
    if not info["audio_streams"]:
        raise ValueError(f"Input file contains no audio streams: {path}")
    dur = info.get("duration_sec")
    if dur is not None and (not math.isfinite(dur) or dur > max_duration_sec):
        raise ValueError(
            f"Audio duration ({dur:.1f}s) exceeds {max_duration_sec:.0f}s PCM buffer limit for game loop analysis."
        )
    aus = info["audio_streams"][0]
    channels = max(1, min(8, int(aus.get("channels") or 1)))
    sr = int(sample_rate or aus.get("sample_rate") or 48000)
    if sr <= 0 or sr > MAX_GAME_AUDIO_SR:
        raise ValueError(
            f"Audio sample rate {sr} Hz exceeds supported (0, {MAX_GAME_AUDIO_SR}] Hz range for PCM analysis."
        )
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-nostdin",
        "-v",
        "error",
        "-err_detect",
        "explode",
        "-protocol_whitelist",
        "file",
        "-i",
        _safe_media_arg(path),
        "-map",
        "0:a:0",
        "-vn",
        "-sn",
        "-dn",
    ]
    if pre_filter:
        cmd.extend(["-af", pre_filter])
    cmd.extend(
        [
            "-ac",
            str(channels),
            "-ar",
            str(sr),
            "-t",
            f"{max_duration_sec + 0.1:.3f}",
            "-f",
            "f32le",
            "-acodec",
            "pcm_f32le",
            "pipe:1",
        ]
    )
    rc, raw, stderr_b = _run_media_subprocess_bounded_bytes(
        cmd,
        max_bytes=MAX_GAME_AUDIO_BYTES,
        timeout=timeout,
    )
    if rc != 0:
        err_txt = (stderr_b or b"").decode("utf-8", errors="replace")[-600:]
        raise RuntimeError(f"ffmpeg PCM decode failed (exit {rc}):\n{err_txt}")
    frame_bytes = 4 * channels
    usable = len(raw) - (len(raw) % frame_bytes)
    decoded_sec = (usable // frame_bytes) / float(sr)
    if decoded_sec > max_duration_sec + 0.02:
        raise ValueError(
            f"Decoded audio duration ({decoded_sec:.2f}s) exceeds {max_duration_sec:.0f}s PCM buffer limit."
        )
    samples = array.array("f")
    samples.frombytes(memoryview(raw)[:usable])
    if sys.byteorder != "little":
        samples.byteswap()
    return samples, channels, sr, info


def analyze_audio_loop_seam(
    path: Path,
    max_seam_step: float = 0.15,
    max_seam_impulse: float = 0.05,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    _require_finite_param("max_seam_step", max_seam_step)
    _require_finite_param("max_seam_impulse", max_seam_impulse)
    if max_seam_step < 0.0:
        raise ValueError(f"Parameter 'max_seam_step' must be >= 0 (got {max_seam_step}).")
    if max_seam_impulse < 0.0:
        raise ValueError(f"Parameter 'max_seam_impulse' must be >= 0 (got {max_seam_impulse}).")
    samples, channels, sr, _ = _decode_audio_f32le(path, sample_rate=None, timeout=timeout)
    n_frames = len(samples) // channels
    if n_frames < 4:
        return {
            "loop_checked": True,
            "seamless": False,
            "sample_rate": sr,
            "channels": channels,
            "n_frames": n_frames,
            "seam_step": None,
            "seam_impulse": None,
            "max_seam_step": max_seam_step,
            "max_seam_impulse": max_seam_impulse,
            "reason": "Audio stream has fewer than 4 frames for loop seam analysis.",
        }

    worst_step_norm = 0.0
    worst_imp_norm = 0.0
    peak_overall = 0.0
    for c in range(channels):
        ch_slice = samples[c::channels]
        ch_peak = 0.0
        for v in ch_slice:
            if not math.isfinite(v):
                return {
                    "loop_checked": True,
                    "seamless": False,
                    "sample_rate": sr,
                    "channels": channels,
                    "n_frames": n_frames,
                    "peak_amp": None,
                    "seam_step": None,
                    "seam_impulse": None,
                    "max_seam_step": max_seam_step,
                    "max_seam_impulse": max_seam_impulse,
                    "reason": "Audio stream contains non-finite (NaN/Inf) PCM samples.",
                }
            av = abs(v)
            if av > ch_peak:
                ch_peak = av
        if ch_peak > peak_overall:
            peak_overall = ch_peak
        scale = ch_peak if ch_peak >= 1e-4 else 1.0
        s0 = ch_slice[0]
        s1 = ch_slice[1]
        s_last = ch_slice[-1]
        s_prev = ch_slice[-2]
        step = abs(s0 - s_last) / scale
        d_end = s_last - s_prev
        d_start = s1 - s0
        d_wrap = s0 - s_last
        impulse = max(abs(d_wrap - d_end), abs(d_start - d_wrap)) / scale
        if step > worst_step_norm:
            worst_step_norm = step
        if impulse > worst_imp_norm:
            worst_imp_norm = impulse

    if not (
        math.isfinite(peak_overall)
        and math.isfinite(worst_step_norm)
        and math.isfinite(worst_imp_norm)
    ):
        return {
            "loop_checked": True,
            "seamless": False,
            "sample_rate": sr,
            "channels": channels,
            "n_frames": n_frames,
            "peak_amp": None,
            "seam_step": None,
            "seam_impulse": None,
            "max_seam_step": max_seam_step,
            "max_seam_impulse": max_seam_impulse,
            "reason": "Loop seam calculation produced non-finite amplitude or discontinuity metrics.",
        }

    seamless = bool(worst_step_norm <= max_seam_step and worst_imp_norm <= max_seam_impulse)
    return {
        "loop_checked": True,
        "seamless": seamless,
        "sample_rate": sr,
        "channels": channels,
        "n_frames": n_frames,
        "peak_amp": round(peak_overall, 6),
        "seam_step": round(worst_step_norm, 6),
        "seam_impulse": round(worst_imp_norm, 6),
        "max_seam_step": max_seam_step,
        "max_seam_impulse": max_seam_impulse,
    }


def _find_zero_crossing_loop_bounds(
    samples: array.array,
    channels: int,
    sample_rate: int,
    max_window_ms: float = 50.0,
) -> Optional[Tuple[int, int]]:
    n_frames = len(samples) // channels
    if n_frames < 32:
        return None
    win = min(n_frames // 4, max(4, int(round(sample_rate * max_window_ms / 1000.0))))
    if win < 4:
        return None

    tail_start = max(win + 2, n_frames - win)
    inspected_indices = list(range(0, win + 2)) + list(range(max(0, tail_start - 2), n_frames))
    peak = 0.0
    for idx in inspected_indices:
        base = idx * channels
        for c in range(channels):
            val = samples[base + c]
            if not math.isfinite(val):
                return None
            av = abs(val)
            if av > peak:
                peak = av
    scale = peak if peak >= 1e-4 else 1.0

    def _frame_mono(idx: int) -> float:
        base = idx * channels
        return sum(samples[base + c] for c in range(channels)) / channels

    head_set: set[int] = set()
    tail_set: set[int] = set()
    # Collect rising zero crossings per channel AND from mono sum so anti-phase stereo still yields candidates.
    probes: List[Callable[[int], float]] = [
        (lambda idx, ch=c: samples[idx * channels + ch]) for c in range(channels)
    ]
    if channels > 1:
        probes.append(_frame_mono)

    for probe_fn in probes:
        prev_val = probe_fn(0)
        if abs(prev_val) <= 1e-4 and probe_fn(1) > prev_val:
            head_set.add(0)
        for i in range(1, win):
            cur_val = probe_fn(i)
            if prev_val <= 0.0 < cur_val:
                head_set.add(i)
            prev_val = cur_val

        t_prev = probe_fn(tail_start - 1)
        for j in range(tail_start, n_frames):
            t_cur = probe_fn(j)
            # Exclusive end boundary `j` means kept final sample is `j - 1` (rising through zero into `j`).
            if t_prev <= 0.0 and (t_cur > 0.0 or (j == n_frames - 1 and abs(t_cur) <= 1e-4)):
                tail_set.add(j)
            t_prev = t_cur

    head_crossings = sorted(head_set)
    tail_crossings = sorted(tail_set)
    if not head_crossings or not tail_crossings:
        return None

    best_bounds: Optional[Tuple[int, int]] = None
    best_cost = float("inf")
    for s in head_crossings[:48]:
        for e in tail_crossings[-48:]:
            if e - s < 16:
                continue
            step_max = 0.0
            imp_max = 0.0
            for c in range(channels):
                s0 = samples[s * channels + c]
                s1 = samples[(s + 1) * channels + c]
                s_last = samples[(e - 1) * channels + c]
                s_prev = samples[(e - 2) * channels + c]
                step = abs(s0 - s_last) / scale
                d_end = s_last - s_prev
                d_start = s1 - s0
                d_wrap = s0 - s_last
                imp = max(abs(d_wrap - d_end), abs(d_start - d_wrap)) / scale
                if step > step_max:
                    step_max = step
                if imp > imp_max:
                    imp_max = imp
            if not (math.isfinite(step_max) and math.isfinite(imp_max)):
                continue
            trim_penalty = 1e-4 * ((s + (n_frames - e)) / max(1, win))
            cost = imp_max + 0.25 * step_max + trim_penalty
            if cost < best_cost:
                best_cost = cost
                best_bounds = (s, e)
    return best_bounds


def _measure_peak_db_after_filter(
    path: Path,
    filter_expr: Optional[str],
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    ffmpeg = _require_tool("ffmpeg")
    _guard_local_media_file(path)
    af = f"{filter_expr},astats=reset=0" if filter_expr else "astats=reset=0"
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-nostdin",
        "-protocol_whitelist",
        "file",
        "-i",
        _safe_media_arg(path),
        "-map",
        "0:a:0",
        "-vn",
        "-sn",
        "-dn",
        "-af",
        af,
        "-f",
        "null",
        "-",
    ]
    proc = _run_media_subprocess(cmd, timeout=timeout)
    log = (proc.stderr or "") + "\n" + (proc.stdout or "")
    if proc.returncode != 0:
        raise RuntimeError(f"Pre-normalization peak measurement failed (exit {proc.returncode}):\n{log[-600:]}")
    overall_blocks = re.split(r"\[Parsed_astats[^\]]*\]\s*Overall", log)
    astats_block = overall_blocks[-1] if len(overall_blocks) > 1 else ""
    m_peak = re.search(r"Peak level dB:\s*([+-]?\d+(?:\.\d+)?|-inf|inf)", astats_block)
    m_rms = re.search(r"RMS level dB:\s*([+-]?\d+(?:\.\d+)?|-inf|inf)", astats_block)
    m_dc = re.search(r"DC offset:\s*([+-]?\d+(?:\.\d+)?)", astats_block)
    return {
        "peak_level_db": _safe_float(m_peak.group(1)) if m_peak else None,
        "rms_level_db": _safe_float(m_rms.group(1)) if m_rms else None,
        "dc_offset": _safe_float(m_dc.group(1)) if m_dc else None,
    }


_FFMPEG_VERSION_CACHE: Dict[str, Optional[Tuple[int, int]]] = {}
_FFMPEG_VERSION_RE = re.compile(r"ffmpeg\s+version\s+(?:n|\d+:)?(\d+)\.(\d+)", re.IGNORECASE)


def _parse_ffmpeg_version(version_output: str) -> Optional[Tuple[int, int]]:
    for line in (version_output or "").splitlines()[:5]:
        m = _FFMPEG_VERSION_RE.search(line)
        if m:
            return (int(m.group(1)), int(m.group(2)))
    return None


def _ffmpeg_supports_fps_mode(ffmpeg_bin: str, timeout: Optional[float] = None) -> bool:
    """Returns True when `ffmpeg` is >= 5.1 (which introduced `-fps_mode`), False on older builds."""
    if timeout is not None and timeout <= 0:
        raise ValueError(f"Parameter 'timeout' must be > 0 (got {timeout}).")
    if ffmpeg_bin in _FFMPEG_VERSION_CACHE:
        cached = _FFMPEG_VERSION_CACHE[ffmpeg_bin]
        return cached is None or cached >= (5, 1)
    ver: Optional[Tuple[int, int]] = None
    probe_ok = False
    probe_timeout = min(10.0, timeout) if timeout is not None else 10.0
    try:
        proc = _run_media_subprocess([ffmpeg_bin, "-version"], timeout=probe_timeout)
        if proc.returncode == 0:
            probe_ok = True
            combined = f"{proc.stdout or ''}\n{proc.stderr or ''}"
            ver = _parse_ffmpeg_version(combined)
        else:
            sys.stderr.write(
                f"[media_qc] ffmpeg -version probe exited {proc.returncode}; falling back to runtime -fps_mode probe.\n"
            )
    except (OSError, TimeoutError, ValueError) as exc:
        sys.stderr.write(
            f"[media_qc] ffmpeg -version probe failed ({type(exc).__name__}): {exc}; falling back to runtime -fps_mode probe.\n"
        )
    if probe_ok and ver is not None:
        _FFMPEG_VERSION_CACHE[ffmpeg_bin] = ver
    return ver is None or ver >= (5, 1)


def _decode_image_rgba_frames(
    path: Path,
    width: int,
    height: int,
    *,
    max_frames: int = 1,
    timeout: Optional[float] = None,
) -> bytes:
    if width <= 0 or height <= 0:
        raise ValueError(f"Invalid image dimensions {width}x{height}.")
    if max_frames < 1:
        raise ValueError(f"Parameter 'max_frames' must be >= 1 (got {max_frames}).")
    frame_pixels = width * height
    if frame_pixels > MAX_GAME_VISUAL_PIXELS:
        raise ValueError(
            f"Image pixel count ({width}x{height}={frame_pixels}) exceeds {MAX_GAME_VISUAL_PIXELS} RGBA buffer limit."
        )
    eff_max_frames = min(max_frames, max(1, MAX_GAME_VISUAL_PIXELS // frame_pixels))
    frame_bytes = frame_pixels * 4
    max_bytes = eff_max_frames * frame_bytes
    ffmpeg = _require_tool("ffmpeg")
    _guard_local_media_file(path)

    def _build_cmd(use_fps_mode: bool) -> List[str]:
        sync_flag = ["-fps_mode", "passthrough"] if use_fps_mode else ["-vsync", "passthrough"]
        return [
            ffmpeg,
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-err_detect",
            "explode",
            "-xerror",
            "-protocol_whitelist",
            "file",
            "-i",
            _safe_media_arg(path),
            "-map",
            "0:v:0",
            "-an",
            "-sn",
            "-dn",
            *sync_flag,
            "-frames:v",
            str(eff_max_frames),
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgba",
            "pipe:1",
        ]

    use_fps = _ffmpeg_supports_fps_mode(ffmpeg, timeout=timeout)
    rc, raw, stderr_b = _run_media_subprocess_bounded_bytes(_build_cmd(use_fps), max_bytes=max_bytes, timeout=timeout)
    if rc != 0 and use_fps:
        err_probe = (stderr_b or b"").decode("utf-8", errors="replace").lower()
        if "fps_mode" in err_probe and ("unrecognized" in err_probe or "unknown" in err_probe or "option" in err_probe):
            _FFMPEG_VERSION_CACHE[ffmpeg] = (5, 0)
            rc, raw, stderr_b = _run_media_subprocess_bounded_bytes(
                _build_cmd(False), max_bytes=max_bytes, timeout=timeout
            )
    if rc != 0:
        err_txt = (stderr_b or b"").decode("utf-8", errors="replace")[-600:]
        raise RuntimeError(f"ffmpeg RGBA decode failed (exit {rc}):\n{err_txt}")
    if len(raw) == 0 or (len(raw) % frame_bytes) != 0:
        raise RuntimeError(
            f"Unexpected RGBA buffer size for {width}x{height}: got {len(raw)} bytes (frame size {frame_bytes})."
        )
    if max_frames == 1 and len(raw) != frame_bytes:
        raise RuntimeError(f"Unexpected RGBA buffer size for {width}x{height}: got {len(raw)} bytes, expected {frame_bytes}.")
    return raw


def _decode_image_rgba(
    path: Path,
    width: int,
    height: int,
    timeout: Optional[float] = None,
) -> bytes:
    return _decode_image_rgba_frames(path, width, height, max_frames=1, timeout=timeout)


def _analyze_game_visual(
    path: Path,
    width: int,
    height: int,
    *,
    pixel_art: bool = False,
    sprite_atlas: bool = False,
    tile_dims: Optional[Tuple[int, int]] = None,
    require_pot: bool = False,
    check_alpha_bleed: bool = False,
    allow_edge_touch: bool = False,
    all_frames: bool = False,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    pot_ok = _is_power_of_two(width) and _is_power_of_two(height)
    tile_aligned = True if tile_dims is None else (width % tile_dims[0] == 0 and height % tile_dims[1] == 0)

    do_bleed = bool(check_alpha_bleed or (sprite_atlas and not pixel_art))
    need_rgba = bool(pixel_art or do_bleed or (tile_dims is not None and not allow_edge_touch))

    semi_alpha_count = 0
    semi_alpha_ratio = 0.0
    alpha_bleed_count = 0
    edge_touch_count = 0
    total_pixels = width * height
    n_frames = 1

    if need_rgba:
        frame_budget = max(1, MAX_GAME_VISUAL_PIXELS // max(1, total_pixels)) if all_frames else 1
        raw = _decode_image_rgba_frames(path, width, height, max_frames=frame_budget, timeout=timeout)
        frame_bytes = total_pixels * 4
        n_frames = max(1, len(raw) // frame_bytes)
        mv = memoryview(raw)
        alpha_plane = bytes(mv[3::4])
        if pixel_art:
            semi_alpha_count = len(alpha_plane) - alpha_plane.count(0) - alpha_plane.count(255)
            semi_alpha_ratio = semi_alpha_count / max(1, len(alpha_plane))

        if do_bleed:
            eff_budget = DEFAULT_SUBPROCESS_TIMEOUT if timeout is None else float(timeout)
            deadline = time.monotonic() + max(5.0, eff_budget)
            for f_idx in range(n_frames):
                a_start = f_idx * total_pixels
                a_frame = alpha_plane[a_start : a_start + total_pixels]
                trans_count = a_frame.count(0)
                if trans_count == 0 or trans_count == total_pixels:
                    continue
                f_off = f_idx * frame_bytes
                for y in range(height):
                    if (y & 63) == 0 and time.monotonic() > deadline:
                        raise TimeoutError("Alpha bleed inspection exceeded wall-clock time budget.")
                    row_off = y * width
                    for x in range(width):
                        idx = row_off + x
                        if a_frame[idx] != 0:
                            continue
                        idx4 = f_off + idx * 4
                        r0, g0, b0 = raw[idx4], raw[idx4 + 1], raw[idx4 + 2]
                        bleed_hit = False
                        if x > 0 and a_frame[idx - 1] >= 128:
                            n4 = idx4 - 4
                            if max(abs(r0 - raw[n4]), abs(g0 - raw[n4 + 1]), abs(b0 - raw[n4 + 2])) > 48:
                                bleed_hit = True
                        if not bleed_hit and x + 1 < width and a_frame[idx + 1] >= 128:
                            n4 = idx4 + 4
                            if max(abs(r0 - raw[n4]), abs(g0 - raw[n4 + 1]), abs(b0 - raw[n4 + 2])) > 48:
                                bleed_hit = True
                        if not bleed_hit and y > 0 and a_frame[idx - width] >= 128:
                            n4 = idx4 - width * 4
                            if max(abs(r0 - raw[n4]), abs(g0 - raw[n4 + 1]), abs(b0 - raw[n4 + 2])) > 48:
                                bleed_hit = True
                        if not bleed_hit and y + 1 < height and a_frame[idx + width] >= 128:
                            n4 = idx4 + width * 4
                            if max(abs(r0 - raw[n4]), abs(g0 - raw[n4 + 1]), abs(b0 - raw[n4 + 2])) > 48:
                                bleed_hit = True
                        if bleed_hit:
                            alpha_bleed_count += 1

        if tile_dims is not None and not allow_edge_touch:
            tw, th = tile_dims
            for f_idx in range(n_frames):
                f_px_off = f_idx * total_pixels
                if tw >= 2 and width > tw:
                    for m in range(1, width // tw):
                        seam_l = m * tw - 1
                        seam_r = m * tw
                        if seam_r >= width:
                            continue
                        for y in range(height):
                            base = f_px_off + y * width
                            if alpha_plane[base + seam_l] >= 128 or alpha_plane[base + seam_r] >= 128:
                                edge_touch_count += 1
                if th >= 2 and height > th:
                    for n in range(1, height // th):
                        seam_t = n * th - 1
                        seam_b = n * th
                        if seam_b >= height:
                            continue
                        top_base = f_px_off + seam_t * width
                        bot_base = f_px_off + seam_b * width
                        for x in range(width):
                            if alpha_plane[top_base + x] >= 128 or alpha_plane[bot_base + x] >= 128:
                                edge_touch_count += 1

    return {
        "width": width,
        "height": height,
        "frames_checked": n_frames,
        "is_pot": pot_ok,
        "require_pot": require_pot,
        "tile_size": f"{tile_dims[0]}x{tile_dims[1]}" if tile_dims else None,
        "tile_aligned": tile_aligned,
        "pixel_art": pixel_art,
        "semi_alpha_pixels": semi_alpha_count,
        "semi_alpha_ratio": round(semi_alpha_ratio, 6),
        "alpha_bleed_pixels": alpha_bleed_count,
        "edge_touch_pixels": edge_touch_count,
    }


def _check_integer_scale_blocks(cand_rgba: bytes | bytearray | memoryview, rw: int, rh: int, k: int) -> int:
    if k <= 1:
        return 0
    cw = rw * k
    stride = cw * 4
    cand_bytes = cand_rgba if isinstance(cand_rgba, (bytes, bytearray)) else bytes(cand_rgba)
    non_uniform = 0
    for by in range(rh):
        y0 = by * k
        for bx in range(rw):
            x0 = bx * k
            first_off = y0 * stride + x0 * 4
            ref_px = cand_bytes[first_off : first_off + 4]
            expected_row = ref_px * k
            uniform = True
            for dy in range(k):
                row_off = (y0 + dy) * stride + x0 * 4
                if cand_bytes[row_off : row_off + k * 4] != expected_row:
                    uniform = False
                    break
            if not uniform:
                non_uniform += 1
    return non_uniform


def check_media(
    path: Path,
    target_lufs: Optional[float] = None,
    lufs_tolerance: float = 1.5,
    max_true_peak: float = -1.0,
    max_dc_offset: float = 0.02,
    allow_silent: bool = False,
    allow_high_chroma: bool = False,
    allow_static: bool = False,
    game_sfx: bool = False,
    check_loop: bool = False,
    max_seam_step: float = 0.15,
    max_seam_impulse: float = 0.05,
    pixel_art: bool = False,
    sprite_atlas: bool = False,
    tile_size: Optional[str] = None,
    require_pot: bool = False,
    check_alpha_bleed: bool = False,
    allow_edge_touch: bool = False,
) -> Dict[str, Any]:
    _require_finite_param("target_lufs", target_lufs)
    _require_finite_param("lufs_tolerance", lufs_tolerance)
    _require_finite_param("max_true_peak", max_true_peak)
    _require_finite_param("max_dc_offset", max_dc_offset)
    _require_finite_param("max_seam_step", max_seam_step)
    _require_finite_param("max_seam_impulse", max_seam_impulse)
    if lufs_tolerance < 0.0:
        raise ValueError(f"Parameter 'lufs_tolerance' must be >= 0 (got {lufs_tolerance}).")
    if max_true_peak > 0.0:
        raise ValueError(f"Parameter 'max_true_peak' must be <= 0.0 dBTP (got {max_true_peak}).")
    if max_dc_offset < 0.0:
        raise ValueError(f"Parameter 'max_dc_offset' must be >= 0 (got {max_dc_offset}).")
    if max_seam_step < 0.0:
        raise ValueError(f"Parameter 'max_seam_step' must be >= 0 (got {max_seam_step}).")
    if max_seam_impulse < 0.0:
        raise ValueError(f"Parameter 'max_seam_impulse' must be >= 0 (got {max_seam_impulse}).")
    parsed_tile_dims = _parse_tile_size(tile_size)
    run_game_visual = bool(pixel_art or sprite_atlas or parsed_tile_dims is not None or require_pot or check_alpha_bleed)

    findings: List[Finding] = []
    try:
        info = probe_media(path)
    except Exception as exc:
        if isinstance(exc, RuntimeError) and "Required binary" in str(exc):
            raise
        findings.append(
            Finding(
                "MEDIA-1",
                "high",
                f"Stream or container integrity failure: {exc}",
                "Run 'media_qc.py salvage <input> <output>' or verify container muxing and trailer completion.",
            )
        )
        return {
            "path": str(path),
            "passed": False,
            "findings": [f.to_dict() for f in findings],
            "probe": None,
            "audio_metrics": None,
            "video_metrics": None,
        }

    v_streams = info["video_streams"]
    a_streams = info["audio_streams"]
    duration = info["duration_sec"] if info["duration_sec"] is not None else 0.0
    is_still_or_anim_image = _is_still_or_anim_container(info)

    if not v_streams and not a_streams:
        findings.append(
            Finding(
                "MEDIA-1",
                "high",
                "Container holds zero video or audio streams.",
                "Ensure at least one valid audio or video stream is mapped (-map) into the output.",
            )
        )
    if check_loop and not a_streams:
        findings.append(
            Finding(
                "GAME-1",
                "high",
                "Loop seam check (--check-loop) requested, but input contains no audio stream.",
                "Provide a file with an audio stream or remove --check-loop.",
            )
        )
    if run_game_visual and not v_streams:
        findings.append(
            Finding(
                "GAME-2" if pixel_art else "GAME-3",
                "high",
                "Visual game-asset check requested, but input contains no image or video stream.",
                "Provide a visual image/video asset or remove visual game flags.",
            )
        )
    if (not math.isfinite(duration) or duration <= 0.0) and not is_still_or_anim_image:
        findings.append(
            Finding(
                "MEDIA-1",
                "high",
                f"Media duration is non-positive ({duration}s).",
                "Check input generator duration and ensure encoding completed without truncation.",
            )
        )

    # MEDIA-2: Audio/Video sync drift & even geometry on yuv420p
    av_drift = info.get("av_drift_sec")
    if av_drift is not None and av_drift > 0.10:
        findings.append(
            Finding(
                "MEDIA-2",
                "high",
                f"Audio-video duration drift is {av_drift:.3f}s (exceeds 0.100s limit).",
                "Normalize VFR clips to CFR (-fps_mode cfr) and match stream durations (-shortest or apad/atrim).",
            )
        )

    for vs in v_streams:
        w = int(vs.get("width") or 0)
        h = int(vs.get("height") or 0)
        pix_fmt = vs.get("pix_fmt") or ""
        codec = vs.get("codec_name") or ""
        if w <= 0 or h <= 0:
            findings.append(
                Finding(
                    "MEDIA-1",
                    "high",
                    f"Video stream #{vs.get('index')} has invalid non-positive dimensions ({w}x{h}).",
                    "Re-mux or re-encode the visual stream with positive width and height.",
                )
            )
            continue
        if "420" in pix_fmt and codec not in ("mjpeg", "webp") and (w % 2 != 0 or h % 2 != 0):
            findings.append(
                Finding(
                    "MEDIA-2",
                    "high",
                    f"Video stream #{vs.get('index')} has odd dimensions ({w}x{h}) with 4:2:0 chroma ({pix_fmt}).",
                    "Enforce even dimensions via scale='trunc(iw/2)*2:trunc(ih/2)*2'.",
                )
            )
        # MEDIA-6: H.264 MP4 web/player compatibility
        if codec == "h264" and path.suffix.lower() in (".mp4", ".m4v", ".mov") and not allow_high_chroma:
            if pix_fmt not in ("yuv420p", "yuvj420p", "nv12"):
                findings.append(
                    Finding(
                        "MEDIA-6",
                        "high",
                        f"H.264 stream uses '{pix_fmt}' instead of web-safe 'yuv420p' in {path.suffix} container.",
                        "Add '-pix_fmt yuv420p -movflags +faststart' for universal browser and mobile playback.",
                    )
                )

    audio_metrics: Optional[Dict[str, Any]] = None
    if a_streams:
        audio_metrics = _analyze_audio_signal(path)
        lufs = audio_metrics.get("integrated_lufs")
        tp = audio_metrics.get("true_peak_dbtp")
        dc = audio_metrics.get("dc_offset")
        if audio_metrics.get("decode_error") or tp is None or dc is None:
            findings.append(
                Finding(
                    "MEDIA-1",
                    "high",
                    "Audio stream failed to decode cleanly or produced zero measurable samples in ffmpeg.",
                    "Re-mux or re-encode the audio stream from a valid source.",
                )
            )

        peak_db = audio_metrics.get("peak_level_db")
        is_short_sfx_clip = game_sfx and duration < 0.5
        if is_short_sfx_clip and (lufs is None or not math.isfinite(lufs) or lufs <= -70.0):
            is_actually_silent = peak_db is None or not math.isfinite(peak_db) or peak_db <= -70.0
            if not allow_silent and is_actually_silent:
                findings.append(
                    Finding(
                        "MEDIA-3",
                        "high",
                        f"Short game SFX stream is silent or near-silent (Peak Level: {peak_db} dBFS <= -70.0 dBFS).",
                        "Verify SFX synthesis gain or pass --allow-silent when a mute track is intentional.",
                    )
                )
        elif not allow_silent and (lufs is None or lufs <= -70.0):
            findings.append(
                Finding(
                    "MEDIA-3",
                    "high",
                    f"Audio stream is silent or near-silent (Integrated Loudness: {lufs} LUFS <= -70.0 LUFS).",
                    "Verify audio synthesis gain or pass --allow-silent when a mute track is intentional.",
                )
            )
        if tp is not None and tp > max_true_peak:
            findings.append(
                Finding(
                    "MEDIA-3",
                    "high",
                    f"Audio True Peak is {tp:.2f} dBTP, exceeding maximum ceiling {max_true_peak:.2f} dBTP.",
                    "Run 'media_qc.py master-audio' with --target-tp -1.0 or apply a true-peak limiter.",
                )
            )
        if target_lufs is not None and lufs is not None and math.isfinite(lufs) and not is_short_sfx_clip:
            delta = abs(lufs - target_lufs)
            if delta > lufs_tolerance:
                findings.append(
                    Finding(
                        "MEDIA-4",
                        "high",
                        f"Integrated loudness is {lufs:.2f} LUFS (target {target_lufs:.2f} +/- {lufs_tolerance:.2f} LUFS; delta {delta:.2f} LU).",
                        "Master audio using two-pass EBU R128 normalization ('media_qc.py master-audio').",
                    )
                )
        if dc is not None and abs(dc) > max_dc_offset:
            findings.append(
                Finding(
                    "MEDIA-5",
                    "medium",
                    f"Audio DC offset is {dc:.4f} (exceeds +/- {max_dc_offset:.4f}).",
                    "Subtract mean sample offset (signal -= np.mean(signal)) or apply 'highpass=f=20'.",
                )
            )

    video_metrics: Optional[Dict[str, Any]] = None
    if v_streams and duration > 0.2:
        fps = v_streams[0].get("fps") or 25.0
        video_metrics = _analyze_video_signal(path, duration, fps)
        if video_metrics.get("decode_error"):
            findings.append(
                Finding(
                    "MEDIA-1",
                    "high",
                    "Video stream failed to decode cleanly in ffmpeg.",
                    "Run 'media_qc.py salvage' or re-encode the video stream and verify container integrity.",
                )
            )
        if video_metrics["black_ratio"] >= 0.90:
            findings.append(
                Finding(
                    "MEDIA-7",
                    "high",
                    f"Video stream is {video_metrics['black_ratio'] * 100:.1f}% black frames ({video_metrics['black_duration_sec']}s / {duration:.2f}s).",
                    "Check rendering light/color values, frame buffer piping, or overlay alpha channels.",
                )
            )
        if not allow_static and duration > 1.0 and video_metrics["freeze_ratio"] >= 0.95:
            findings.append(
                Finding(
                    "MEDIA-7",
                    "medium",
                    f"Video stream is {video_metrics['freeze_ratio'] * 100:.1f}% frozen/static frames over {duration:.2f}s.",
                    "Verify frame index time progression (t = f / fps) or pass --allow-static for static slates.",
                )
            )
    elif v_streams:
        decode_ok, decode_errs = _verify_visual_decode(path)
        video_metrics = {
            "decode_error": not decode_ok,
            "decode_error_count": len(decode_errs),
            "max_brng_pixels": 0,
            "black_duration_sec": 0.0,
            "black_ratio": 0.0,
            "freeze_duration_sec": 0.0,
            "freeze_ratio": 0.0,
        }
        if not decode_ok:
            detail = decode_errs[0] if decode_errs else "corrupt or truncated frame data"
            findings.append(
                Finding(
                    "MEDIA-1",
                    "high",
                    f"Still image or short visual stream failed full frame decode: {detail}",
                    "Re-export or run 'media_qc.py salvage <input> <output> --allow-reencode' to recover intact scanlines.",
                )
            )

    loop_metrics: Optional[Dict[str, Any]] = None
    if a_streams and check_loop:
        if audio_metrics and audio_metrics.get("decode_error"):
            loop_metrics = {
                "loop_checked": False,
                "seamless": False,
                "seam_step": None,
                "seam_impulse": None,
                "max_seam_step": max_seam_step,
                "max_seam_impulse": max_seam_impulse,
                "reason": "Skipped loop seam analysis because audio decoding failed.",
            }
            findings.append(
                Finding(
                    "GAME-1",
                    "high",
                    "Audio loop seam check skipped due to corrupted or undecodable audio stream.",
                    "Salvage or re-encode the audio stream cleanly before verifying loop seams.",
                )
            )
        else:
            try:
                loop_metrics = analyze_audio_loop_seam(
                    path, max_seam_step=max_seam_step, max_seam_impulse=max_seam_impulse
                )
                if not loop_metrics.get("seamless"):
                    reason_note = f" ({loop_metrics['reason']})" if loop_metrics.get("reason") else ""
                    findings.append(
                        Finding(
                            "GAME-1",
                            "high",
                            f"Audio loop seam discontinuity detected "
                            f"(step={loop_metrics.get('seam_step')} [max {max_seam_step}], "
                            f"impulse={loop_metrics.get('seam_impulse')} [max {max_seam_impulse}]){reason_note}.",
                            "Trim endpoints cleanly on matched rising zero-crossings via 'media_qc.py master-audio --trim-loop'.",
                        )
                    )
            except (ValueError, RuntimeError, TimeoutError) as exc:
                loop_metrics = {
                    "loop_checked": False,
                    "seamless": False,
                    "seam_step": None,
                    "seam_impulse": None,
                    "max_seam_step": max_seam_step,
                    "max_seam_impulse": max_seam_impulse,
                    "reason": str(exc),
                }
                findings.append(
                    Finding(
                        "GAME-1",
                        "high",
                        f"Audio loop seam analysis failed: {exc}",
                        "Verify audio stream integrity, sample rate (<= 384 kHz), and duration (<= 300s) before loop checking.",
                    )
                )

    game_visual_metrics: Optional[Dict[str, Any]] = None
    if v_streams and run_game_visual and not (video_metrics and video_metrics.get("decode_error")):
        try:
            vw, vh = _effective_dimensions(v_streams[0])
        except ValueError as exc:
            findings.append(
                Finding(
                    "MEDIA-1",
                    "high",
                    f"Video stream #0 has invalid visual dimensions for game analysis: {exc}",
                    "Re-encode or repair container stream dimensions.",
                )
            )
            vw, vh = 0, 0
        if vw > 0 and vh > 0:
            try:
                game_visual_metrics = _analyze_game_visual(
                    path,
                    vw,
                    vh,
                    pixel_art=pixel_art,
                    sprite_atlas=sprite_atlas,
                    tile_dims=parsed_tile_dims,
                    require_pot=require_pot,
                    check_alpha_bleed=check_alpha_bleed,
                    allow_edge_touch=allow_edge_touch,
                    all_frames=is_still_or_anim_image,
                )
            except (ValueError, RuntimeError, TimeoutError) as exc:
                findings.append(
                    Finding(
                        "GAME-2" if pixel_art else "GAME-3",
                        "high",
                        f"Game visual inspection failed on {vw}x{vh} asset: {exc}",
                        "Ensure visual frames are valid and within supported pixel/time inspection bounds.",
                    )
                )
            if game_visual_metrics is not None:
                if pixel_art and game_visual_metrics["semi_alpha_ratio"] > 0.01:
                    findings.append(
                        Finding(
                            "GAME-2",
                            "high",
                            f"Pixel-art surface has {game_visual_metrics['semi_alpha_pixels']} semi-transparent fringe pixels "
                            f"({game_visual_metrics['semi_alpha_ratio'] * 100:.2f}% > 1.00%), indicating bilinear/lanczos blur.",
                            "Re-scale pixel art strictly with integer factors and '-sws_flags neighbor' (flags=neighbor).",
                        )
                    )
                if require_pot and not game_visual_metrics["is_pot"]:
                    findings.append(
                        Finding(
                            "GAME-3",
                            "high",
                            f"Texture/atlas dimensions {vw}x{vh} are not Power-of-Two (--require-pot).",
                            "Pack sprites onto a power-of-two canvas (e.g. 256x256, 512x512, 1024x512).",
                        )
                    )
                if parsed_tile_dims is not None and not game_visual_metrics["tile_aligned"]:
                    tw, th = parsed_tile_dims
                    findings.append(
                        Finding(
                            "GAME-3",
                            "high",
                            f"Atlas dimensions {vw}x{vh} are not divisible by tile size {tw}x{th}.",
                            f"Adjust sprite-atlas canvas dimensions to exact multiples of {tw}x{th}.",
                        )
                    )
                if game_visual_metrics["alpha_bleed_pixels"] > 0:
                    findings.append(
                        Finding(
                            "GAME-3",
                            "medium",
                            f"Detected {game_visual_metrics['alpha_bleed_pixels']} transparent edge pixels with un-dilated RGB halo risk (> 48 delta).",
                            "Dilate adjacent sprite RGB colors into transparent neighbor texels (alpha bleeding fix) before atlas export.",
                        )
                    )
                if game_visual_metrics["edge_touch_pixels"] > 0:
                    findings.append(
                        Finding(
                            "GAME-3",
                            "medium",
                            f"Detected {game_visual_metrics['edge_touch_pixels']} opaque pixels touching internal tile grid borders without gutter padding.",
                            "Add >= 1px transparent padding/extrusion around tiles or pass --allow-edge-touch for seamless full-bleed tilesets.",
                        )
                    )

    result: Dict[str, Any] = {
        "path": str(path),
        "passed": len(findings) == 0,
        "findings": [f.to_dict() for f in findings],
        "probe": info,
        "audio_metrics": audio_metrics,
        "video_metrics": video_metrics,
    }
    if loop_metrics is not None:
        result["loop_metrics"] = loop_metrics
    if game_visual_metrics is not None:
        result["game_visual_metrics"] = game_visual_metrics
    return result


def _stream_sar(vs: Dict[str, Any]) -> float:
    raw = vs.get("sample_aspect_ratio")
    if raw is None or str(raw).strip() == "" or str(raw).strip().lower() in ("0:1", "0/1", "0:0", "0/0", "n/a"):
        return 1.0
    sar = _parse_fraction(str(raw).strip().replace(":", "/"))
    if sar is None or sar <= 0.0 or not math.isfinite(sar):
        raise ValueError(f"Invalid or non-positive sample_aspect_ratio: {raw!r}")
    return sar


def _effective_dimensions(vs: Dict[str, Any]) -> Tuple[int, int]:
    w = int(vs.get("width") or 0)
    h = int(vs.get("height") or 0)
    if w <= 0 or h <= 0:
        raise ValueError(f"Video stream has invalid non-positive dimensions: {w}x{h}")
    rot = int(vs.get("rotation") or 0)
    if abs(rot) % 180 == 90:
        return h, w
    return w, h


def _effective_aspect_ratio(vs: Dict[str, Any]) -> float:
    ew, eh = _effective_dimensions(vs)
    return (float(ew) / float(eh)) * _stream_sar(vs)


def _collect_salvage_errors(proc_stderr: Optional[str], val_errs: List[str]) -> List[str]:
    ff_lines = [ln.strip() for ln in (proc_stderr or "").splitlines() if ln.strip()]
    combined: List[str] = []
    if any("moov atom not found" in ln.lower() for ln in ff_lines):
        combined.append(
            "missing MP4/MOV 'moov' atom (unfinalized recording with no index table; requires a same-camera reference file)"
        )
    for ln in ff_lines[-4:]:
        if ln not in combined:
            combined.append(ln)
    for ve in val_errs:
        if ve not in combined:
            combined.append(ve)
    return combined


def _build_reencode_salvage_args(out_ext: str, pre_probe: Optional[Dict[str, Any]], mux_args: List[str]) -> List[str]:
    has_video = bool(pre_probe and pre_probe.get("video_streams")) or out_ext not in _AUDIO_ONLY_SUFFIXES
    has_audio = bool(pre_probe and pre_probe.get("audio_streams"))
    nb_frames = 0
    if pre_probe and pre_probe.get("video_streams"):
        nb_frames = int(pre_probe["video_streams"][0].get("nb_frames") or 0)

    if out_ext == ".png":
        return ["-frames:v", "1", "-c:v", "png"]
    if out_ext in (".jpg", ".jpeg"):
        return ["-frames:v", "1", "-pix_fmt", "yuvj444p", "-q:v", "2"]
    if out_ext in (".tif", ".tiff"):
        return ["-frames:v", "1", "-c:v", "tiff"]
    if out_ext == ".bmp":
        return ["-frames:v", "1", "-c:v", "bmp"]
    if out_ext == ".webp":
        codec = "libwebp_anim" if nb_frames > 1 else "libwebp"
        return ["-c:v", codec, "-lossless", "1"]
    if out_ext == ".apng":
        return ["-plays", "0", "-c:v", "apng", "-pix_fmt", "rgba"]
    if out_ext == ".gif":
        return ["-filter_complex", "[0:v]split[a][b];[a]palettegen[p];[b][p]paletteuse", "-loop", "0"]
    if out_ext == ".wav":
        return ["-vn", "-c:a", "pcm_s24le"]
    if out_ext == ".flac":
        return ["-vn", "-c:a", "flac"]
    if out_ext in (".ogg", ".opus"):
        return ["-vn", "-c:a", "libopus", "-b:a", "160k"]
    if out_ext == ".mp3":
        return ["-vn", "-c:a", "libmp3lame", "-b:a", "192k"]
    if out_ext == ".m4a":
        return ["-vn", "-c:a", "aac", "-b:a", "192k"] + mux_args
    if out_ext == ".webm":
        args: List[str] = []
        if has_video:
            args += ["-map", "0:v?", "-c:v", "libvpx-vp9", "-crf", "20", "-b:v", "0", "-pix_fmt", "yuv420p"]
        if has_audio or not has_video:
            args += ["-map", "0:a?", "-c:a", "libopus", "-b:a", "160k"]
        return args

    args = []
    if has_video:
        args += [
            "-map",
            "0:v?",
            "-vf",
            "scale=trunc(iw/2)*2:trunc(ih/2)*2",
            "-c:v",
            "libx264",
            "-crf",
            "16",
            "-pix_fmt",
            "yuv420p",
        ]
    if has_audio or not has_video:
        args += ["-map", "0:a?", "-c:a", "aac", "-b:a", "192k"]
    return args + mux_args


def salvage_media(
    input_path: Path,
    output_path: Path,
    allow_reencode: bool = False,
    allow_partial: bool = False,
) -> Dict[str, Any]:
    ffmpeg = _require_tool("ffmpeg")
    if not input_path.is_file():
        raise FileNotFoundError(f"Input media file does not exist: {input_path}")
    _guard_local_media_file(input_path)
    _check_output_target_safety(output_path, [input_path])

    pre_probe: Optional[Dict[str, Any]] = None
    pre_duration: Optional[float] = None
    try:
        pre_probe = probe_media(input_path)
        pre_duration = pre_probe.get("duration_sec")
    except Exception as exc:
        if isinstance(exc, (ValueError,)) and "playlist" in str(exc).lower():
            raise
        pre_probe = None
        pre_duration = None

    _, src_errs = _verify_full_decode(input_path)
    safe_in = _safe_media_arg(input_path)
    in_ext = input_path.suffix.lower()
    out_ext = output_path.suffix.lower()
    mux_args = ["-movflags", "+faststart"] if out_ext in (".mp4", ".m4a", ".mov") else []
    demux_args = (
        ["-ignore_length", "true", "-err_detect", "ignore_err"]
        if in_ext == ".wav"
        else ["-fflags", "+genpts+igndts+discardcorrupt", "-err_detect", "ignore_err"]
    )

    def _validate_candidate(cand: Path) -> Tuple[bool, Optional[Dict[str, Any]], List[str]]:
        if not cand.is_file() or cand.stat().st_size == 0:
            return False, None, ["salvage produced no output bytes"]
        try:
            p_info = probe_media(cand)
        except Exception as exc:
            return False, None, [str(exc)]
        if not p_info["video_streams"] and not p_info["audio_streams"]:
            return False, p_info, ["salvaged container has zero audio or video streams"]
        if pre_probe is not None:
            if pre_probe.get("video_streams") and out_ext not in _AUDIO_ONLY_SUFFIXES and not p_info["video_streams"]:
                return False, p_info, ["salvaged output lost video stream present in source"]
            if (
                pre_probe.get("audio_streams")
                and out_ext not in (_SINGLE_FRAME_BITMAP_SUFFIXES | {".gif", ".webp", ".apng"})
                and not p_info["audio_streams"]
            ):
                return False, p_info, ["salvaged output lost audio stream present in source"]
        is_img = _is_still_or_anim_container(p_info)
        rec_d = p_info.get("duration_sec") or 0.0
        if rec_d <= 0.0 and not is_img:
            return False, p_info, ["salvaged container has non-positive duration"]
        if (
            not allow_partial
            and not is_img
            and pre_duration is not None
            and math.isfinite(pre_duration)
            and pre_duration > 0.25
            and rec_d < 0.95 * pre_duration
        ):
            return (
                False,
                p_info,
                [
                    f"partial recovery ({rec_d:.3f}s of {pre_duration:.3f}s < 95%); "
                    "pass --allow-partial to accept truncated timeline recovery"
                ],
            )
        dec_ok, dec_errs = _verify_full_decode(cand)
        return dec_ok, p_info, dec_errs

    is_single_bitmap_pair = in_ext in _SINGLE_FRAME_BITMAP_SUFFIXES and out_ext in _SINGLE_FRAME_BITMAP_SUFFIXES
    mode_used = "reencode_required" if (is_single_bitmap_pair and not allow_reencode) else "stream_copy"
    last_errors: List[str] = []

    with _staged_output(output_path, [input_path]) as (tmp_out, commit_out):
        # Stage 1: Lossless stream-copy container/header salvage (zero generation loss)
        if not is_single_bitmap_pair:
            cmd_copy = (
                [ffmpeg, "-hide_banner", "-nostdin", "-y"]
                + demux_args
                + ["-protocol_whitelist", "file", "-i", safe_in, "-map", "0:v?", "-map", "0:a?", "-c", "copy"]
                + mux_args
                + [str(tmp_out)]
            )
            try:
                proc_copy = _run_media_subprocess(cmd_copy)
            except TimeoutError as exc:
                last_errors = [str(exc)]
                proc_copy = None
            if proc_copy is not None:
                ok, post_info, out_errs = _validate_candidate(tmp_out)
                if proc_copy.returncode == 0 and ok and post_info is not None:
                    commit_out()
                    rec_dur = post_info.get("duration_sec") or 0.0
                    return {
                        "input": str(input_path),
                        "output": str(output_path),
                        "passed": True,
                        "mode": "stream_copy",
                        "pre_duration_sec": pre_duration,
                        "recovered_duration_sec": rec_dur,
                        "source_decode_errors": len(src_errs),
                        "output_decode_errors": 0,
                        "errors": [],
                    }
                last_errors = _collect_salvage_errors(proc_copy.stderr, out_errs)
            if os.path.lexists(tmp_out):
                tmp_out.unlink()
        elif not allow_reencode:
            last_errors = [
                f"single-frame bitmap format '{in_ext}' has no packet container index to remux; "
                "pass --allow-reencode to decode intact scanlines into a lossless archival target (.png/.tiff)"
            ]

        # Stage 2: Archival re-encode salvage (only when explicitly authorized via allow_reencode)
        if allow_reencode:
            mode_used = "reencode_salvage"
            enc_args = _build_reencode_salvage_args(out_ext, pre_probe, mux_args)
            cmd_re = (
                [ffmpeg, "-hide_banner", "-nostdin", "-y"]
                + demux_args
                + ["-protocol_whitelist", "file", "-i", safe_in]
                + enc_args
                + [str(tmp_out)]
            )
            try:
                proc_re = _run_media_subprocess(cmd_re)
            except TimeoutError as exc:
                last_errors = [str(exc)]
                proc_re = None
            if proc_re is not None:
                ok, post_info, out_errs = _validate_candidate(tmp_out)
                if proc_re.returncode == 0 and ok and post_info is not None:
                    commit_out()
                    rec_dur = post_info.get("duration_sec") or 0.0
                    return {
                        "input": str(input_path),
                        "output": str(output_path),
                        "passed": True,
                        "mode": "reencode_salvage",
                        "pre_duration_sec": pre_duration,
                        "recovered_duration_sec": rec_dur,
                        "source_decode_errors": len(src_errs),
                        "output_decode_errors": 0,
                        "errors": [],
                    }
                last_errors = _collect_salvage_errors(proc_re.stderr, out_errs)

    return {
        "input": str(input_path),
        "output": str(output_path),
        "passed": False,
        "mode": mode_used,
        "pre_duration_sec": pre_duration,
        "recovered_duration_sec": 0.0,
        "source_decode_errors": len(src_errs),
        "output_decode_errors": max(1, len(last_errors)),
        "errors": last_errors or ["container salvage failed; pass --allow-reencode if codec packets require transcoding"],
    }


def _select_compare_pix_fmt(
    ref_vs: Dict[str, Any],
    cand_vs: Dict[str, Any],
    rw: int,
    rh: int,
    *,
    pixel_art: bool = False,
) -> str:
    ref_pf = str(ref_vs.get("pix_fmt") or "").lower()
    cand_pf = str(cand_vs.get("pix_fmt") or "").lower()
    alpha_tokens = ("rgba", "bgra", "argb", "abgr", "yuva", "gbrap", "ya8", "ya16", "pal8")
    if any(tok in ref_pf or tok in cand_pf for tok in alpha_tokens):
        return "yuva444p"
    if "16" in ref_pf or "16" in cand_pf:
        return "gray16le" if ("gray" in ref_pf and "gray" in cand_pf) else "yuv444p16le"
    # Avoid 4:2:0 subsampling on pixel art or small sprites (<16px halves chroma below ffmpeg ssim's 8x8 window).
    if pixel_art or rw < 16 or rh < 16:
        return "yuv444p"
    return "yuv420p" if (rw % 2 == 0 and rh % 2 == 0) else "yuv444p"


def compare_media(
    reference: Path,
    candidate: Path,
    min_ssim: float = 0.95,
    min_psnr: float = 35.0,
    allow_aspect_change: bool = False,
    allow_trim: bool = False,
    pixel_art: bool = False,
) -> Dict[str, Any]:
    _require_finite_param("min_ssim", min_ssim)
    _require_finite_param("min_psnr", min_psnr)
    if not (0.0 <= min_ssim <= 1.0):
        raise ValueError(f"Parameter 'min_ssim' must be within [0.0, 1.0] (got {min_ssim}).")
    if min_psnr < 0.0:
        raise ValueError(f"Parameter 'min_psnr' must be >= 0.0 dB (got {min_psnr}).")
    ffmpeg = _require_tool("ffmpeg")
    ref_info = probe_media(reference)
    cand_info = probe_media(candidate)
    if not ref_info["video_streams"] or not cand_info["video_streams"]:
        raise ValueError("Both reference and candidate files must contain at least one video stream.")

    ref_vs = ref_info["video_streams"][0]
    cand_vs = cand_info["video_streams"][0]
    rw, rh = _effective_dimensions(ref_vs)
    cw, ch = _effective_dimensions(cand_vs)

    ref_aspect = _effective_aspect_ratio(ref_vs)
    cand_aspect = _effective_aspect_ratio(cand_vs)
    ref_sar = _stream_sar(ref_vs)
    cand_sar = _stream_sar(cand_vs)
    display_drift = abs(cand_aspect - ref_aspect) / ref_aspect if ref_aspect > 0.0 else 0.0
    # Reject silent non-square SAR injection from `scale=W:H` without `setsar=1`, while allowing
    # intentional normalization of anamorphic sources (`ref_sar != 1`) to square pixels (`cand_sar == 1`).
    non_square_sar_drift = (
        abs(cand_sar - ref_sar) / ref_sar if (abs(cand_sar - 1.0) > 0.02 and ref_sar > 0.0) else 0.0
    )
    aspect_drift = max(display_drift, non_square_sar_drift)
    aspect_ok = bool(allow_aspect_change or aspect_drift <= 0.02)

    ref_dur = ref_info.get("duration_sec") or 0.0
    cand_dur = cand_info.get("duration_sec") or 0.0
    is_timed = (not _is_still_or_anim_container(ref_info) and ref_dur > 0.2) or (
        not _is_still_or_anim_container(cand_info) and cand_dur > 0.2
    )
    duration_drift_sec = abs(cand_dur - ref_dur) if is_timed else 0.0
    duration_ok = bool(
        allow_trim or not is_timed or duration_drift_sec <= max(0.12, 0.02 * max(ref_dur, 0.001))
    )

    integer_scale_ok = True
    block_uniform_ok = True
    scale_factor: Optional[int] = None
    non_uniform_blocks: Optional[int] = None
    cmp_w, cmp_h = rw, rh
    scale_flags = "bicubic"
    if pixel_art:
        scale_flags = "neighbor"
        integer_scale_ok = bool(
            cw >= rw and ch >= rh and cw % rw == 0 and ch % rh == 0 and (cw // rw) == (ch // rh)
        )
        if integer_scale_ok:
            scale_factor = cw // rw
            cmp_w, cmp_h = cw, ch
            if scale_factor >= 2:
                frame_pixels = cw * ch
                frame_budget = (
                    max(1, MAX_GAME_VISUAL_PIXELS // max(1, frame_pixels))
                    if _is_still_or_anim_container(cand_info)
                    else 1
                )
                cand_rgba = _decode_image_rgba_frames(candidate, cw, ch, max_frames=frame_budget)
                frame_bytes = frame_pixels * 4
                n_cand_frames = max(1, len(cand_rgba) // frame_bytes)
                mv_cand = memoryview(cand_rgba)
                non_uniform_blocks = sum(
                    _check_integer_scale_blocks(
                        mv_cand[f_idx * frame_bytes : (f_idx + 1) * frame_bytes],
                        rw,
                        rh,
                        scale_factor,
                    )
                    for f_idx in range(n_cand_frames)
                )
                block_uniform_ok = non_uniform_blocks == 0
            else:
                non_uniform_blocks = 0
        else:
            block_uniform_ok = False

    cmp_pix_fmt = _select_compare_pix_fmt(ref_vs, cand_vs, cmp_w, cmp_h, pixel_art=pixel_art)
    upsample_post = ""
    if cmp_w < 8 or cmp_h < 8:
        up_k = max(2, math.ceil(8 / max(1, min(cmp_w, cmp_h))))
        upsample_post = f",scale={cmp_w * up_k}:{cmp_h * up_k}:flags=neighbor"
    # Place reference on input 0 so a truncated candidate cannot prematurely stop framesync at frame 1.
    filtergraph = (
        f"[0:v]scale={cmp_w}:{cmp_h}:flags={scale_flags}{upsample_post},format={cmp_pix_fmt},settb=AVTB,setpts=PTS-STARTPTS,split=2[r1][r2];"
        f"[1:v]scale={cmp_w}:{cmp_h}:flags={scale_flags}{upsample_post},format={cmp_pix_fmt},settb=AVTB,setpts=PTS-STARTPTS,split=2[c1][c2];"
        f"[r1][c1]ssim=eof_action=repeat:shortest=0;"
        f"[r2][c2]psnr=eof_action=repeat:shortest=0"
    )
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-nostdin",
        "-err_detect",
        "explode",
        "-xerror",
        "-protocol_whitelist",
        "file",
        "-i",
        _safe_media_arg(reference),
        "-protocol_whitelist",
        "file",
        "-i",
        _safe_media_arg(candidate),
        "-lavfi",
        filtergraph,
        "-f",
        "null",
        "-",
    ]
    proc = _run_media_subprocess(cmd)
    log = (proc.stderr or "") + "\n" + (proc.stdout or "")
    if proc.returncode != 0:
        raise RuntimeError(f"ffmpeg SSIM/PSNR comparison failed (exit {proc.returncode}):\n{log[-600:]}")

    m_ssim = re.search(r"SSIM\s+.*?All:([0-9.]+)", log)
    m_psnr = re.search(r"PSNR\s+.*?average:([0-9.]+|inf)", log)
    m_frames = re.search(r"PSNR\s+n:(\d+)", log)
    if not m_ssim or not m_psnr or (m_frames and int(m_frames.group(1)) < 1):
        raise RuntimeError(f"Failed to parse valid non-empty SSIM/PSNR frames from ffmpeg output:\n{log[-600:]}")

    ssim_val = float(m_ssim.group(1))
    psnr_raw = m_psnr.group(1)
    psnr_val = 100.0 if psnr_raw == "inf" else float(psnr_raw)
    if not (math.isfinite(ssim_val) and math.isfinite(psnr_val)):
        raise RuntimeError(f"ffmpeg SSIM/PSNR produced non-finite metrics (SSIM={ssim_val}, PSNR={psnr_val}).")

    passed = bool(
        ssim_val >= min_ssim
        and psnr_val >= min_psnr
        and aspect_ok
        and duration_ok
        and integer_scale_ok
        and block_uniform_ok
    )
    out: Dict[str, Any] = {
        "reference": str(reference),
        "candidate": str(candidate),
        "ssim_all": round(ssim_val, 6),
        "psnr_avg_db": round(psnr_val, 2),
        "min_ssim": min_ssim,
        "min_psnr": min_psnr,
        "aspect_drift_ratio": round(aspect_drift, 6),
        "aspect_ok": aspect_ok,
        "duration_drift_sec": round(duration_drift_sec, 4),
        "duration_ok": duration_ok,
        "passed": passed,
    }
    if pixel_art:
        out.update(
            {
                "pixel_art": True,
                "scale_factor": scale_factor,
                "integer_scale_ok": integer_scale_ok,
                "non_uniform_blocks": non_uniform_blocks,
                "block_uniform_ok": block_uniform_ok,
            }
        )
    return out


def master_audio(
    input_path: Path,
    output_path: Path,
    target_lufs: float = -14.0,
    target_tp: float = -1.0,
    target_lra: float = 11.0,
    highpass_hz: int = 0,
    denoise: str = "none",
    declip: bool = False,
    game_sfx: bool = False,
    peak_db: Optional[float] = None,
    ogg_codec: str = "opus",
    trim_loop: bool = False,
) -> Dict[str, Any]:
    _require_finite_param("target_lufs", target_lufs)
    _require_finite_param("target_tp", target_tp)
    _require_finite_param("target_lra", target_lra)
    _require_finite_param("peak_db", peak_db)
    if target_tp > 0.0:
        raise ValueError(f"Parameter 'target_tp' must be <= 0.0 dBTP (got {target_tp}).")
    if target_lra <= 0.0:
        raise ValueError(f"Parameter 'target_lra' must be > 0.0 LU (got {target_lra}).")
    if highpass_hz < 0:
        raise ValueError(f"Parameter 'highpass_hz' must be >= 0 Hz (got {highpass_hz}).")
    if peak_db is not None and peak_db > 0.0:
        raise ValueError(f"Parameter 'peak_db' must be <= 0.0 dBFS (got {peak_db}).")
    if ogg_codec not in ("opus", "vorbis"):
        raise ValueError(f"Unsupported ogg_codec '{ogg_codec}'; choose 'opus' or 'vorbis'.")
    ext = output_path.suffix.lower()
    if ogg_codec == "vorbis" and ext != ".ogg":
        raise ValueError("--ogg-codec vorbis requires a '.ogg' output file path.")

    ffmpeg = _require_tool("ffmpeg")
    _check_output_target_safety(output_path, [input_path])

    info = probe_media(input_path)
    if not info["audio_streams"]:
        raise ValueError(f"Input file contains no audio streams: {input_path}")
    if trim_loop and info["video_streams"]:
        raise ValueError(
            "--trim-loop is supported only on audio-only assets; container holds video streams that would lose A/V sync."
        )

    pre_filters: List[str] = []
    if highpass_hz > 0:
        pre_filters.append(f"highpass=f={int(highpass_hz)}:poles=2")
    if declip:
        pre_filters.append("adeclip=w=55:o=75:a=8")
        pre_filters.append("adeclick=w=55:o=75:a=2")
    if denoise == "fft":
        pre_filters.append("afftdn=nr=12:nf=-40:tn=1")
    elif denoise == "nlm":
        pre_filters.append("anlmdn=s=0.002:p=0.004:r=0.01")
    elif denoise != "none":
        raise ValueError(f"Unsupported denoise mode '{denoise}'; choose 'none', 'fft', or 'nlm'.")

    pre_filter_str = ",".join(pre_filters)
    pre_chain = (pre_filter_str + ",") if pre_filter_str else ""
    safe_in = _safe_media_arg(input_path)

    trim_info: Optional[Dict[str, Any]] = None
    trim_af = ""
    if trim_loop:
        pcm_samples, pcm_ch, pcm_sr, _ = _decode_audio_f32le(
            input_path,
            sample_rate=48000,
            pre_filter=pre_filter_str or None,
        )
        bounds = _find_zero_crossing_loop_bounds(pcm_samples, pcm_ch, pcm_sr)
        if bounds is not None:
            s_idx, e_idx = bounds
            trim_af = f"aresample=48000,atrim=start_sample={s_idx}:end_sample={e_idx},asetpts=PTS-STARTPTS"
            trim_info = {
                "applied": True,
                "method": "zero_crossing",
                "start_sample": s_idx,
                "end_sample": e_idx,
            }
        else:
            dur_s = len(pcm_samples) / float(max(1, pcm_ch * pcm_sr))
            fade_d = min(0.003, max(0.0005, dur_s * 0.1)) if dur_s > 0.0 else 0.003
            trim_af = (
                f"aresample=48000,afade=t=in:st=0:d={fade_d:.4f},"
                f"areverse,afade=t=in:st=0:d={fade_d:.4f},areverse"
            )
            trim_info = {
                "applied": True,
                "method": "micro_fade_fallback",
                "fade_sec": round(fade_d, 4),
            }

    body_prefix_str = ",".join(part for part in (pre_filter_str, trim_af) if part)
    body_prefix_chain = (body_prefix_str + ",") if body_prefix_str else ""

    use_peak_mode = bool(game_sfx or peak_db is not None)
    eff_peak_target: Optional[float] = None
    gain_db: Optional[float] = None
    measured: Optional[Dict[str, Any]] = None

    if use_peak_mode:
        is_lossy_target = ext in (".ogg", ".opus", ".webm", ".mp3", ".aac", ".m4a")
        if peak_db is not None:
            eff_peak_target = float(peak_db)
        else:
            eff_peak_target = min(float(target_tp) - 0.6, -1.6) if is_lossy_target else float(target_tp)
        measured = _measure_peak_db_after_filter(input_path, body_prefix_str or None)
        in_peak = measured.get("peak_level_db")
        if in_peak is None or not math.isfinite(in_peak) or in_peak <= -90.0:
            raise ValueError(
                f"Input audio is completely silent or unmeasurable (peak_level_db={in_peak!r}); "
                "cannot apply peak normalization."
            )
        gain_db = max(-60.0, min(60.0, eff_peak_target - in_peak))
        pass2_af = f"{body_prefix_chain}volume={gain_db:.4f}dB,aresample=48000"
    else:
        # Pass 1: Measure EBU R128 parameters after pre-restoration filters
        pass1_af = f"{body_prefix_chain}loudnorm=I={target_lufs}:TP={target_tp}:LRA={target_lra}:print_format=json"
        cmd_pass1 = [
            ffmpeg,
            "-hide_banner",
            "-nostdin",
            "-protocol_whitelist",
            "file",
            "-i",
            safe_in,
            "-map",
            "0:a:0",
            "-vn",
            "-sn",
            "-dn",
            "-af",
            pass1_af,
            "-f",
            "null",
            "-",
        ]
        proc1 = _run_media_subprocess(cmd_pass1)
        log1 = (proc1.stderr or "") + "\n" + (proc1.stdout or "")
        if proc1.returncode != 0:
            raise RuntimeError(f"Pass 1 loudnorm failed (exit {proc1.returncode}):\n{log1[-600:]}")
        loudnorm_blocks = re.split(r"\[Parsed_loudnorm[^\]]*\]", log1)
        if len(loudnorm_blocks) <= 1:
            raise RuntimeError(f"Pass 1 loudnorm filter header missing from output:\n{log1[-600:]}")
        m_json = re.search(r"\{\s*\"input_i\"\s*:.*?\}", loudnorm_blocks[-1], re.DOTALL)
        if not m_json:
            raise RuntimeError(f"Pass 1 loudnorm JSON measurement failed:\n{log1[-600:]}")
        measured = json.loads(m_json.group(0))

        raw_i = _safe_float(measured.get("input_i"))
        if raw_i is None or not math.isfinite(raw_i):
            raise ValueError(
                f"Input audio is completely silent or unmeasurable (input_i={measured.get('input_i')!r}); "
                "cannot apply linear loudness normalization."
            )
        validated_vals: Dict[str, float] = {"input_i": raw_i}
        for key in ("input_tp", "input_lra", "input_thresh", "target_offset"):
            fv = _safe_float(measured.get(key))
            if fv is None or not math.isfinite(fv):
                raise RuntimeError(f"Pass 1 loudnorm returned non-finite '{key}': {measured.get(key)!r}")
            validated_vals[key] = fv

        # Pass 2: Apply linear loudnorm with strictly validated numeric parameters + sample rate 48000 Hz
        pass2_af = (
            f"{body_prefix_chain}loudnorm=I={target_lufs}:TP={target_tp}:LRA={target_lra}:"
            f"measured_I={validated_vals['input_i']:.4f}:measured_TP={validated_vals['input_tp']:.4f}:"
            f"measured_LRA={validated_vals['input_lra']:.4f}:"
            f"measured_thresh={validated_vals['input_thresh']:.4f}:offset={validated_vals['target_offset']:.4f}:"
            f"linear=true:print_format=summary,aresample=48000"
        )

    if ext == ".wav":
        audio_codec_args = ["-c:a", "pcm_s24le"]
    elif ext == ".flac":
        audio_codec_args = ["-c:a", "flac"]
    elif ext == ".mp3":
        audio_codec_args = ["-c:a", "libmp3lame", "-b:a", "192k"]
    elif ext in (".ogg", ".opus", ".webm"):
        if ogg_codec == "vorbis" and ext == ".ogg":
            audio_codec_args = ["-c:a", "libvorbis", "-q:a", "5"]
        else:
            audio_codec_args = ["-c:a", "libopus", "-b:a", "160k"]
    else:
        audio_codec_args = ["-c:a", "aac", "-b:a", "192k"]

    mux_args = ["-movflags", "+faststart"] if ext in (".mp4", ".m4a", ".mov") else []
    multi_stream_containers = (".mp4", ".mov", ".mkv", ".webm", ".m4v")
    multi_audio_containers = (".m4a", ".ogg", ".opus", ".mka")
    if ext in multi_stream_containers:
        stream_args = ["-map", "0", "-map", "-0:d?", "-map", "-0:t?", "-c:v", "copy", "-c:s", "copy"]
    elif ext in multi_audio_containers and len(info["audio_streams"]) > 1:
        stream_args = ["-map", "0:a", "-vn", "-sn", "-dn"]
    else:
        stream_args = ["-vn"]

    filter_args = (
        ["-filter:a", pass2_af]
        if len(info["audio_streams"]) > 1 and ext in (multi_stream_containers + multi_audio_containers)
        else ["-af", pass2_af]
    )

    with _staged_output(output_path, [input_path]) as (tmp_out, commit_out):
        cmd_pass2 = (
            [
                ffmpeg,
                "-hide_banner",
                "-nostdin",
                "-y",
                "-protocol_whitelist",
                "file",
                "-i",
                safe_in,
            ]
            + stream_args
            + filter_args
            + audio_codec_args
            + mux_args
            + [str(tmp_out)]
        )
        proc2 = _run_media_subprocess(cmd_pass2)
        if proc2.returncode != 0:
            raise RuntimeError(f"Pass 2 loudnorm render failed:\n{(proc2.stderr or '')[-600:]}")
        commit_out()

    post_metrics = _analyze_audio_signal(output_path)
    dec_ok = not post_metrics.get("decode_error")
    post_tp = post_metrics.get("true_peak_dbtp")
    loop_ok = True
    if trim_info is not None:
        if not dec_ok:
            loop_ok = False
            trim_info["post_loop_seam"] = {
                "loop_checked": False,
                "seamless": False,
                "reason": "Skipped post-render loop seam check due to audio decode failure.",
            }
        else:
            try:
                post_loop = analyze_audio_loop_seam(output_path)
                trim_info["post_loop_seam"] = post_loop
                loop_ok = bool(post_loop.get("seamless"))
            except (ValueError, RuntimeError, TimeoutError) as exc:
                loop_ok = False
                trim_info["post_loop_seam"] = {
                    "loop_checked": False,
                    "seamless": False,
                    "reason": str(exc),
                }

    if use_peak_mode:
        assert eff_peak_target is not None and gain_db is not None
        post_peak = post_metrics.get("peak_level_db")
        peak_ok = post_peak is not None and math.isfinite(post_peak) and abs(post_peak - eff_peak_target) <= 1.5
        tp_ceiling = min(0.0, max(float(target_tp), float(eff_peak_target)) + 0.2)
        tp_ok = post_tp is not None and post_tp <= tp_ceiling
        out_res: Dict[str, Any] = {
            "input": str(input_path),
            "output": str(output_path),
            "mode": "peak_game_sfx",
            "ogg_codec": ogg_codec if ext in (".ogg", ".opus", ".webm") else None,
            "target_lufs": None,
            "target_tp": target_tp,
            "target_peak_db": eff_peak_target,
            "gain_db": round(gain_db, 4),
            "passed": bool(dec_ok and peak_ok and tp_ok and loop_ok),
            "pass1_measured": measured,
            "post_metrics": post_metrics,
        }
    else:
        post_lufs = post_metrics.get("integrated_lufs")
        lufs_ok = post_lufs is not None and math.isfinite(post_lufs) and abs(post_lufs - target_lufs) <= 1.5
        tp_ok = post_tp is not None and post_tp <= min(0.0, float(target_tp) + 0.2)
        out_res = {
            "input": str(input_path),
            "output": str(output_path),
            "mode": "ebu_r128",
            "ogg_codec": ogg_codec if ext in (".ogg", ".opus", ".webm") else None,
            "target_lufs": target_lufs,
            "target_tp": target_tp,
            "passed": bool(dec_ok and lufs_ok and tp_ok and loop_ok),
            "pass1_measured": measured,
            "post_metrics": post_metrics,
        }
    if trim_info is not None:
        out_res["trim_loop"] = trim_info
    return out_res


def extract_keyframes(
    input_path: Path,
    output_png: Path,
    cols: int = 4,
    rows: int = 2,
    tile_width: int = 320,
) -> Dict[str, Any]:
    ffmpeg = _require_tool("ffmpeg")
    if cols < 1 or rows < 1:
        raise ValueError("cols and rows must be >= 1.")
    if tile_width < 32:
        raise ValueError("tile_width must be >= 32.")
    _check_output_target_safety(output_png, [input_path])
    info = probe_media(input_path)
    if not info["video_streams"]:
        raise ValueError(f"File contains no video stream: {input_path}")

    total_tiles = cols * rows
    duration = info.get("duration_sec") or 0.0
    nb_frames = info["video_streams"][0].get("nb_frames") or 0

    if duration > 0.2:
        fps_sample = max(1e-4, total_tiles / duration)
        vf = f"fps={fps_sample:.6f},scale={tile_width}:-1:flags=lanczos,tile={cols}x{rows}:padding=4:margin=4"
    elif nb_frames > 1:
        step = max(1, nb_frames // total_tiles)
        vf = f"select='not(mod(n\\,{step}))',scale={tile_width}:-1:flags=lanczos,tile={cols}x{rows}:padding=4:margin=4"
    else:
        vf = f"scale={tile_width}:-1:flags=lanczos"

    with _staged_output(output_png, [input_path]) as (tmp_png, commit_png):
        cmd = [
            ffmpeg,
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-err_detect",
            "explode",
            "-xerror",
            "-y",
            "-protocol_whitelist",
            "file",
            "-i",
            _safe_media_arg(input_path),
            "-vf",
            vf,
            "-frames:v",
            "1",
            str(tmp_png),
        ]
        proc = _run_media_subprocess(cmd)
        if proc.returncode != 0 or not tmp_png.is_file() or tmp_png.stat().st_size == 0:
            raise RuntimeError(f"Keyframe contact sheet extraction failed:\n{(proc.stderr or '')[-600:]}")
        dec_ok, dec_errs = _verify_visual_decode(tmp_png)
        if not dec_ok:
            raise RuntimeError(f"Keyframe contact sheet failed decode check: {dec_errs}")
        commit_png()

    return {
        "input": str(input_path),
        "output_png": str(output_png),
        "grid": f"{cols}x{rows}",
        "size_bytes": output_png.stat().st_size,
    }


def _clamp_ab_tile_dimensions(
    tile_width: int,
    aspect: float,
    eff_samples: int,
    min_tile_h: int = 2,
    scale_flags: str = "lanczos",
) -> Tuple[int, int, str]:
    pad_w = 4 if eff_samples == 1 else 12
    pad_h = 0 if eff_samples == 1 else (eff_samples - 1) * 4 + 8
    max_tw_dim = max(2, (MAX_AB_CANVAS_DIM - pad_w) // 2)
    max_th_dim = max(min_tile_h, (MAX_AB_CANVAS_DIM - pad_h) // max(1, eff_samples))

    tile_w = min(tile_width, max_tw_dim)
    tile_h = max(min_tile_h, int(round(tile_w / aspect)))
    if tile_h > max_th_dim:
        tile_w = max(2, min(max_tw_dim, int(math.floor(max_th_dim * aspect))))
        tile_h = max(min_tile_h, min(max_th_dim, int(round(tile_w / aspect))))

    def _canvas_dims(tw: int, th: int) -> Tuple[int, int]:
        return 2 * tw + pad_w, (th if eff_samples == 1 else eff_samples * th + pad_h)

    cw, ch = _canvas_dims(tile_w, tile_h)
    if (cw * ch) > MAX_AB_CANVAS_PIXELS:
        scale = math.sqrt(MAX_AB_CANVAS_PIXELS / max(1, cw * ch))
        tile_w = max(2, int(math.floor(tile_w * scale)))
        tile_h = max(min_tile_h, min(max_th_dim, int(round(tile_w / aspect))))
        cw, ch = _canvas_dims(tile_w, tile_h)
    while tile_w > 2 and (cw > MAX_AB_CANVAS_DIM or ch > MAX_AB_CANVAS_DIM or (cw * ch) > MAX_AB_CANVAS_PIXELS):
        tile_w -= 1
        tile_h = max(min_tile_h, min(max_th_dim, int(round(tile_w / aspect))))
        cw, ch = _canvas_dims(tile_w, tile_h)

    post_scale = ""
    if cw > MAX_AB_CANVAS_DIM or ch > MAX_AB_CANVAS_DIM or (cw * ch) > MAX_AB_CANVAS_PIXELS:
        scale2 = min(
            MAX_AB_CANVAS_DIM / max(1, cw),
            MAX_AB_CANVAS_DIM / max(1, ch),
            math.sqrt(MAX_AB_CANVAS_PIXELS / max(1, cw * ch)),
        )
        capped_w = max(2, min(MAX_AB_CANVAS_DIM, int(math.floor(cw * scale2))))
        capped_h = max(2, min(MAX_AB_CANVAS_DIM, int(math.floor(ch * scale2))))
        post_scale = f",scale={capped_w}:{capped_h}:flags={scale_flags}:force_original_aspect_ratio=decrease"
    return tile_w, tile_h, post_scale


def extract_ab_sheet(
    reference: Path,
    candidate: Path,
    output_png: Path,
    tile_width: int = 480,
    samples: int = 3,
    pixel_art: bool = False,
) -> Dict[str, Any]:
    ffmpeg = _require_tool("ffmpeg")
    if tile_width < 64:
        raise ValueError("tile_width must be >= 64.")
    if samples < 1:
        raise ValueError("samples must be >= 1.")
    _check_output_target_safety(output_png, [reference, candidate])

    ref_info = probe_media(reference)
    cand_info = probe_media(candidate)
    has_ref_v = bool(ref_info["video_streams"])
    has_cand_v = bool(cand_info["video_streams"])
    right_flags = "neighbor" if pixel_art else "lanczos"

    if has_ref_v and has_cand_v:
        modality = "visual"
        cand_vs = cand_info["video_streams"][0]
        eff_aspect = _effective_aspect_ratio(cand_vs)
        ref_dur = ref_info.get("duration_sec") or 0.0
        cand_dur = cand_info.get("duration_sec") or 0.0
        if ref_dur < 0.0 or cand_dur < 0.0 or not math.isfinite(ref_dur) or not math.isfinite(cand_dur):
            raise ValueError("Reference or candidate has invalid duration.")
        duration = min(ref_dur, cand_dur)
        max_samples = max(1, (MAX_AB_CANVAS_DIM - 4) // 20)
        cand_nb_frames = int(cand_vs.get("nb_frames") or 0)
        ref_nb_frames = int(ref_info["video_streams"][0].get("nb_frames") or 0)
        is_single_frame = (cand_nb_frames == 1) or (ref_nb_frames == 1)
        eff_samples = min(samples, max_samples) if (duration > 0.25 and not is_single_frame) else 1
        tile_width, tile_h, post_scale = _clamp_ab_tile_dimensions(
            tile_width,
            eff_aspect,
            eff_samples,
            min_tile_h=2,
            scale_flags=right_flags,
        )
        if eff_samples == 1:
            lavfi = (
                f"[0:v]scale={tile_width}:{tile_h}:flags=neighbor,setsar=1,"
                f"pad={tile_width + 4}:{tile_h}:0:0:color=#18181B[left];"
                f"[1:v]scale={tile_width}:{tile_h}:flags={right_flags},setsar=1[right];"
                f"[left][right]hstack=inputs=2{post_scale}"
            )
        else:
            fps_sample = max(1e-4, (eff_samples + 0.25) / duration)
            lavfi = (
                f"[0:v]fps={fps_sample:.6f},scale={tile_width}:{tile_h}:flags=neighbor,setsar=1,"
                f"pad={tile_width + 4}:{tile_h}:0:0:color=#18181B[left];"
                f"[1:v]fps={fps_sample:.6f},scale={tile_width}:{tile_h}:flags={right_flags},setsar=1[right];"
                f"[left][right]hstack=inputs=2,tile=1x{eff_samples}:padding=4:margin=4:color=#09090B{post_scale}"
            )
    elif not has_ref_v and not has_cand_v and ref_info["audio_streams"] and cand_info["audio_streams"]:
        modality = "audio_spectrogram"
        eff_samples = 1
        tile_width, tile_h, post_scale = _clamp_ab_tile_dimensions(
            tile_width, 1.0 / 0.6, eff_samples, min_tile_h=120
        )
        lavfi = (
            f"[0:a]showspectrumpic=s={tile_width}x{tile_h}:legend=0,"
            f"pad={tile_width + 4}:{tile_h}:0:0:color=#18181B[left];"
            f"[1:a]showspectrumpic=s={tile_width}x{tile_h}:legend=0[right];"
            f"[left][right]hstack=inputs=2{post_scale}"
        )
    else:
        raise ValueError(
            "Reference and candidate must both contain visual streams or both contain audio-only streams."
        )

    with _staged_output(output_png, [reference, candidate]) as (tmp_png, commit_png):
        cmd = [
            ffmpeg,
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-err_detect",
            "explode",
            "-xerror",
            "-y",
            "-protocol_whitelist",
            "file",
            "-i",
            _safe_media_arg(reference),
            "-protocol_whitelist",
            "file",
            "-i",
            _safe_media_arg(candidate),
            "-lavfi",
            lavfi,
            "-frames:v",
            "1",
            str(tmp_png),
        ]
        proc = _run_media_subprocess(cmd)
        if proc.returncode != 0 or not tmp_png.is_file() or tmp_png.stat().st_size == 0:
            raise RuntimeError(f"A/B comparison sheet extraction failed:\n{(proc.stderr or '')[-600:]}")
        dec_ok, dec_errs = _verify_visual_decode(tmp_png)
        if not dec_ok:
            raise RuntimeError(f"A/B comparison sheet failed decode check: {dec_errs}")
        commit_png()

    return {
        "reference": str(reference),
        "candidate": str(candidate),
        "output_png": str(output_png),
        "modality": modality,
        "samples": eff_samples,
        "tile_size": f"{tile_width}x{tile_h}",
        "pixel_art": pixel_art,
        "size_bytes": output_png.stat().st_size,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="media_qc.py",
        description="Deterministic audio/video probe, quality gate & Two-Pass EBU R128 mastering CLI.",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_probe = sub.add_parser("probe", help="Inspect container and stream layout via ffprobe.")
    p_probe.add_argument("path", type=Path, help="Input media file path.")
    p_probe.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_check = sub.add_parser("check", help="Run MEDIA-1..MEDIA-7 (+ optional GAME-1..GAME-3) audio/video quality gate.")
    p_check.add_argument("path", type=Path, help="Input media file path.")
    p_check.add_argument("--target-lufs", type=float, default=None, help="Target integrated loudness in LUFS (e.g. -14.0).")
    p_check.add_argument("--lufs-tolerance", type=float, default=1.5, help="Allowed LUFS deviation (+/- LU, default: 1.5).")
    p_check.add_argument("--max-true-peak", type=float, default=-1.0, help="Maximum allowed True Peak in dBTP (default: -1.0).")
    p_check.add_argument("--max-dc-offset", type=float, default=0.02, help="Maximum absolute DC offset (default: 0.02).")
    p_check.add_argument("--allow-silent", action="store_true", help="Allow silent audio streams (<= -70 LUFS).")
    p_check.add_argument("--allow-high-chroma", action="store_true", help="Allow yuv422p/yuv444p in H.264 MP4.")
    p_check.add_argument("--allow-static", action="store_true", help="Allow static/frozen video frames on >1s clips.")
    p_check.add_argument(
        "--game-sfx",
        action="store_true",
        help="Validate short game SFX (<0.5s) via Peak dBFS rather than ITU-R BS.1770 400ms LUFS gating.",
    )
    p_check.add_argument("--check-loop", action="store_true", help="Verify seamless audio wrap continuity (GAME-1).")
    p_check.add_argument("--max-seam-step", type=float, default=0.15, help="Normalized wrap sample step ceiling (default: 0.15).")
    p_check.add_argument("--max-seam-impulse", type=float, default=0.05, help="Normalized wrap slope impulse ceiling (default: 0.05).")
    p_check.add_argument("--pixel-art", action="store_true", help="Verify crisp nearest-neighbor pixel-art alpha edges (GAME-2).")
    p_check.add_argument("--sprite-atlas", action="store_true", help="Enable sprite-atlas geometry & alpha bleed QC (GAME-3).")
    p_check.add_argument("--tile-size", type=str, default=None, help="Sprite tile cell dimensions WxH (e.g. 32x32).")
    p_check.add_argument("--require-pot", action="store_true", help="Require power-of-two texture/atlas width and height (GAME-3).")
    p_check.add_argument("--check-alpha-bleed", action="store_true", help="Flag transparent edge texels with un-dilated RGB halos.")
    p_check.add_argument("--allow-edge-touch", action="store_true", help="Allow opaque sprite pixels on internal tile borders.")
    p_check.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_salv = sub.add_parser("salvage", help="Recover truncated headers or damaged container indices via stream-copy first.")
    p_salv.add_argument("input", type=Path, help="Damaged or unindexed input media file.")
    p_salv.add_argument("output", type=Path, help="Output salvaged file path (must differ from input).")
    p_salv.add_argument(
        "--allow-reencode",
        action="store_true",
        help="Allow archival re-encode fallback only when lossless stream-copy cannot recover damaged codec packets.",
    )
    p_salv.add_argument(
        "--allow-partial",
        action="store_true",
        help="Accept truncated timeline recovery when <95%% of original container duration survives.",
    )
    p_salv.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_cmp = sub.add_parser("compare", help="Compare candidate visual file against reference using SSIM, PSNR & aspect lock.")
    p_cmp.add_argument("reference", type=Path, help="Reference source image or video file.")
    p_cmp.add_argument("candidate", type=Path, help="Processed/upscaled candidate image or video file.")
    p_cmp.add_argument("--min-ssim", type=float, default=0.95, help="Minimum passing All-SSIM score (default: 0.95).")
    p_cmp.add_argument("--min-psnr", type=float, default=35.0, help="Minimum passing average PSNR in dB (default: 35.0).")
    p_cmp.add_argument(
        "--allow-aspect-change",
        action="store_true",
        help="Allow >2%% display aspect ratio change when intentional cropping/reframing was requested.",
    )
    p_cmp.add_argument(
        "--allow-trim",
        action="store_true",
        help="Allow timeline duration differences when intentional trimming or speed change was requested.",
    )
    p_cmp.add_argument(
        "--pixel-art",
        action="store_true",
        help="Verify nearest-neighbor integer upscale factor & uniform kxk pixel blocks.",
    )
    p_cmp.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_ab = sub.add_parser("ab-sheet", help="Render a side-by-side Reference vs. Enhanced PNG comparison sheet.")
    p_ab.add_argument("reference", type=Path, help="Original reference image, video, or audio file.")
    p_ab.add_argument("candidate", type=Path, help="Restored or upscaled candidate image, video, or audio file.")
    p_ab.add_argument("output_png", type=Path, help="Output side-by-side comparison PNG path.")
    p_ab.add_argument("--tile-width", type=int, default=480, help="Width per side in pixels (default: 480).")
    p_ab.add_argument("--samples", type=int, default=3, help="Timestamp rows to stack for video inputs (default: 3).")
    p_ab.add_argument("--pixel-art", action="store_true", help="Render both A and B sides with crisp nearest-neighbor scaling.")
    p_ab.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_master = sub.add_parser("master-audio", help="Run Two-Pass EBU R128 loudness normalization or peak game SFX mastering.")
    p_master.add_argument("input", type=Path, help="Input audio/video file.")
    p_master.add_argument("output", type=Path, help="Output mastered file (must differ from input).")
    p_master.add_argument("--target-lufs", type=float, default=-14.0, help="Target integrated loudness in LUFS (default: -14.0).")
    p_master.add_argument("--target-tp", type=float, default=-1.0, help="Target True Peak ceiling in dBTP (default: -1.0).")
    p_master.add_argument("--target-lra", type=float, default=11.0, help="Target Loudness Range in LU (default: 11.0).")
    p_master.add_argument("--highpass", type=int, default=0, help="Optional high-pass filter cutoff in Hz (e.g. 75 for voice).")
    p_master.add_argument("--denoise", choices=("none", "fft", "nlm"), default="none", help="Optional spectral/broadband denoiser.")
    p_master.add_argument("--declip", action="store_true", help="Apply adeclip and adeclick before normalization.")
    p_master.add_argument(
        "--game-sfx",
        action="store_true",
        help="Use linear peak normalization instead of two-pass loudnorm (required for <400ms game SFX impulses).",
    )
    p_master.add_argument("--peak-db", type=float, default=None, help="Explicit peak target in dBFS (triggers peak normalization mode).")
    p_master.add_argument(
        "--ogg-codec",
        choices=("opus", "vorbis"),
        default="opus",
        help="Encoder for .ogg outputs: 'opus' (default, Web/streaming) or 'vorbis' (Unity/Godot/Unreal compatibility).",
    )
    p_master.add_argument(
        "--trim-loop",
        action="store_true",
        help="Trim head/tail endpoints onto matched rising zero-crossings for seamless audio loops.",
    )
    p_master.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_kf = sub.add_parser("keyframes", help="Extract a tiled contact-sheet PNG of video keyframes.")
    p_kf.add_argument("input", type=Path, help="Input video or animated visual file.")
    p_kf.add_argument("output_png", type=Path, help="Output contact-sheet PNG path.")
    p_kf.add_argument("--cols", type=int, default=4, help="Grid columns (default: 4).")
    p_kf.add_argument("--rows", type=int, default=2, help="Grid rows (default: 2).")
    p_kf.add_argument("--tile-width", type=int, default=320, help="Width per tile in pixels (default: 320).")
    p_kf.add_argument("--json", action="store_true", help="Emit JSON output.")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        if args.subcommand == "probe":
            res = probe_media(args.path)
            if args.json:
                print(json.dumps(res, indent=2, allow_nan=False))
            else:
                print(f"File     : {res['path']} ({res['size_bytes']} bytes)")
                print(f"Format   : {res['format_name']} | Duration: {res['duration_sec']}s | AV Drift: {res['av_drift_sec']}s")
                for vs in res["video_streams"]:
                    print(
                        f"Video #{vs['index']} : {vs['codec_name']} {vs['width']}x{vs['height']} "
                        f"pix_fmt={vs['pix_fmt']} fps={vs['fps']} vfr={vs['is_vfr']} color={vs['color_space']}"
                    )
                for aus in res["audio_streams"]:
                    print(
                        f"Audio #{aus['index']} : {aus['codec_name']} {aus['sample_rate']}Hz "
                        f"channels={aus['channels']} ({aus['channel_layout']}) fmt={aus['sample_fmt']}"
                    )
            return 0

        if args.subcommand == "check":
            res = check_media(
                args.path,
                target_lufs=args.target_lufs,
                lufs_tolerance=args.lufs_tolerance,
                max_true_peak=args.max_true_peak,
                max_dc_offset=args.max_dc_offset,
                allow_silent=args.allow_silent,
                allow_high_chroma=args.allow_high_chroma,
                allow_static=args.allow_static,
                game_sfx=args.game_sfx,
                check_loop=args.check_loop,
                max_seam_step=args.max_seam_step,
                max_seam_impulse=args.max_seam_impulse,
                pixel_art=args.pixel_art,
                sprite_atlas=args.sprite_atlas,
                tile_size=args.tile_size,
                require_pot=args.require_pot,
                check_alpha_bleed=args.check_alpha_bleed,
                allow_edge_touch=args.allow_edge_touch,
            )
            if args.json:
                print(json.dumps(res, indent=2, allow_nan=False))
            else:
                status = "PASS" if res["passed"] else "FAIL"
                print(f"[{status}] Media QC Gate -> {res['path']}")
                if res["audio_metrics"]:
                    am = res["audio_metrics"]
                    print(
                        f"  Audio : I={am['integrated_lufs']} LUFS | TP={am['true_peak_dbtp']} dBTP | "
                        f"Peak={am['peak_level_db']} dBFS | LRA={am['lra_lu']} LU | DC={am['dc_offset']}"
                    )
                if res.get("loop_metrics"):
                    lm = res["loop_metrics"]
                    print(
                        f"  Loop  : seamless={lm['seamless']} | step={lm['seam_step']} | impulse={lm['seam_impulse']}"
                    )
                if res["video_metrics"]:
                    vm = res["video_metrics"]
                    print(
                        f"  Video : black_ratio={vm['black_ratio']:.3f} | freeze_ratio={vm['freeze_ratio']:.3f}"
                    )
                if res.get("game_visual_metrics"):
                    gm = res["game_visual_metrics"]
                    print(
                        f"  Game  : {gm['width']}x{gm['height']} | PoT={gm['is_pot']} | tile={gm['tile_size']} "
                        f"(aligned={gm['tile_aligned']}) | semi_alpha={gm['semi_alpha_pixels']} | "
                        f"bleed={gm['alpha_bleed_pixels']} | edge_touch={gm['edge_touch_pixels']}"
                    )
                for f in res["findings"]:
                    print(f"  [{f['rule_id']}] ({f['severity']}) {f['message']}")
                    print(f"     Fix: {f['fix_hint']}")
            return 0 if res["passed"] else 1

        if args.subcommand == "salvage":
            res = salvage_media(
                args.input,
                args.output,
                allow_reencode=args.allow_reencode,
                allow_partial=args.allow_partial,
            )
            if args.json:
                print(json.dumps(res, indent=2, allow_nan=False))
            else:
                status = "PASS" if res["passed"] else "FAIL"
                print(
                    f"[{status}] Media Salvage ({res['mode']}) -> {res['output']} | "
                    f"Recovered={res['recovered_duration_sec']}s | OutDecodeErrors={res['output_decode_errors']}"
                )
                for err in res["errors"]:
                    print(f"  Error: {err}")
            return 0 if res["passed"] else 1

        if args.subcommand == "compare":
            res = compare_media(
                args.reference,
                args.candidate,
                min_ssim=args.min_ssim,
                min_psnr=args.min_psnr,
                allow_aspect_change=args.allow_aspect_change,
                allow_trim=args.allow_trim,
                pixel_art=args.pixel_art,
            )
            if args.json:
                print(json.dumps(res, indent=2, allow_nan=False))
            else:
                status = "PASS" if res["passed"] else "FAIL"
                extra = (
                    f" | Scale={res['scale_factor']}x (int_ok={res['integer_scale_ok']}, "
                    f"non_uniform={res['non_uniform_blocks']})"
                    if res.get("pixel_art")
                    else ""
                )
                print(
                    f"[{status}] Visual Fidelity Compare: SSIM={res['ssim_all']:.4f} (min {res['min_ssim']}) | "
                    f"PSNR={res['psnr_avg_db']:.2f} dB (min {res['min_psnr']} dB) | "
                    f"AspectDrift={res['aspect_drift_ratio'] * 100:.2f}% (ok={res['aspect_ok']}) | "
                    f"DurationDrift={res['duration_drift_sec']:.3f}s (ok={res['duration_ok']}){extra}"
                )
            return 0 if res["passed"] else 1

        if args.subcommand == "ab-sheet":
            res = extract_ab_sheet(
                args.reference,
                args.candidate,
                args.output_png,
                tile_width=args.tile_width,
                samples=args.samples,
                pixel_art=args.pixel_art,
            )
            if args.json:
                print(json.dumps(res, indent=2, allow_nan=False))
            else:
                print(
                    f"[OK] Extracted {res['samples']}-row A/B comparison sheet ({res['tile_size']} per side) -> "
                    f"{res['output_png']} ({res['size_bytes']} bytes)"
                )
            return 0

        if args.subcommand == "master-audio":
            res = master_audio(
                args.input,
                args.output,
                target_lufs=args.target_lufs,
                target_tp=args.target_tp,
                target_lra=args.target_lra,
                highpass_hz=args.highpass,
                denoise=args.denoise,
                declip=args.declip,
                game_sfx=args.game_sfx,
                peak_db=args.peak_db,
                ogg_codec=args.ogg_codec,
                trim_loop=args.trim_loop,
            )
            if args.json:
                print(json.dumps(res, indent=2, allow_nan=False))
            else:
                pm = res["post_metrics"]
                status = "OK" if res["passed"] else "FAIL"
                if res.get("mode") == "peak_game_sfx":
                    print(
                        f"[{status}] Mastered ({res['mode']}) '{res['input']}' -> '{res['output']}' | "
                        f"Post Peak={pm['peak_level_db']} dBFS, TP={pm['true_peak_dbtp']} dBTP, Gain={res['gain_db']} dB"
                    )
                else:
                    print(
                        f"[{status}] Mastered '{res['input']}' -> '{res['output']}' | "
                        f"Post I={pm['integrated_lufs']} LUFS, TP={pm['true_peak_dbtp']} dBTP"
                    )
            return 0 if res["passed"] else 1

        if args.subcommand == "keyframes":
            res = extract_keyframes(
                args.input,
                args.output_png,
                cols=args.cols,
                rows=args.rows,
                tile_width=args.tile_width,
            )
            if args.json:
                print(json.dumps(res, indent=2, allow_nan=False))
            else:
                print(f"[OK] Extracted {res['grid']} keyframe sheet -> {res['output_png']} ({res['size_bytes']} bytes)")
            return 0

    except Exception as exc:
        if getattr(args, "json", False):
            print(json.dumps({"passed": False, "error": str(exc)}, indent=2, allow_nan=False))
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
