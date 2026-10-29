#!/usr/bin/env python3
"""
tests/test_media_studio.py — Hermetic unit tests for skills/media-studio/scripts/media_qc.py
Verifies probe, check (MEDIA-1..MEDIA-7), compare (SSIM/PSNR), master-audio (Two-Pass EBU R128), and keyframes.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MEDIA_QC_PATH = REPO_ROOT / "skills" / "media-studio" / "scripts" / "media_qc.py"

spec = importlib.util.spec_from_file_location("media_qc", MEDIA_QC_PATH)
assert spec is not None and spec.loader is not None
media_qc = importlib.util.module_from_spec(spec)
sys.modules["media_qc"] = media_qc
spec.loader.exec_module(media_qc)


@unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "ffmpeg/ffprobe required")
class MediaStudioQcTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-media-test-")
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_ffmpeg(self, args: list[str]) -> None:
        cmd = ["ffmpeg", "-hide_banner", "-nostdin", "-y"] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            self.fail(f"ffmpeg test fixture setup failed: {proc.stderr}")

    def test_probe_and_check_clean_av_mp4_passes_all_rules(self) -> None:
        clean_mp4 = self.tmp_dir / "clean.mp4"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=1.5:size=160x120:rate=15",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=48000:duration=1.5",
                "-af",
                "volume=-6dB",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                "-b:a",
                "128k",
                str(clean_mp4),
            ]
        )

        info = media_qc.probe_media(clean_mp4)
        self.assertEqual(len(info["video_streams"]), 1)
        self.assertEqual(len(info["audio_streams"]), 1)
        self.assertEqual(info["video_streams"][0]["pix_fmt"], "yuv420p")
        self.assertEqual(info["video_streams"][0]["width"], 160)
        self.assertEqual(info["video_streams"][0]["height"], 120)

        res = media_qc.check_media(clean_mp4, max_true_peak=-1.0)
        self.assertTrue(res["passed"], f"Expected clean MP4 to pass, got findings: {res['findings']}")
        self.assertEqual(res["findings"], [])
        self.assertEqual(media_qc.main(["check", str(clean_mp4), "--json"]), 0)

    def test_check_detects_peak_clipping_dc_offset_bad_chroma_and_black_video(self) -> None:
        # 1. Audio with True Peak > -1.0 dBTP and positive DC shift
        clipped_wav = self.tmp_dir / "clipped_dc.wav"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=48000:duration=1.2",
                "-af",
                "volume=20dB,dcshift=shift=0.08",
                "-c:a",
                "pcm_s16le",
                str(clipped_wav),
            ]
        )
        res_audio = media_qc.check_media(clipped_wav, target_lufs=-16.0, lufs_tolerance=1.0, max_true_peak=-1.5)
        self.assertFalse(res_audio["passed"])
        rule_ids = {f["rule_id"] for f in res_audio["findings"]}
        self.assertIn("MEDIA-3", rule_ids)
        self.assertIn("MEDIA-4", rule_ids)
        self.assertIn("MEDIA-5", rule_ids)
        self.assertEqual(media_qc.main(["check", str(clipped_wav), "--max-true-peak", "-1.5"]), 1)

        # 2. H.264 MP4 with yuv444p chroma (MEDIA-6) and all-black frames (MEDIA-7)
        bad_mp4 = self.tmp_dir / "black_444.mp4"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "color=c=black:s=160x120:d=1.5:r=10",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv444p",
                str(bad_mp4),
            ]
        )
        res_video = media_qc.check_media(bad_mp4, allow_static=True)
        self.assertFalse(res_video["passed"])
        v_rules = {f["rule_id"] for f in res_video["findings"]}
        self.assertIn("MEDIA-6", v_rules)
        self.assertIn("MEDIA-7", v_rules)
        self.assertTrue(any("black frames" in f["message"] for f in res_video["findings"]))

        # Verify --allow-high-chroma suppresses MEDIA-6 while black_ratio still triggers MEDIA-7
        res_allow_chroma = media_qc.check_media(bad_mp4, allow_high_chroma=True, allow_static=True)
        self.assertNotIn("MEDIA-6", {f["rule_id"] for f in res_allow_chroma["findings"]})
        self.assertIn("MEDIA-7", {f["rule_id"] for f in res_allow_chroma["findings"]})

        # 3. Non-black static blue video triggers MEDIA-7 solely via freeze_ratio, and passes with allow_static=True
        frozen_blue_mp4 = self.tmp_dir / "frozen_blue.mp4"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "color=c=blue:s=160x120:d=1.5:r=10",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(frozen_blue_mp4),
            ]
        )
        res_frozen = media_qc.check_media(frozen_blue_mp4, allow_static=False)
        self.assertFalse(res_frozen["passed"])
        self.assertEqual([f["rule_id"] for f in res_frozen["findings"]], ["MEDIA-7"])
        self.assertIn("frozen/static", res_frozen["findings"][0]["message"])
        self.assertTrue(media_qc.check_media(frozen_blue_mp4, allow_static=True)["passed"])

    def test_media1_missing_empty_and_media2_av_drift_and_media3_silent(self) -> None:
        # MEDIA-1: missing file and 0-byte file
        missing_path = self.tmp_dir / "does_not_exist.mp4"
        res_missing = media_qc.check_media(missing_path)
        self.assertFalse(res_missing["passed"])
        self.assertEqual(res_missing["findings"][0]["rule_id"], "MEDIA-1")
        self.assertEqual(media_qc.main(["check", str(missing_path)]), 1)

        empty_path = self.tmp_dir / "empty.mp4"
        empty_path.write_bytes(b"")
        res_empty = media_qc.check_media(empty_path)
        self.assertFalse(res_empty["passed"])
        self.assertEqual(res_empty["findings"][0]["rule_id"], "MEDIA-1")

        # MEDIA-2: audio/video duration drift > 0.10s (1.5s video + 0.8s audio)
        drift_mp4 = self.tmp_dir / "drift.mp4"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=1.5:size=160x120:rate=15",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=48000:duration=0.8",
                "-af",
                "volume=-6dB",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(drift_mp4),
            ]
        )
        res_drift = media_qc.check_media(drift_mp4)
        self.assertFalse(res_drift["passed"])
        self.assertIn("MEDIA-2", {f["rule_id"] for f in res_drift["findings"]})

        # MEDIA-3: silent audio track fails by default and passes with allow_silent=True
        silent_wav = self.tmp_dir / "silent.wav"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "anullsrc=r=48000:cl=mono",
                "-t",
                "1.0",
                "-c:a",
                "pcm_s16le",
                str(silent_wav),
            ]
        )
        res_silent_fail = media_qc.check_media(silent_wav, allow_silent=False)
        self.assertFalse(res_silent_fail["passed"])
        self.assertEqual([f["rule_id"] for f in res_silent_fail["findings"]], ["MEDIA-3"])
        self.assertTrue(media_qc.check_media(silent_wav, allow_silent=True)["passed"])

    def test_two_pass_master_audio_normalizes_loudness_and_blocks_in_place_overwrite(self) -> None:
        raw_wav = self.tmp_dir / "quiet_input.wav"
        mastered_wav = self.tmp_dir / "mastered_output.wav"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=500:sample_rate=48000:duration=2.5",
                "-af",
                "volume=-10dB",
                "-c:a",
                "pcm_s24le",
                str(raw_wav),
            ]
        )

        # In-place overwrite must raise ValueError
        with self.assertRaises(ValueError):
            media_qc.master_audio(raw_wav, raw_wav)

        res = media_qc.master_audio(
            raw_wav,
            mastered_wav,
            target_lufs=-14.0,
            target_tp=-1.0,
            highpass_hz=60,
            denoise="fft",
            declip=True,
        )
        post = res["post_metrics"]
        self.assertTrue(res["passed"])
        self.assertIsNotNone(post["integrated_lufs"])
        self.assertAlmostEqual(post["integrated_lufs"], -14.0, delta=1.5)
        self.assertLessEqual(post["true_peak_dbtp"], -0.8)

        # In-tolerance MEDIA-4 pass check on the mastered audio
        res_check_mastered = media_qc.check_media(mastered_wav, target_lufs=-14.0, lufs_tolerance=1.5, max_true_peak=-0.8)
        self.assertTrue(res_check_mastered["passed"], f"Expected mastered WAV to pass MEDIA-4: {res_check_mastered['findings']}")

    def test_compare_ssim_psnr_and_keyframes_contact_sheet(self) -> None:
        ref_mp4 = self.tmp_dir / "ref.mp4"
        good_mp4 = self.tmp_dir / "good.mp4"
        bad_mp4 = self.tmp_dir / "degraded.mp4"
        sheet_png = self.tmp_dir / "sheet.png"

        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=1.2:size=160x120:rate=10",
                "-c:v",
                "libx264",
                "-crf",
                "14",
                "-pix_fmt",
                "yuv420p",
                str(ref_mp4),
            ]
        )
        self._run_ffmpeg(["-i", str(ref_mp4), "-c:v", "libx264", "-crf", "18", "-pix_fmt", "yuv420p", str(good_mp4)])
        self._run_ffmpeg(
            [
                "-i",
                str(ref_mp4),
                "-vf",
                "boxblur=10:2,noise=alls=60:allf=t",
                "-c:v",
                "libx264",
                "-crf",
                "45",
                "-pix_fmt",
                "yuv420p",
                str(bad_mp4),
            ]
        )

        cmp_good = media_qc.compare_media(ref_mp4, good_mp4, min_ssim=0.95, min_psnr=35.0)
        self.assertTrue(cmp_good["passed"])
        self.assertGreaterEqual(cmp_good["ssim_all"], 0.95)

        # Conjunction boundary: SSIM passes (>= 0.95) but impossible min_psnr (99.9 dB) fails
        cmp_psnr_only_fail = media_qc.compare_media(ref_mp4, good_mp4, min_ssim=0.95, min_psnr=99.9)
        self.assertFalse(cmp_psnr_only_fail["passed"])

        cmp_bad = media_qc.compare_media(ref_mp4, bad_mp4, min_ssim=0.95, min_psnr=35.0)
        self.assertFalse(cmp_bad["passed"])
        self.assertLess(cmp_bad["ssim_all"], 0.80)
        self.assertLess(cmp_bad["psnr_avg_db"], 30.0)
        self.assertEqual(media_qc.main(["compare", str(ref_mp4), str(bad_mp4), "--min-ssim", "0.95"]), 1)

        kf_res = media_qc.extract_keyframes(ref_mp4, sheet_png, cols=2, rows=2, tile_width=120)
        self.assertTrue(sheet_png.is_file())
        self.assertGreater(kf_res["size_bytes"], 100)
        self.assertEqual(sheet_png.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")


if __name__ == "__main__":
    unittest.main()
