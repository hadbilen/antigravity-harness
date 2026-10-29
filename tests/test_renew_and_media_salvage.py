#!/usr/bin/env python3
"""
tests/test_renew_and_media_salvage.py — Hermetic seam tests for the `renew` skill routing
and `media-studio` salvage, still-image quality control, aspect-locked comparison, and A/B sheets.
"""

from __future__ import annotations

import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

import hermetic  # noqa: F401, E402
from guard import agy_hooks  # noqa: E402

import importlib.util  # noqa: E402
import subprocess  # noqa: E402

MEDIA_QC_PATH = REPO_ROOT / "skills" / "media-studio" / "scripts" / "media_qc.py"
_mq_spec = importlib.util.spec_from_file_location("media_qc", MEDIA_QC_PATH)
assert _mq_spec is not None and _mq_spec.loader is not None
media_qc = importlib.util.module_from_spec(_mq_spec)
sys.modules["media_qc"] = media_qc
_mq_spec.loader.exec_module(media_qc)


class TestRenewSkillRouting(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_renew_route_"))
        self.cfg_dir = self.tmp / "gemini_config"
        self.state_dir = self.tmp / "state"
        self.cfg_dir.mkdir(parents=True)
        self.state_dir.mkdir(parents=True)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
            },
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_renew_positive_bilingual_and_legacy_game_triggers(self) -> None:
        positive_prompts = [
            "/renew ile bu eski Python 2 masaüstü aracını modern sisteme taşı.",
            "Modernize this legacy WinForms desktop application to a modern cross-platform stack.",
            "Bu eski programı yenile ve Windows-1254 kayıt dosyalarını bozmadan güncel çalışma zamanına uyarla.",
            "Port this old SDL1 classic game to modern WebGL while keeping original tick physics.",
            "Eski oyunu yenile, 4:3 piksel oranını ve kayıt dosyası uyumluluğunu koruyarak remaster yap.",
        ]
        for idx, prompt in enumerate(positive_prompts):
            with self.subTest(idx=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-renew-pos-{idx}", "prompt": prompt}
                )
                self.assertIn("injectSteps", res, f"Expected PreInvocation hint for: {prompt}")
                msg = res["injectSteps"][0]["ephemeralMessage"]
                self.assertIn("`renew`", msg)
                self.assertIn("skills/renew/SKILL.md", msg)

    def test_renew_rejects_auth_billing_and_filepath_false_positives(self) -> None:
        negative_prompts = [
            "Implement logic to renew JWT access tokens before expiration in auth_service.py.",
            "Auto-renew TLS certificates via ACME webhook.",
            "Fix subscription renewal retry handler in src/renew/worker.py.",
            "Bump express from 4.19.2 to 4.21.1 in package-lock.json.",
            "Giriş sayfasının tasarımını modernize et ve buton boşluklarını düzenle.",
            "Bu ses kaydını remaster yap ve arka plan hışırtısını temizle.",
        ]
        for idx, prompt in enumerate(negative_prompts):
            with self.subTest(idx=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-renew-neg-{idx}", "prompt": prompt}
                )
                msg = res.get("injectSteps", [{}])[0].get("ephemeralMessage", "")
                self.assertNotIn("`renew`", msg, f"False positive `renew` hint injected for: {prompt}")


@unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "ffmpeg/ffprobe required")
class TestMediaSalvageStillImageAndFidelityGate(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy-salvage-test-")
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_ffmpeg(self, args: list[str]) -> None:
        cmd = ["ffmpeg", "-hide_banner", "-nostdin", "-y"] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            self.fail(f"ffmpeg fixture setup failed: {proc.stderr}")

    def _sample_rgb(self, path: Path, x: int, y: int) -> tuple[int, int, int]:
        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-nostdin",
            "-i",
            str(path),
            "-vf",
            f"crop=1:1:{x}:{y}",
            "-frames:v",
            "1",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-",
        ]
        proc = subprocess.run(cmd, capture_output=True, check=False)
        self.assertEqual(proc.returncode, 0, f"RGB sample failed: {proc.stderr.decode('utf-8', 'replace')}")
        self.assertGreaterEqual(len(proc.stdout), 3)
        return proc.stdout[0], proc.stdout[1], proc.stdout[2]

    def test_still_image_check_and_odd_dimension_upscale_compare_with_aspect_guard(self) -> None:
        photo_png = self.tmp_dir / "scan_odd.png"
        photo_jpg = self.tmp_dir / "scan_odd_420.jpg"
        photo_webp = self.tmp_dir / "scan_odd_420.webp"
        odd_video_nut = self.tmp_dir / "odd_video_420.nut"
        corrupt_png = self.tmp_dir / "corrupt_scan.png"
        upscaled_2x = self.tmp_dir / "upscaled_2x.png"
        stretched_sar = self.tmp_dir / "stretched_nonsquare_sar.png"
        stretched_sq = self.tmp_dir / "stretched_square_sar.png"

        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=0.1:size=161x121:rate=10",
                "-frames:v",
                "1",
                str(photo_png),
            ]
        )
        # Odd-dimension 4:2:0 JPEG (`mjpeg`) and WebP (`webp`) must pass check_media (`TAA-1`, `CCA-2`)
        self._run_ffmpeg(
            ["-i", str(photo_png), "-pix_fmt", "yuvj420p", "-strict", "-1", "-q:v", "2", str(photo_jpg)]
        )
        self._run_ffmpeg(["-i", str(photo_png), "-c:v", "libwebp", "-pix_fmt", "yuv420p", str(photo_webp)])

        res_png = media_qc.check_media(photo_png)
        self.assertTrue(res_png["passed"], f"Expected odd-dim PNG to pass: {res_png['findings']}")
        res_jpg = media_qc.check_media(photo_jpg)
        self.assertTrue(res_jpg["passed"], f"Expected odd-dim 4:2:0 JPG to pass: {res_jpg['findings']}")
        res_webp = media_qc.check_media(photo_webp)
        self.assertTrue(res_webp["passed"], f"Expected odd-dim 4:2:0 WebP to pass: {res_webp['findings']}")

        # Non-mjpeg/webp 4:2:0 video with odd dimensions must fail check_media with MEDIA-2 (`TAA-1`)
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=0.3:size=161x121:rate=10",
                "-c:v",
                "rawvideo",
                "-pix_fmt",
                "yuv420p",
                str(odd_video_nut),
            ]
        )
        res_odd_vid = media_qc.check_media(odd_video_nut)
        self.assertFalse(res_odd_vid["passed"])
        self.assertIn("MEDIA-2", {f["rule_id"] for f in res_odd_vid["findings"]})

        # Truncated/corrupted still image payload must fail MEDIA-1 decode verification
        raw_png = photo_png.read_bytes()
        corrupt_png.write_bytes(raw_png[: max(48, len(raw_png) // 3)])
        res_corrupt = media_qc.check_media(corrupt_png)
        self.assertFalse(res_corrupt["passed"])
        self.assertIn("MEDIA-1", {f["rule_id"] for f in res_corrupt["findings"]})

        # Faithful 2x upscale (322x242, square SAR) preserves aspect ratio and passes compare_media
        self._run_ffmpeg(["-i", str(photo_png), "-vf", "scale=322:242:flags=lanczos,setsar=1", str(upscaled_2x)])
        cmp_ok = media_qc.compare_media(photo_png, upscaled_2x, min_ssim=0.88, min_psnr=25.0)
        self.assertTrue(cmp_ok["passed"], f"Expected 2x upscale to pass compare: {cmp_ok}")
        self.assertTrue(cmp_ok["aspect_ok"])
        self.assertLessEqual(cmp_ok["aspect_drift_ratio"], 0.02)

        # Distorted aspect ratio must fail BOTH via display_drift (setsar=1, `TAA-4`) and non_square_sar_drift
        self._run_ffmpeg(["-i", str(photo_png), "-vf", "scale=322:150:flags=lanczos,setsar=1", str(stretched_sq)])
        cmp_sq = media_qc.compare_media(photo_png, stretched_sq, min_ssim=0.40, min_psnr=10.0)
        self.assertFalse(cmp_sq["passed"])
        self.assertFalse(cmp_sq["aspect_ok"])
        self.assertGreater(cmp_sq["aspect_drift_ratio"], 0.15)

        self._run_ffmpeg(["-i", str(photo_png), "-vf", "scale=322:150:flags=lanczos", str(stretched_sar)])
        cmp_stretched = media_qc.compare_media(photo_png, stretched_sar, min_ssim=0.40, min_psnr=10.0)
        self.assertFalse(cmp_stretched["passed"])
        self.assertFalse(cmp_stretched["aspect_ok"])
        self.assertEqual(
            media_qc.main(["compare", str(photo_png), str(stretched_sq), "--min-ssim", "0.40", "--min-psnr", "10.0"]),
            1,
        )
        cmp_allowed = media_qc.compare_media(
            photo_png, stretched_sq, min_ssim=0.40, min_psnr=10.0, allow_aspect_change=True
        )
        self.assertTrue(cmp_allowed["passed"])

    def test_anamorphic_normalization_exif_orientation_and_truncated_video_duration_guard(self) -> None:
        # 1. Anamorphic 320x200 (SAR 5:6 -> 4:3 display) normalized to square-pixel 320x240 (SAR 1:1 -> 4:3) (`SGA-3`)
        anamorphic_mkv = self.tmp_dir / "dos_320x200_sar5_6.mkv"
        square_4_3_mp4 = self.tmp_dir / "norm_320x240_sar1.mp4"
        truncated_mp4 = self.tmp_dir / "truncated_cand.mp4"

        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=1.2:size=320x200:rate=10",
                "-vf",
                "setsar=5/6",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(anamorphic_mkv),
            ]
        )
        self._run_ffmpeg(
            [
                "-i",
                str(anamorphic_mkv),
                "-vf",
                "scale=320:240:flags=lanczos,setsar=1",
                "-c:v",
                "libx264",
                "-crf",
                "12",
                "-pix_fmt",
                "yuv420p",
                str(square_4_3_mp4),
            ]
        )
        cmp_anamorphic = media_qc.compare_media(anamorphic_mkv, square_4_3_mp4, min_ssim=0.90, min_psnr=28.0)
        self.assertTrue(cmp_anamorphic["aspect_ok"], f"Anamorphic->square 4:3 normalization failed: {cmp_anamorphic}")
        self.assertTrue(cmp_anamorphic["passed"], f"Expected anamorphic normalization to pass: {cmp_anamorphic}")

        # 2. Truncated candidate video (0.3s vs 1.2s reference) must fail duration_ok unless allow_trim=True (`SFH-4`)
        self._run_ffmpeg(
            [
                "-i",
                str(square_4_3_mp4),
                "-t",
                "0.3",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(truncated_mp4),
            ]
        )
        cmp_trunc = media_qc.compare_media(square_4_3_mp4, truncated_mp4, min_ssim=0.50, min_psnr=15.0)
        self.assertFalse(cmp_trunc["duration_ok"])
        self.assertFalse(cmp_trunc["passed"])
        cmp_trimmed = media_qc.compare_media(
            square_4_3_mp4, truncated_mp4, min_ssim=0.50, min_psnr=15.0, allow_trim=True
        )
        self.assertTrue(cmp_trimmed["duration_ok"])

        # 3. EXIF Orientation=6 (90° CW) JPEG vs upright auto-transposed PNG must pass aspect & SSIM (`SGA-12`)
        raw_jpg = self.tmp_dir / "raw_160x100.jpg"
        exif6_jpg = self.tmp_dir / "exif6_portrait.jpg"
        upright_png = self.tmp_dir / "upright_100x160.png"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=0.1:size=160x100:rate=10",
                "-frames:v",
                "1",
                "-q:v",
                "2",
                str(raw_jpg),
            ]
        )
        tiff_ifd = (
            b"II"
            + struct.pack("<HI", 42, 8)
            + struct.pack("<H", 1)
            + struct.pack("<HHII", 0x0112, 3, 1, 6)
            + struct.pack("<I", 0)
        )
        exif_payload = b"Exif\x00\x00" + tiff_ifd
        app1_seg = b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload
        jb = raw_jpg.read_bytes()
        exif6_jpg.write_bytes(jb[:2] + app1_seg + jb[2:])
        self._run_ffmpeg(["-i", str(exif6_jpg), "-frames:v", "1", str(upright_png)])

        cmp_exif = media_qc.compare_media(exif6_jpg, upright_png, min_ssim=0.97, min_psnr=35.0)
        self.assertTrue(cmp_exif["aspect_ok"], f"EXIF-6 aspect lock failed: {cmp_exif}")
        self.assertTrue(cmp_exif["passed"], f"EXIF-6 comparison failed: {cmp_exif}")

    def test_salvage_recovers_truncated_wav_header_blocks_inplace_and_fails_on_garbage(self) -> None:
        valid_wav = self.tmp_dir / "valid.wav"
        corrupt_wav = self.tmp_dir / "truncated_header.wav"
        salvaged_wav = self.tmp_dir / "salvaged.wav"
        salvaged_cli_wav = self.tmp_dir / "salvaged_cli.wav"
        garbage_mp4 = self.tmp_dir / "garbage.mp4"
        garbage_out = self.tmp_dir / "garbage_out.mp4"

        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=48000:duration=2.0",
                "-af",
                "volume=-6dB",
                "-c:a",
                "pcm_s16le",
                str(valid_wav),
            ]
        )
        raw = bytearray(valid_wav.read_bytes())
        data_idx = raw.index(b"data")
        # Corrupt the WAV data chunk length to 32 bytes (~0.0003s) while 2.0s of PCM samples remain intact
        raw[data_idx + 4 : data_idx + 8] = (32).to_bytes(4, "little")
        corrupt_wav.write_bytes(bytes(raw))

        # Confirm standard probe sees truncated duration (< 0.05s) before salvage
        pre_info = media_qc.probe_media(corrupt_wav)
        self.assertLess(pre_info["duration_sec"], 0.05)

        # Non-destructive rule: in-place overwrite must raise ValueError
        with self.assertRaises(ValueError):
            media_qc.salvage_media(corrupt_wav, corrupt_wav)

        res = media_qc.salvage_media(corrupt_wav, salvaged_wav)
        self.assertTrue(res["passed"], f"Expected WAV header salvage to pass: {res}")
        self.assertEqual(res["mode"], "stream_copy")
        self.assertEqual(res["output_decode_errors"], 0)
        self.assertGreaterEqual(res["recovered_duration_sec"], 1.95)
        self.assertEqual(media_qc.main(["salvage", str(corrupt_wav), str(salvaged_cli_wav), "--json"]), 0)

        # Unrecoverable garbage container must fail closed (exit 1), never pass silently
        garbage_mp4.write_bytes(b"CORRUPT_NON_MEDIA_PAYLOAD_BYTES" * 128)
        bad_res = media_qc.salvage_media(garbage_mp4, garbage_out)
        self.assertFalse(bad_res["passed"])
        self.assertEqual(media_qc.main(["salvage", str(garbage_mp4), str(garbage_out)]), 1)

    def test_salvage_av_container_remux_and_still_bitmap_reencode_opt_in(self) -> None:
        # 1. Positive Audio+Video container salvage (`stream_copy`) preserving both streams (`TAA-3`)
        src_ts = self.tmp_dir / "broadcast_clip.ts"
        salvaged_mp4 = self.tmp_dir / "salvaged_clip.mp4"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=1.0:size=160x120:rate=10",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=48000:duration=1.0",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                "-b:a",
                "128k",
                str(src_ts),
            ]
        )
        av_res = media_qc.salvage_media(src_ts, salvaged_mp4)
        self.assertTrue(av_res["passed"], f"Expected A/V container stream_copy salvage to pass: {av_res}")
        self.assertEqual(av_res["mode"], "stream_copy")
        av_probe = media_qc.probe_media(salvaged_mp4)
        self.assertEqual(len(av_probe["video_streams"]), 1)
        self.assertEqual(len(av_probe["audio_streams"]), 1)

        # 2. Single-frame bitmap salvage requires --allow-reencode (`SGA-1`, `TAA-2`, `CCA-1`)
        src_tif = self.tmp_dir / "archival_scan.tiff"
        out_png_blocked = self.tmp_dir / "salvaged_blocked.png"
        out_png_ok = self.tmp_dir / "salvaged_reencoded.png"
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=0.1:size=140x100:rate=10",
                "-frames:v",
                "1",
                "-c:v",
                "tiff",
                str(src_tif),
            ]
        )
        no_re = media_qc.salvage_media(src_tif, out_png_blocked, allow_reencode=False)
        self.assertFalse(no_re["passed"])
        self.assertEqual(no_re["mode"], "reencode_required")
        self.assertFalse(out_png_blocked.exists())

        cli_rc = media_qc.main(["salvage", str(src_tif), str(out_png_ok), "--allow-reencode", "--json"])
        self.assertEqual(cli_rc, 0)
        self.assertTrue(out_png_ok.is_file())
        re_probe = media_qc.probe_media(out_png_ok)
        self.assertEqual(re_probe["video_streams"][0]["width"], 140)
        self.assertEqual(re_probe["video_streams"][0]["height"], 100)

    def test_ab_sheet_generates_side_by_side_comparison_png_for_still_video_and_audio(self) -> None:
        ref_png = self.tmp_dir / "ref_red.png"
        cand_png = self.tmp_dir / "cand_blue_2x.png"
        ab_still = self.tmp_dir / "ab_still.png"
        ref_mp4 = self.tmp_dir / "ref.mp4"
        cand_mp4 = self.tmp_dir / "cand.mp4"
        ab_video = self.tmp_dir / "ab_video.png"
        ref_wav = self.tmp_dir / "ref_tone.wav"
        cand_wav = self.tmp_dir / "cand_tone.wav"
        ab_audio = self.tmp_dir / "ab_audio_spec.png"

        # Distinct pure-red reference vs pure-blue candidate to verify left/right frame separation (`TAA-6`)
        self._run_ffmpeg(
            ["-f", "lavfi", "-i", "color=c=red:s=120x90:d=0.1", "-frames:v", "1", str(ref_png)]
        )
        self._run_ffmpeg(
            ["-f", "lavfi", "-i", "color=c=blue:s=240x180:d=0.1", "-frames:v", "1", str(cand_png)]
        )

        # In-place overwrite blocked for BOTH reference and candidate (`TAA-5`)
        with self.assertRaises(ValueError):
            media_qc.extract_ab_sheet(ref_png, cand_png, ref_png)
        with self.assertRaises(ValueError):
            media_qc.extract_ab_sheet(ref_png, cand_png, cand_png)
        self.assertEqual(media_qc.main(["ab-sheet", str(ref_png), str(cand_png), str(cand_png)]), 2)

        res_still = media_qc.extract_ab_sheet(ref_png, cand_png, ab_still, tile_width=240, samples=1)
        self.assertEqual(res_still["modality"], "visual")
        self.assertTrue(ab_still.is_file())
        self.assertEqual(ab_still.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
        ab_info = media_qc.probe_media(ab_still)
        self.assertGreaterEqual(ab_info["video_streams"][0]["width"], 480)
        left_r, left_g, left_b = self._sample_rgb(ab_still, 60, 45)
        right_r, right_g, right_b = self._sample_rgb(ab_still, 360, 45)
        self.assertGreater(left_r, 180)
        self.assertLess(left_b, 60)
        self.assertGreater(right_b, 180)
        self.assertLess(right_r, 60)

        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=1.2:size=160x120:rate=10",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(ref_mp4),
            ]
        )
        self._run_ffmpeg(
            [
                "-i",
                str(ref_mp4),
                "-vf",
                "scale=320:240:flags=lanczos",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                str(cand_mp4),
            ]
        )
        self.assertEqual(
            media_qc.main(
                ["ab-sheet", str(ref_mp4), str(cand_mp4), str(ab_video), "--tile-width", "200", "--samples", "3"]
            ),
            0,
        )
        ab_vid_info = media_qc.probe_media(ab_video)
        self.assertGreaterEqual(ab_vid_info["video_streams"][0]["width"], 400)
        self.assertGreaterEqual(ab_vid_info["video_streams"][0]["height"], 400)

        # Audio-only spectrogram side-by-side A/B sheet (`SGA-4`)
        self._run_ffmpeg(
            ["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=0.6", str(ref_wav)]
        )
        self._run_ffmpeg(
            ["-f", "lavfi", "-i", "sine=frequency=880:sample_rate=48000:duration=0.6", str(cand_wav)]
        )
        res_audio_ab = media_qc.extract_ab_sheet(ref_wav, cand_wav, ab_audio, tile_width=240)
        self.assertEqual(res_audio_ab["modality"], "audio_spectrogram")
        self.assertTrue(ab_audio.is_file())
        self.assertGreaterEqual(media_qc.probe_media(ab_audio)["video_streams"][0]["width"], 480)

    def test_security_boundaries_loudnorm_metadata_playlist_hardlink_symlink_and_dash_paths(self) -> None:
        # 1. `SBV-1`: Crafted loudnorm JSON in container metadata must never inject filtergraph stages
        injected_marker = self.tmp_dir / "injected_side_effect.txt"
        crafted_wav = self.tmp_dir / "crafted_meta.wav"
        mastered_wav = self.tmp_dir / "mastered_safe.wav"
        fake_json = (
            '{"input_i":"-18.0","input_tp":"-2.0","input_lra":"5.0",'
            f'"input_thresh":"-28.0","target_offset":"0.0,ametadata=mode=print:file={injected_marker}"}}'
        )
        self._run_ffmpeg(
            [
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:sample_rate=48000:duration=1.2",
                "-af",
                "volume=-12dB",
                "-metadata",
                f"comment={fake_json}",
                "-c:a",
                "pcm_s16le",
                str(crafted_wav),
            ]
        )
        m_res = media_qc.master_audio(crafted_wav, mastered_wav)
        self.assertTrue(m_res["passed"], f"Expected master_audio to ignore metadata spoof and pass: {m_res}")
        self.assertFalse(injected_marker.exists(), "Filtergraph injection marker must never be created!")

        # 2. `SBV-2`: Playlist/network manifest masquerading as local media file must be rejected
        fake_hls = self.tmp_dir / "spoof.mp4"
        fake_hls.write_text("#EXTM3U\n#EXTINF:5.0,\nhttp://127.0.0.1:9/segment.ts\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            media_qc.probe_media(fake_hls)
        with self.assertRaises(ValueError):
            media_qc.salvage_media(fake_hls, self.tmp_dir / "spoof_out.mp4")

        # Relative leading-dash filename must not be misinterpreted as an ffmpeg CLI flag
        prev_cwd = os.getcwd()
        try:
            os.chdir(self.tmp_dir)
            dash_wav = Path("-dash_clip.wav")
            shutil.copyfile(crafted_wav, self.tmp_dir / dash_wav)
            p_dash = media_qc.probe_media(dash_wav)
            self.assertEqual(len(p_dash["audio_streams"]), 1)
        finally:
            os.chdir(prev_cwd)

        # 3. `SBV-3` & `SBV-4`: Hardlink output alias and symlinked parent directory must be refused
        hardlink_alias = self.tmp_dir / "hardlink_alias.wav"
        os.link(crafted_wav, hardlink_alias)
        with self.assertRaises(ValueError):
            media_qc.salvage_media(crafted_wav, hardlink_alias)

        real_outside = self.tmp_dir / "outside_target"
        real_outside.mkdir()
        sym_parent = self.tmp_dir / "sym_parent"
        sym_parent.symlink_to(real_outside)
        with self.assertRaises(ValueError):
            media_qc.salvage_media(crafted_wav, sym_parent / "escaped.wav")


class TestMediaStudioExpandedRoutingAndPorterParity(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_media_route_"))
        self.cfg_dir = self.tmp / "gemini_config"
        self.state_dir = self.tmp / "state"
        self.cfg_dir.mkdir(parents=True)
        self.state_dir.mkdir(parents=True)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
            },
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_media_studio_salvage_photo_and_upscale_triggers_without_generic_enhance_leak(self) -> None:
        positive_prompts = [
            "Bozuk ses dosyasını aslını bozmadan düzelt ve kırık WAV başlığını kurtar.",
            "Eski fotoğrafın çiziklerini temizle ve kalitesini orijinali bozmadan yükselt.",
            "Salvage this corrupted MP4 container and upscale the low-resolution archival video.",
            "Restore this damaged scanned photo and repair JPEG blocking artifacts.",
            "Bu eski ses kaydını remaster yap ve arka plan hışırtısını temizle.",
        ]
        for idx, prompt in enumerate(positive_prompts):
            with self.subTest(idx=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-ms-exp-pos-{idx}", "prompt": prompt}
                )
                self.assertIn("injectSteps", res, f"Expected media-studio hint for: {prompt}")
                msg = res["injectSteps"][0]["ephemeralMessage"]
                self.assertIn("`media-studio`", msg)
                self.assertNotIn("`renew`", msg)

        negative_prompts = [
            "Enhance SQL query execution plan on the invoices table.",
            "Enhance keyboard navigation and form validation in login.tsx.",
            "Session önbelleğini temizle ve süresi dolmuş oturum anahtarlarını sil.",
            "Bozuk kayıtları veritabanından düzelt ve eksik indeksleri yeniden oluştur.",
        ]
        for idx, prompt in enumerate(negative_prompts):
            with self.subTest(idx=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-ms-exp-neg-{idx}", "prompt": prompt}
                )
                msg = res.get("injectSteps", [{}])[0].get("ephemeralMessage", "")
                self.assertNotIn("`media-studio`", msg, f"False positive media-studio hint for: {prompt}")

    def test_porter_cursor_export_includes_renew_and_media_studio_reference_subfile(self) -> None:
        from porter.emitters.cursor import CursorEmitter
        from porter.manifest import ManifestEngine
        from porter.sanitizer import ConstitutionalSanitizer

        # Verify $HOME and ${HOME} ~/.gemini/config export sanitization (`CCA-4`)
        sample = (
            'for p in "$HOME/.gemini/config/skills/media-studio/scripts/media_qc.py" '
            '"${HOME}/.gemini/config/skills/media-studio/scripts/media_qc.py"; do echo "$p"; done'
        )
        sanitized = ConstitutionalSanitizer.sanitize_for_export(sample, target="cursor")
        self.assertNotIn(".gemini/config", sanitized)
        self.assertIn("skills/media-studio/scripts/media_qc.py", sanitized)

        manifest = ManifestEngine(REPO_ROOT).build_manifest(deterministic=True)
        skill_names = {s["name"] for s in manifest.skills}
        self.assertIn("renew", skill_names)
        self.assertIn("media-studio", skill_names)

        out_dir = self.tmp / "cursor_export"
        plan, _ = CursorEmitter.plan(manifest, out_dir)
        self.assertIn(out_dir / ".cursor/skills/renew/SKILL.md", plan)
        self.assertIn(
            out_dir / ".cursor/skills/media-studio/references/salvage-and-enhancement.md",
            plan,
        )
        ms_rule = plan[out_dir / ".cursor/rules/skill-media-studio.mdc"]
        self.assertIn(".cursor/skills/media-studio/references/salvage-and-enhancement.md", ms_rule)
        for out_path, body in plan.items():
            if out_path.suffix == ".mdc" and out_path.name != "99-harness-index.mdc":
                self.assertNotIn(
                    ".gemini/config",
                    body,
                    f"Unsanitized .gemini/config path leaked into Cursor rule {out_path}",
                )
        salvage_ref = (REPO_ROOT / "skills/media-studio/references/salvage-and-enhancement.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(
            ".gemini/config",
            ConstitutionalSanitizer.sanitize_for_export(salvage_ref, target="cursor"),
        )


if __name__ == "__main__":
    unittest.main()
