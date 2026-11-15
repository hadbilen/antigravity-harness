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
                msg = res["injectSteps"][0]["systemMessage"]["systemMessage"]
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
                msg = res.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
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
                msg = res["injectSteps"][0]["systemMessage"]["systemMessage"]
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
                msg = res.get("injectSteps", [{}])[0].get("systemMessage", {}).get("systemMessage", "")
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


def _write_test_png_rgba(path: Path, width: int, height: int, pixels: bytes) -> None:
    """Write an uncompressed/zlib RGBA PNG with zero external dependencies beyond stdlib."""
    import binascii
    import zlib

    assert len(pixels) == width * height * 4

    def _chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", binascii.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    rows = bytearray()
    stride = width * 4
    for y in range(height):
        rows.append(0)
        rows.extend(pixels[y * stride : (y + 1) * stride])
    idat = zlib.compress(bytes(rows))
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b""))


def _write_sine_wav(
    path: Path,
    duration_sec: float,
    freq_hz: float = 440.0,
    amp: float = 0.2,
    sample_rate: int = 48000,
    fade_ms: float = 0.0,
) -> None:
    import math
    import wave

    n_frames = max(1, int(round(duration_sec * sample_rate)))
    fade_frames = int(round(fade_ms * sample_rate / 1000.0))
    buf = bytearray()
    for i in range(n_frames):
        val = amp * math.sin(2.0 * math.pi * freq_hz * (i / sample_rate)) if amp > 0.0 else 0.0
        if fade_frames > 0:
            if i < fade_frames:
                val *= 0.5 * (1.0 - math.cos(math.pi * i / fade_frames))
            elif i >= n_frames - fade_frames:
                rem = n_frames - 1 - i
                val *= 0.5 * (1.0 - math.cos(math.pi * rem / fade_frames))
        sample_i16 = max(-32767, min(32767, int(round(val * 32767.0))))
        buf.extend(struct.pack("<h", sample_i16))
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(bytes(buf))


class TestGameAudioAndPixelArtQC(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_game_media_"))
        self.ffmpeg = shutil.which("ffmpeg")
        self.ffprobe = shutil.which("ffprobe")
        self.assertIsNotNone(self.ffmpeg, "ffmpeg binary must be available on PATH")
        self.assertIsNotNone(self.ffprobe, "ffprobe binary must be available on PATH")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_game_sfx_short_clip_peak_normalization_vorbis_and_silence_guard(self) -> None:
        short_wav = self.tmp / "click_150ms.wav"
        silent_wav = self.tmp / "mute_150ms.wav"
        _write_sine_wav(short_wav, duration_sec=0.15, freq_hz=660.0, amp=0.08, fade_ms=8.0)
        _write_sine_wav(silent_wav, duration_sec=0.15, freq_hz=440.0, amp=0.0)

        # Default loudnorm cannot measure <400ms gated LUFS and must still reject silent/short inputs explicitly.
        with self.assertRaises(ValueError):
            media_qc.master_audio(short_wav, self.tmp / "loudnorm_fail.wav")

        # Default ogg codec preserves libopus backwards compatibility.
        sfx_opus = self.tmp / "click_opus.ogg"
        res_opus = media_qc.master_audio(short_wav, sfx_opus, game_sfx=True)
        self.assertTrue(res_opus["passed"], res_opus)
        self.assertEqual(res_opus["mode"], "peak_game_sfx")
        self.assertEqual(media_qc.probe_media(sfx_opus)["audio_streams"][0]["codec_name"], "opus")

        # Opt-in --ogg-codec vorbis emits libvorbis for game engines (Unity/Godot/Unreal).
        sfx_vorbis = self.tmp / "click_vorbis.ogg"
        res_vorbis = media_qc.master_audio(short_wav, sfx_vorbis, game_sfx=True, ogg_codec="vorbis")
        self.assertTrue(res_vorbis["passed"], res_vorbis)
        self.assertEqual(media_qc.probe_media(sfx_vorbis)["audio_streams"][0]["codec_name"], "vorbis")

        with self.assertRaises(ValueError):
            media_qc.master_audio(short_wav, self.tmp / "bad.wav", ogg_codec="vorbis")

        # Audible <150ms click passes check_media(..., game_sfx=True), whereas genuinely silent clip still fails MEDIA-3.
        self.assertEqual(media_qc.main(["check", str(sfx_vorbis), "--game-sfx", "--json"]), 0)
        res_mute = media_qc.check_media(silent_wav, game_sfx=True)
        self.assertFalse(res_mute["passed"])
        self.assertTrue(any(f["rule_id"] == "MEDIA-3" for f in res_mute["findings"]))

    def test_audio_loop_seam_detection_and_zero_crossing_trim(self) -> None:
        seamless_wav = self.tmp / "loop_seamless.wav"
        cut_wav = self.tmp / "loop_cut.wav"
        trimmed_wav = self.tmp / "loop_trimmed.wav"

        _write_sine_wav(seamless_wav, duration_sec=1.0, freq_hz=440.0, amp=0.20)
        # 0.5005s at 440Hz ends mid-cycle with a large sample step & slope discontinuity.
        _write_sine_wav(cut_wav, duration_sec=0.5005, freq_hz=440.0, amp=0.20)

        res_ok = media_qc.check_media(seamless_wav, check_loop=True)
        self.assertTrue(res_ok["passed"], res_ok)
        self.assertTrue(res_ok["loop_metrics"]["seamless"])

        res_bad = media_qc.check_media(cut_wav, check_loop=True)
        self.assertFalse(res_bad["passed"])
        self.assertEqual(res_bad["findings"][0]["rule_id"], "GAME-1")

        m_trim = media_qc.master_audio(cut_wav, trimmed_wav, target_lufs=-16.0, trim_loop=True)
        self.assertTrue(m_trim["passed"], m_trim)
        self.assertEqual(m_trim["trim_loop"]["method"], "zero_crossing")
        res_trimmed_check = media_qc.check_media(trimmed_wav, check_loop=True)
        self.assertTrue(res_trimmed_check["passed"], res_trimmed_check)

    def test_pixel_art_nearest_neighbor_and_lanczos_rejection(self) -> None:
        ref_8 = self.tmp / "sprite_8x8.png"
        good_32 = self.tmp / "sprite_32_neighbor.png"
        blur_32 = self.tmp / "sprite_32_lanczos.png"
        odd_25 = self.tmp / "sprite_25_neighbor.png"
        ab_out = self.tmp / "sprite_ab.png"

        px = bytearray()
        for y in range(8):
            for x in range(8):
                if 2 <= x <= 5 and 2 <= y <= 5:
                    px.extend((64, 210, 180, 255))
                else:
                    px.extend((64, 210, 180, 0))
        _write_test_png_rgba(ref_8, 8, 8, bytes(px))

        for out_p, w, h, flg in (
            (good_32, 32, 32, "neighbor"),
            (blur_32, 32, 32, "lanczos"),
            (odd_25, 25, 25, "neighbor"),
        ):
            proc = subprocess.run(
                [self.ffmpeg, "-y", "-i", str(ref_8), "-vf", f"scale={w}:{h}:flags={flg}", str(out_p)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

        self.assertTrue(media_qc.check_media(good_32, pixel_art=True)["passed"])
        blur_chk = media_qc.check_media(blur_32, pixel_art=True)
        self.assertFalse(blur_chk["passed"])
        self.assertTrue(any(f["rule_id"] == "GAME-2" for f in blur_chk["findings"]))

        cmp_ok = media_qc.compare_media(ref_8, good_32, min_ssim=0.99, min_psnr=40.0, pixel_art=True)
        self.assertTrue(cmp_ok["passed"], cmp_ok)
        self.assertEqual(cmp_ok["scale_factor"], 4)
        self.assertEqual(cmp_ok["non_uniform_blocks"], 0)

        cmp_blur = media_qc.compare_media(ref_8, blur_32, min_ssim=0.80, min_psnr=20.0, pixel_art=True)
        self.assertFalse(cmp_blur["passed"])
        self.assertFalse(cmp_blur["block_uniform_ok"])

        cmp_odd = media_qc.compare_media(ref_8, odd_25, min_ssim=0.50, min_psnr=10.0, pixel_art=True)
        self.assertFalse(cmp_odd["passed"])
        self.assertFalse(cmp_odd["integer_scale_ok"])

        ab_res = media_qc.extract_ab_sheet(ref_8, good_32, ab_out, tile_width=64, samples=1, pixel_art=True)
        self.assertTrue(ab_res["pixel_art"])
        self.assertTrue(ab_out.is_file())

    def test_sprite_atlas_pot_tile_alignment_alpha_bleed_and_edge_touch(self) -> None:
        # Valid 64x64 atlas (2x2 tiles of 32x32) with inner sprite padding and dilated transparent RGB.
        good_atlas = self.tmp / "atlas_64x64_ok.png"
        px_ok = bytearray([220, 180, 90, 0] * (64 * 64))
        for ty in range(2):
            for tx in range(2):
                for y in range(ty * 32 + 4, (ty + 1) * 32 - 4):
                    for x in range(tx * 32 + 4, (tx + 1) * 32 - 4):
                        off = (y * 64 + x) * 4
                        px_ok[off : off + 4] = bytes((220, 180, 90, 255))
        _write_test_png_rgba(good_atlas, 64, 64, bytes(px_ok))

        res_ok = media_qc.check_media(good_atlas, sprite_atlas=True, tile_size="32x32", require_pot=True)
        self.assertTrue(res_ok["passed"], res_ok)

        # Unaligned tile size -> GAME-3
        res_bad_tile = media_qc.check_media(good_atlas, sprite_atlas=True, tile_size="24x24")
        self.assertFalse(res_bad_tile["passed"])
        self.assertTrue(any(f["rule_id"] == "GAME-3" for f in res_bad_tile["findings"]))

        # Non-Power-of-Two 96x64 atlas passes tile_size 32x32 without require_pot, fails with require_pot=True.
        npot_atlas = self.tmp / "atlas_96x64.png"
        px_npot = bytearray([200, 200, 200, 0] * (96 * 64))
        for y in range(6, 26):
            for x in range(6, 26):
                off = (y * 96 + x) * 4
                px_npot[off : off + 4] = bytes((200, 200, 200, 255))
        _write_test_png_rgba(npot_atlas, 96, 64, bytes(px_npot))
        self.assertTrue(media_qc.check_media(npot_atlas, sprite_atlas=True, tile_size="32x32")["passed"])
        npot_fail = media_qc.check_media(npot_atlas, sprite_atlas=True, tile_size="32x32", require_pot=True)
        self.assertFalse(npot_fail["passed"])
        self.assertTrue(any(f["rule_id"] == "GAME-3" for f in npot_fail["findings"]))

        # Un-dilated white sprite over (0, 0, 0, 0) black transparent background triggers alpha-bleed GAME-3.
        bleed_atlas = self.tmp / "atlas_bleed.png"
        px_bleed = bytearray([0, 0, 0, 0] * (64 * 64))
        for y in range(8, 24):
            for x in range(8, 24):
                off = (y * 64 + x) * 4
                px_bleed[off : off + 4] = bytes((255, 255, 255, 255))
        _write_test_png_rgba(bleed_atlas, 64, 64, bytes(px_bleed))
        bleed_fail = media_qc.check_media(bleed_atlas, sprite_atlas=True, check_alpha_bleed=True)
        self.assertFalse(bleed_fail["passed"])
        self.assertGreater(bleed_fail["game_visual_metrics"]["alpha_bleed_pixels"], 0)

        # Full-bleed edge-touching tile borders fail by default and pass with --allow-edge-touch.
        edge_atlas = self.tmp / "atlas_edge.png"
        px_edge = bytearray((220, 180, 90, 255)) * (64 * 64)
        _write_test_png_rgba(edge_atlas, 64, 64, bytes(px_edge))
        edge_fail = media_qc.check_media(edge_atlas, sprite_atlas=True, tile_size="32x32")
        self.assertFalse(edge_fail["passed"])
        self.assertGreater(edge_fail["game_visual_metrics"]["edge_touch_pixels"], 0)
        self.assertTrue(
            media_qc.check_media(edge_atlas, sprite_atlas=True, tile_size="32x32", allow_edge_touch=True)["passed"]
        )

    def test_game_engineering_profiles_rea_brownfield_and_vibecoder_bridge(self) -> None:
        ge_text = (REPO_ROOT / "skills" / "game-engineering" / "SKILL.md").read_text(encoding="utf-8")
        vc_text = (REPO_ROOT / "skills" / "vibecoder" / "SKILL.md").read_text(encoding="utf-8")
        hs_text = (REPO_ROOT / "skills" / "harness" / "SKILL.md").read_text(encoding="utf-8")
        ms_text = (REPO_ROOT / "skills" / "media-studio" / "SKILL.md").read_text(encoding="utf-8")

        for needle in (
            "Profile A",
            "Profile B",
            "schemaVersion",
            "Input Buffering",
            "Asset Preload",
            "reverse-engineer-anything",
            "rea_rea",
            "diagnosing-bugs",
            "sweetspot",
            "skills/renew/SKILL.md",
            "skills/media-studio/SKILL.md",
        ):
            self.assertIn(needle, ge_text)

        self.assertIn("skills/game-engineering/SKILL.md", vc_text)
        self.assertIn("skills/media-studio/SKILL.md", vc_text)
        self.assertIn('"mode": "game"', hs_text)
        self.assertIn("skills/game-engineering/SKILL.md", hs_text)
        self.assertIn("skills/media-studio/SKILL.md", hs_text)
        for needle in ("--game-sfx", "--ogg-codec vorbis", "--check-loop", "--trim-loop", "--pixel-art", "--sprite-atlas"):
            self.assertIn(needle, ms_text)


class TestW3MediaQcHardeningAndEdgeBoundaries(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_w3_media_"))
        self.ffmpeg = shutil.which("ffmpeg")
        self.ffprobe = shutil.which("ffprobe")
        self.assertIsNotNone(self.ffmpeg, "ffmpeg binary must be available on PATH")
        self.assertIsNotNone(self.ffprobe, "ffprobe binary must be available on PATH")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_analyze_audio_loop_seam_non_finite_samples_fail_explicitly(self) -> None:
        dummy_wav = self.tmp / "dummy.wav"
        _write_sine_wav(dummy_wav, duration_sec=0.1, freq_hz=440.0, amp=0.1)
        for bad_val in (float("nan"), float("inf")):
            with self.subTest(bad_val=bad_val), mock.patch.object(
                media_qc,
                "_decode_audio_f32le",
                return_value=([0.0, bad_val, 0.1, 0.0], 1, 48000, 0.1),
            ):
                res = media_qc.analyze_audio_loop_seam(dummy_wav)
                self.assertFalse(res["seamless"])
                self.assertIsNone(res["seam_step"])
                self.assertIn("non-finite", res["reason"].lower())

        # Rotated 90-deg stream dimensions swap displayed width/height for atlas geometry & pixel buffer decoding
        rot_stream = {"width": 16, "height": 8, "rotation": 90}
        self.assertEqual(media_qc._effective_dimensions(rot_stream), (8, 16))
        self.assertEqual(media_qc._effective_dimensions({"width": 16, "height": 8, "rotation": -270}), (8, 16))
        self.assertEqual(media_qc._effective_dimensions({"width": 16, "height": 8, "rotation": 180}), (16, 8))

    def test_antiphase_stereo_trim_loop_uses_per_channel_zero_crossings(self) -> None:
        import math
        import wave

        sr = 48000
        n_frames = int(round(0.5005 * sr))
        raw = bytearray()
        for i in range(n_frames):
            val = 0.25 * math.sin(2.0 * math.pi * 440.0 * (i / sr))
            l_s = max(-32767, min(32767, int(round(val * 32767.0))))
            r_s = max(-32767, min(32767, int(round(-val * 32767.0))))
            raw.extend(struct.pack("<hh", l_s, r_s))
        anti_wav = self.tmp / "antiphase_stereo.wav"
        with wave.open(str(anti_wav), "wb") as wf:
            wf.setnchannels(2)
            wf.setsampwidth(2)
            wf.setframerate(sr)
            wf.writeframes(bytes(raw))

        trimmed = self.tmp / "antiphase_trimmed.wav"
        m_res = media_qc.master_audio(anti_wav, trimmed, target_lufs=-16.0, trim_loop=True)
        self.assertTrue(m_res["passed"], m_res)
        self.assertEqual(m_res["trim_loop"]["method"], "zero_crossing")
        self.assertTrue(media_qc.check_media(trimmed, check_loop=True)["passed"])

    def test_multiframe_apng_semi_alpha_and_multistream_mkv(self) -> None:
        # 1. Multi-frame animated APNG: frame 1 crisp, frame 2 has semi-transparent pixels -> caught by pixel_art=True
        f1 = self.tmp / "apng_f1.png"
        f2 = self.tmp / "apng_f2.png"
        _write_test_png_rgba(f1, 8, 8, bytes((40, 180, 90, 255)) * 64)
        _write_test_png_rgba(f2, 8, 8, bytes((40, 180, 90, 128)) * 64)
        apng = self.tmp / "anim.apng"
        proc_apng = subprocess.run(
            [self.ffmpeg, "-y", "-framerate", "2", "-i", str(self.tmp / "apng_f%d.png"), "-plays", "0", str(apng)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_apng.returncode, 0, proc_apng.stderr)
        chk_apng = media_qc.check_media(apng, pixel_art=True)
        self.assertFalse(chk_apng["passed"])
        self.assertEqual(chk_apng["game_visual_metrics"]["frames_checked"], 2)
        self.assertTrue(any(f["rule_id"] == "GAME-2" for f in chk_apng["findings"]))

        # 2. Multi-stream MKV (2 video + 2 audio streams): -map 0:v:0 / -filter:a handle multi-stream containers cleanly
        multi_mkv = self.tmp / "multi_streams.mkv"
        proc_mkv = subprocess.run(
            [
                self.ffmpeg,
                "-y",
                "-f",
                "lavfi",
                "-i",
                "color=c=0x224466:s=64x64:d=0.6:r=10",
                "-f",
                "lavfi",
                "-i",
                "color=c=0x112233:s=32x32:d=0.6:r=10",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:duration=0.6:sample_rate=48000",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=660:duration=0.6:sample_rate=48000",
                "-map",
                "0:v",
                "-map",
                "1:v",
                "-map",
                "2:a",
                "-map",
                "3:a",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(multi_mkv),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_mkv.returncode, 0, proc_mkv.stderr)
        raw_frame = media_qc._decode_image_rgba_frames(multi_mkv, 64, 64, max_frames=1)
        self.assertEqual(len(raw_frame), 64 * 64 * 4)

        out_multi_mkv = self.tmp / "multi_norm.mkv"
        m_mkv = media_qc.master_audio(multi_mkv, out_multi_mkv, game_sfx=True, peak_db=-2.0)
        self.assertTrue(m_mkv["passed"], m_mkv)
        out_probe = media_qc.probe_media(out_multi_mkv)
        self.assertEqual(len(out_probe["audio_streams"]), 2)

    def test_odd_pixel_art_compare_5x5_and_identity_4x4(self) -> None:
        px5 = bytearray()
        for y in range(5):
            for x in range(5):
                px5.extend(((x * 45) % 256, (y * 50) % 256, 160, 255))
        ref5 = self.tmp / "spr5.png"
        cand10 = self.tmp / "spr10.png"
        _write_test_png_rgba(ref5, 5, 5, bytes(px5))
        proc5 = subprocess.run(
            [self.ffmpeg, "-y", "-i", str(ref5), "-vf", "scale=10:10:flags=neighbor", str(cand10)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc5.returncode, 0, proc5.stderr)
        res5 = media_qc.compare_media(ref5, cand10, min_ssim=0.99, min_psnr=40.0, pixel_art=True)
        self.assertTrue(res5["passed"], res5)
        self.assertEqual(res5["scale_factor"], 2)
        self.assertEqual(res5["non_uniform_blocks"], 0)

        ref4 = self.tmp / "spr4.png"
        _write_test_png_rgba(ref4, 4, 4, bytes((10, 120, 220, 255)) * 16)
        res4 = media_qc.compare_media(ref4, ref4, min_ssim=0.99, min_psnr=40.0, pixel_art=True)
        self.assertTrue(res4["passed"], res4)
        self.assertEqual(res4["scale_factor"], 1)

    def test_master_audio_rejects_muxed_trim_loop_and_consistent_sfx_bypass(self) -> None:
        muxed_mp4 = self.tmp / "muxed.mp4"
        proc = subprocess.run(
            [
                self.ffmpeg,
                "-y",
                "-f",
                "lavfi",
                "-i",
                "color=c=0x112233:s=64x64:d=0.6:r=10",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:duration=0.6:sample_rate=48000",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                str(muxed_mp4),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with self.assertRaises(ValueError):
            media_qc.master_audio(muxed_mp4, self.tmp / "muxed_trim.wav", trim_loop=True)

        short_wav = self.tmp / "short_150ms.wav"
        short_out = self.tmp / "short_150ms_norm.wav"
        _write_sine_wav(short_wav, duration_sec=0.15, freq_hz=550.0, amp=0.15, fade_ms=5.0)
        self.assertEqual(
            media_qc.main(["master-audio", str(short_wav), str(short_out), "--game-sfx", "--peak-db", "-2.0"]),
            0,
        )
        chk = media_qc.check_media(short_out, target_lufs=-14.0, lufs_tolerance=0.5, game_sfx=True)
        self.assertTrue(chk["passed"], chk)

    def test_parameter_validation_and_cli_game_gates(self) -> None:
        loop_wav = self.tmp / "loop_cli.wav"
        _write_sine_wav(loop_wav, duration_sec=1.0, freq_hz=440.0, amp=0.2)

        with self.assertRaises(ValueError):
            media_qc.check_media(loop_wav, max_true_peak=1.0)
        with self.assertRaises(ValueError):
            media_qc.master_audio(loop_wav, self.tmp / "bad_tp.wav", target_tp=0.5)
        with self.assertRaises(ValueError):
            media_qc.master_audio(loop_wav, self.tmp / "bad_pk.wav", peak_db=0.5)
        with self.assertRaises(ValueError):
            media_qc.compare_media(loop_wav, loop_wav, min_ssim=1.5)
        self.assertEqual(media_qc.main(["check", str(loop_wav), "--max-true-peak", "1.0"]), 2)
        self.assertEqual(media_qc.main(["check", str(loop_wav), "--check-loop", "--json"]), 0)

        atlas_ok = self.tmp / "atlas_cli.png"
        px = bytearray()
        for y in range(32):
            for x in range(32):
                lx, ly = x % 16, y % 16
                if 2 <= lx <= 13 and 2 <= ly <= 13:
                    px.extend((80, 200, 140, 255))
                else:
                    px.extend((0, 0, 0, 0))
        _write_test_png_rgba(atlas_ok, 32, 32, bytes(px))
        self.assertEqual(
            media_qc.main(["check", str(atlas_ok), "--pixel-art", "--sprite-atlas", "--tile-size", "16x16", "--require-pot", "--json"]),
            0,
        )

        ref8 = self.tmp / "ref8.png"
        cand32 = self.tmp / "cand32.png"
        ab_png = self.tmp / "ab_pixel.png"
        _write_test_png_rgba(ref8, 8, 8, bytes((220, 80, 40, 255)) * 64)
        proc = subprocess.run(
            [self.ffmpeg, "-y", "-i", str(ref8), "-vf", "scale=32:32:flags=neighbor", str(cand32)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(media_qc.main(["ab-sheet", str(ref8), str(cand32), str(ab_png), "--pixel-art"]), 0)
        self.assertTrue(ab_png.is_file() and ab_png.stat().st_size > 100)


if __name__ == "__main__":
    unittest.main()
