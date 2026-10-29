---
name: media-studio
description: >-
  High-fidelity audio, video, still image, and animated visual (MP4, WebM, Animated WebP, GIF, APNG, PNG, JPEG, TIFF,
  WAV, FLAC, Opus, AAC) synthesis, timeline editing, damaged-container salvage, archival restoration, fidelity-bounded
  upscaling, and broadcast/streaming mastering. Enforces the 4-stage Probe -> Plan -> Process -> Verify pipeline,
  stream-copy container salvage, two-pass EBU R128 loudness normalization, spectral/temporal denoising, debanding,
  two-pass palette generation, and objective quality gates (media_qc.py: probe, check, salvage, compare, ab-sheet,
  master-audio, keyframes). Invoke with /media-studio or when generating, editing, salvaging, restoring, upscaling,
  transcoding, or mastering audio, video, still photos, or animated visual files ("ses üret", "video üret", "ses düzenle",
  "video düzenle", "bozuk sesi/görüntüyü kurtar", "eski fotoğrafı onar", "ses kalitesini düzelt", "görüntü kalitesini
  artır", "gürültü temizle", "hareketli görsel", "mastering"). Not for zero-spec single-file UX discovery interviews
  (use 'vibecoder'), real-time 60 Hz interactive game simulation loops (use 'game-engineering'), or static architectural
  diagrams (use 'visualizer').
---

# Media Studio — Audio, Video, Still Image & Animated Visual Production, Salvage & Restoration Discipline

Guessing raw `ffmpeg` flags from memory, applying single-pass dynamic loudness filters that pump background noise, converting videos to 256-color GIFs without a custom palette, or re-encoding lossy streams without inspecting container metadata produces clipped audio, color-banded gradients, audio-video synchronization drift, and broken browser playback. This skill enforces a deterministic four-stage engineering pipeline (**Probe → Plan → Process → Verify**) across synthesis, timeline editing, signal restoration, and mastering.

---

## 1. The 4-Stage Deterministic Media Pipeline & Guardrails

Every audio, video, or animated visual task executes four ordered phases:

1. **Stage 1 — Pre-Flight Probe & Defect Diagnosis (`probe` & `check`):**
   * **Pre-Flight Missing-Binary Stop Rule (`ffmpeg` & `ffprobe`):** Verify `command -v ffmpeg && command -v ffprobe` before probing or processing media. If either binary is absent, halt immediately in `BLOCKED` status and ask the human operator to install `ffmpeg` — never download unpinned binaries or execute remote install scripts (`GEMINI.md` Rule 12).
   * For existing media files, never construct a filtergraph before inspecting the input stream layout and signal metrics:
     ```bash
     MEDIA_QC="skills/media-studio/scripts/media_qc.py"
     for _p in .claude .cursor .agents .aider; do [ -f "$MEDIA_QC" ] || MEDIA_QC="$_p/skills/media-studio/scripts/media_qc.py"; done
     [ -f "$MEDIA_QC" ] || MEDIA_QC="$HOME/.gemini/config/skills/media-studio/scripts/media_qc.py"
     [ -f "$MEDIA_QC" ] || MEDIA_QC="/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py"
     python3 "$MEDIA_QC" probe <input_path> --json
     python3 "$MEDIA_QC" check <input_path> --json
     ```
   * Record container format, video codec, dimensions, Sample Aspect Ratio (`SAR`), Display Aspect Ratio (`DAR`), pixel format (`pix_fmt`), color space (`color_space`, `color_transfer`, `color_primaries`), nominal vs. average frame rate (`r_frame_rate` vs. `avg_frame_rate` to detect Variable Frame Rate `VFR`), audio codec, sample rate, channel layout, integrated loudness (`LUFS`), True Peak (`dBTP`), Direct Current (`DC`) offset, and broadcast range outliers (`brng`).
2. **Stage 2 — Filtergraph & Synthesis Planning (`Plan`):**
   * **Non-Destructive File Discipline:** Never overwrite an input media file in place. Always write to a distinct output filename or staging path and verify the output before replacing any target file.
   * **Stream-Copy & Salvage First (`-c copy` / `salvage`):** When remuxing containers, stripping metadata, cutting on keyframe boundaries, or recovering truncated `.wav` headers / broken `.mp4`/`.mkv` timestamps without altering pixels or audio samples, use `-c copy` (via `python3 "$MEDIA_QC" salvage <input> <output>`) to preserve 100% of the source quality. Re-encode only when filtering, resizing, repairing signal defects, or changing codecs.
3. **Stage 3 — Execution (`Process`):**
   * Combine all video and audio transformations into a single unified `-filter_complex` pass (or a lossless float/raw pipe from `Python` into `ffmpeg`) so media never suffers multi-generation lossy re-compression.
4. **Stage 4 — Objective Quality Control & Visual Inspection (`Verify`):**
   * Run `python3 "$MEDIA_QC" check <output_path>` (resolving workspace, exported `.claude`/`.cursor`/`.agents`/`.aider`, installed global `~/.gemini/config/skills/media-studio/scripts/media_qc.py`, or system fallback `/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py`), plus `compare <reference> <output>` on visual outputs (`--min-ssim 0.95 --min-psnr 35.0` for lossless-intent transcodes, `--min-ssim 0.85 --min-psnr 24.0` for spatial upscales, or `--min-ssim 0.0 --min-psnr 0.0` aspect/duration lock for faded-cast/tone-mapped restorations) and `keyframes` or `ab-sheet` viewed via `read_file` before declaring completion.

---

## 2. Audio Synthesis, Timeline Editing & Signal Restoration

### A. Programmatic Audio Synthesis (`NumPy`, `SciPy`, `SoundFile`, `Librosa` & `FFmpeg lavfi`)
When synthesizing sound effects, musical stems, ambient textures, UI cues, or calibration signals from scratch:

1. **64-Bit Floating-Point Digital Signal Processing (`DSP`):** Construct waveforms, Frequency Modulation (`FM`) / subtractive synth patches, biquad/Butterworth filter sweeps (`scipy.signal.butter`, `scipy.signal.sosfilt`), and room impulse convolutions (`scipy.signal.fftconvolve`) in `float64` arrays at `48000 Hz` (or `44100 Hz` when matching an existing timeline).
2. **Click-Free Envelope & Zero-DC Discipline:**
   * Subtract mean DC offset (`signal = signal - np.mean(signal)`) after synthesis and nonlinear waveshaping.
   * Apply an explicit Attack-Decay-Sustain-Release (`ADSR`) envelope or at least a `5 ms` raised-cosine (`hann`) fade-in and fade-out ramp so waveforms never start or terminate at a non-zero sample step.
   * Normalize peak amplitude below `-1.0 dBTP` (`peak_limit = 10 ** (-1.0 / 20.0)`) before writing to disk.
3. **Lossless Master & Delivery Formats:**
   * Write archival or intermediate stems as 24-bit signed Pulse-Code Modulation (`PCM_24` via `soundfile.write(..., subtype="PCM_24")` or `-c:a pcm_s24le` / `-c:a flac`).
   * Encode compressed delivery assets with `-c:a libopus -b:a 160k` (WebM/Ogg) or `-c:a aac -b:a 192k` (MP4/M4A).

### B. Audio Timeline Editing & Mixing
* **Pop-Free Trimming & Silence Removal:** Detect dead air with `silencedetect=noise=-38dB:d=0.4` and join trimmed segments using `acrossfade=d=0.03:c1=tri:c2=tri` (`30 ms` triangular crossfade) or `afade` micro-ramps to prevent splice clicks.
* **Headroom-Safe Multi-Track Mixing:** When mixing $N$ stems with `amix=inputs=N:normalize=0`, assign explicit per-track gain (`volume` filter) or duck background music under voice tracks using `sidechaincompress=threshold=0.03:ratio=4:attack=15:release=250` followed by two-pass loudness normalization.

### C. Ordered Audio Restoration & Two-Pass EBU R128 Mastering
When repairing noisy, clipped, uneven, or off-spec audio, apply filters in this exact physical signal order:

1. **DC Offset & Subsonic Rumble Removal:**
   * Voice/dialogue: `highpass=f=75:poles=2`
   * Music/full-range effects: `highpass=f=20:poles=2`
2. **De-Clipping & De-Clicking (Before Denoising or EQ):**
   * When `media_qc.py check` reports peak clipping (`MEDIA-3`), `astats` `flat_factor_db > 0.0` (attenuated hard-clipped waveforms), or spectral/waveform inspection reveals impulsive clicks, run `adeclip=w=55:o=75:a=8` and `adeclick=w=55:o=75:a=2` first so downstream spectral filters do not smear clipped square-wave harmonics.
3. **Mains Hum & Broadband Noise Reduction:**
   * For `50 Hz` or `60 Hz` electrical hum, notch fundamental and harmonics (`bandreject=f=50:width_type=q:w=10,bandreject=f=100:width_type=q:w=10`).
   * For stationary broadband hiss/room tone: `afftdn=nr=12:nf=-40:tn=1` (Fast Fourier Transform spectral denoiser) or `anlmdn=s=0.002:p=0.004:r=0.01` (non-local means denoiser). Avoid `nr > 20` on `afftdn` to prevent metallic musical-noise artifacts.
   * For speech in complex background noise: `arnndn` (when an RNNoise model is provided) or `scipy.signal` Short-Time Fourier Transform (`STFT`) spectral gating.
4. **Dynamics & Speech Leveling:**
   * Apply gentle downward compression (`acompressor=threshold=-18dB:ratio=2.5:attack=15:release=150:makeup=1`) or `speechnorm=e=6.25:r=0.0001:l=1` when whisper-to-shout loudness range (`LRA`) exceeds `14 LU`.
5. **Two-Pass European Broadcasting Union R128 (`EBU R128`) Loudness Mastering:**
   * Single-pass `loudnorm` dynamically alters gain over time and causes audible pumping on music and studio voiceovers. Always execute **Two-Pass `loudnorm`** via the built-in helper:
     ```bash
     MEDIA_QC="skills/media-studio/scripts/media_qc.py"
     for _p in .claude .cursor .agents .aider; do [ -f "$MEDIA_QC" ] || MEDIA_QC="$_p/skills/media-studio/scripts/media_qc.py"; done
     [ -f "$MEDIA_QC" ] || MEDIA_QC="$HOME/.gemini/config/skills/media-studio/scripts/media_qc.py"
     [ -f "$MEDIA_QC" ] || MEDIA_QC="/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py"
     python3 "$MEDIA_QC" master-audio <input> <output> \
       --target-lufs -14.0 --target-tp -1.0 --target-lra 11.0
     ```
   * **Standard Loudness Targets:**
     * Web / Streaming / Social Video (YouTube, Spotify, Reels): `-14.0 LUFS`, True Peak `<= -1.0 dBTP`
     * Podcast / Voiceover / Dialogue: `-16.0 LUFS`, True Peak `<= -1.5 dBTP`
     * Broadcast Television (`EBU R128` / `ITU-R BS.1770`): `-23.0 LUFS`, True Peak `<= -1.5 dBTP`

---

## 3. Video & Animated Visual Generation, Editing & Restoration

### A. Programmatic Video & Motion Graphic Generation (`OpenCV`, `Pillow`, `NumPy`, `Canvas`/`Remotion` & `FFmpeg`)
When generating animations, data-driven videos, title sequences, or procedural visualizers from code:

1. **Pure Frame-Index Determinism:** Express every visual property (position, scale, opacity, camera pan, waveform height) as a pure function of frame index $f \in [0, N - 1]$ and normalized time $t = f / \text{FPS}$, using smooth cubic-bezier or spring easing curves.
2. **Design & Contrast Compliance (`DESIGN.md`):** Honor `DESIGN.md` palette hierarchy, typographic scale, and WCAG AA contrast ratios (`>= 4.5:1` for captions and lower-thirds). Never use uncalibrated raw RGB/CMY primaries (`#FF0000`, `#00FF00`, `#0000FF`).
3. **Lossless Pipe to Encoder:** Pipe raw frames (`-f rawvideo -pix_fmt rgb24 -s <WxH> -r <FPS> -i -`) or lossless `.png` sequences directly into `ffmpeg`. Never write intermediate lossy `.jpg` frames.
4. **Derivative & Production Format Standards:**
   * **Animated GIF (Mandatory Two-Pass Palette):** Never run `ffmpeg -i in.mp4 out.gif` directly. Always generate a content-fitted 256-color palette first:
     ```bash
     ffmpeg -y -i input.mp4 \
       -filter_complex "[0:v]fps=15,scale=640:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=full[p];[b][p]paletteuse=dither=bayer:bayer_scale=5" \
       output.gif
     ```
   * **Animated WebP & APNG (24-Bit + Alpha):** Prefer `libwebp_anim` (`-c:v libwebp_anim -loop 0 -lossless 0 -q:v 85 -compression_level 6 -pix_fmt yuva420p`) or `apng` (`-plays 0 -pix_fmt rgba`) when smooth gradients or transparent backgrounds are required.
   * **Web & Universal MP4 (`H.264`):** `-c:v libx264 -crf 18 -preset slow -pix_fmt yuv420p -movflags +faststart` (ensures instant HTTP streaming seek and universal decoder compatibility; dimensions must be even integers via `scale=trunc(iw/2)*2:trunc(ih/2)*2`).
   * **High-Efficiency Archival / Modern Web (`HEVC` / `VP9` / `AV1`):**
     * Apple-compatible HEVC: `-c:v libx265 -crf 20 -preset slow -pix_fmt yuv420p -tag:v hvc1 -movflags +faststart`
     * WebM VP9: `-c:v libvpx-vp9 -crf 24 -b:v 0 -row-mt 1 -pix_fmt yuv420p`
     * AV1: `-c:v libsvtav1 -crf 24 -preset 6 -pix_fmt yuv420p`

### B. Video Timeline Editing, Reframing & Synchronization
* **Variable Frame Rate (`VFR`) Normalization Before Concatenation:** Screen recordings and smartphone clips frequently use `VFR` (`r_frame_rate != avg_frame_rate`). Normalize every input clip to Constant Frame Rate (`fps=30` or `fps=60`, `-fps_mode cfr`, `settb=AVTB`) and matching sample rate (`aresample=48000:async=1`) before `concat` to eliminate cumulative audio-video sync drift.
* **Distortion-Free Aspect Ratio Reframing (`16:9` ↔ `9:16` / `1:1`):** Never stretch aspect ratios without locking Sample Aspect Ratio (`setsar=1`). Either smart-crop around the focal region (`crop=ih*9/16:ih`) or composite the foreground over a darkened, Gaussian-blurred background plate:
  ```text
  [0:v]split=2[bg][fg];
  [bg]scale=1080:1920:force_original_aspect_ratio=increase,crop=1080:1920,boxblur=24:4,eq=brightness=-0.12[bg_blur];
  [fg]scale=1080:1920:force_original_aspect_ratio=decrease[fg_scaled];
  [bg_blur][fg_scaled]overlay=(W-w)/2:(H-h)/2,setsar=1[v]
  ```

### C. Ordered Video Restoration & Artifact Repair
When fixing visual defects in existing footage, apply filters in this order:

1. **Deinterlacing:** If `media_qc.py probe` reports `field_order` other than `progressive`/`unknown`, apply `bwdif=mode=send_frame:parity=auto:deint=interlaced` first.
2. **Spatial-Temporal Denoising:**
   * Light-to-moderate sensor grain: `hqdn3d=luma_spatial=4:chroma_spatial=3:luma_tmp=6:chroma_tmp=6` or temporal adaptive averaging `atadenoise=0a=0.02:0b=0.04:1a=0.02:1b=0.04`.
   * Heavy compression noise or low-light grain: `nlmeans=s=3.0:p=7:r=15` or Block-Matching 3D `bm3d=sigma=3.5`.
3. **Gradient Debanding (`deband`):**
   * Remove 8-bit color banding steps in skies, studio backdrops, and dark vignettes: `deband=1thr=0.02:2thr=0.02:3thr=0.02:range=16:blur=true`.
4. **Color Space & High Dynamic Range (`HDR`) to Standard Dynamic Range (`SDR`) Tone Mapping:**
   * When converting `bt2020nc` / `smpte2084` (`PQ`) or `arib-std-b67` (`HLG`) sources to standard `bt709` without grey washout:
     ```text
     zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,zscale=t=bt709:m=bt709:r=tv,format=yuv420p
     ```
5. **Scaling, Detail Recovery & Motion Interpolation:**
   * Upscale with `scale=<W>:<H>:flags=lanczos,setsar=1` followed by subtle luma-only sharpening (`unsharp=5:5:0.45:5:5:0.0`).
   * For smooth frame-rate conversion (when motion interpolation is explicitly requested): `minterpolate=fps=60:mi_mode=mci:mc_mode=aobmc:me_mode=bidir:vsbmc=1`.

### D. Corrupted Container Salvage, Still-Image Restoration & Fidelity-Bounded Enhancement
When recovering damaged/truncated audio, video, or image files, restoring scanned/old photographs (`.jpg`, `.png`, `.tiff`, `.bmp`, `.webp`), or enhancing low-resolution media without altering original identity ("aslını bozmadan"), load [salvage-and-enhancement.md](./references/salvage-and-enhancement.md) and enforce:
1. **Mode 1 (Salvage & Defect Repair):** For timed audio/video/animated containers, run `python3 "$MEDIA_QC" salvage <input> <output>` (`-c copy` first; `--allow-reencode` only if codec packets are fractured; for single-frame raster bitmaps with truncated scanlines, pass `--allow-reencode` directly to a lossless `.png`/`.tiff` target) before applying DSP filters; for still photos, normalize `EXIF` orientation first and restrict dust/scratch inpainting strictly to impulse masks.
2. **Mode 2 (Fidelity-Bounded Enhancement):** Default to zero-hallucination mathematical enhancement (Lanczos + `setsar=1` + luma-only `unsharp` + `deband` / two-pass `EBU R128`). Require explicit user confirmation via `ask_question` and SHA-256-verified local-only weights (`GEMINI.md` Rule 12) before running neural super-resolution or bandwidth-extension models; verify visual outputs via `compare --min-ssim 0.85 --min-psnr 24.0` (aspect-drift guard `<= 2%`) + `ab-sheet` viewed with `read_file`, and verify audio-only outputs via `check` (`MEDIA-1..MEDIA-5`), duration drift `<= 50 ms`, and `ab-sheet` spectrogram comparison viewed with `read_file`.

---

## 4. Objective Quality Control & Delivery Gate (`scripts/media_qc.py`)

No audio, video, or animated visual file may be delivered solely because `ffmpeg` exited with code `0`. Before delivery, execute the deterministic quality gate:

```bash
MEDIA_QC="skills/media-studio/scripts/media_qc.py"
for _p in .claude .cursor .agents .aider; do [ -f "$MEDIA_QC" ] || MEDIA_QC="$_p/skills/media-studio/scripts/media_qc.py"; done
[ -f "$MEDIA_QC" ] || MEDIA_QC="$HOME/.gemini/config/skills/media-studio/scripts/media_qc.py"
[ -f "$MEDIA_QC" ] || MEDIA_QC="/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py"

# 1. Inspect stream structure and metadata
python3 "$MEDIA_QC" probe <output_file> --json

# 2. Enforce signal quality & container compliance (MEDIA-1 through MEDIA-7)
python3 "$MEDIA_QC" check <output_file> \
  --target-lufs -14.0 --lufs-tolerance 1.5 --max-true-peak -1.0 --max-dc-offset 0.02

# 3. Salvage truncated WAV headers or broken container timestamps via stream-copy first
python3 "$MEDIA_QC" salvage <damaged_input> <salvaged_output> --json

# 4. Compare visual, aspect-ratio & timeline fidelity against reference source
#    - Lossless-intent transcodes/edits: --min-ssim 0.95 --min-psnr 35.0
#    - Tier 1 / Tier 2 spatial upscales: --min-ssim 0.85 --min-psnr 24.0
#    - Faded color-cast / HDR tone-mapped restorations: --min-ssim 0.0 --min-psnr 0.0 (enforces <=2% aspect & timeline lock; pair with ab-sheet)
python3 "$MEDIA_QC" compare <reference_file> <output_file> --min-ssim 0.95 --min-psnr 35.0

# 5. Render a side-by-side Reference vs. Enhanced sheet (visual frames or audio spectrograms) and inspect via read_file
python3 "$MEDIA_QC" ab-sheet <reference_file> <output_file> <scratch_dir>/ab_sheet.png \
  --tile-width 480 --samples 3

# 6. Two-Pass EBU R128 audio mastering with optional pre-restoration filters
python3 "$MEDIA_QC" master-audio <input_file> <output_file> \
  --target-lufs -14.0 --target-tp -1.0 --target-lra 11.0 --highpass 75 --denoise fft --declip

# 7. Extract a tiled keyframe contact sheet and inspect via read_file (for video/animated outputs)
python3 "$MEDIA_QC" keyframes <output_file> <scratch_dir>/contact_sheet.png \
  --cols 4 --rows 2 --tile-width 320
```

### Enforced Quality Rules (`media_qc.py check`)
* **`MEDIA-1` (Stream, Duration & Still-Image Decode Integrity):** File must exist, be non-empty, have positive duration (`> 0 s` for timed containers; still/animated image streams such as `gif`, `webp`, `webp_pipe`, `apng`, `image2`, `png_pipe`, `jpeg_pipe`, `mjpeg`, `tiff_pipe`, `bmp_pipe` are exempt from container duration), and decode every frame/packet with zero fatal `ffmpeg` stream errors (including full scanline decode verification on still images).
* **`MEDIA-2` (Audio-Video Sync Drift & Even Geometry):** When both video and audio streams are present, their durations must agree within `<= 100 ms` (`0.10 s`), and odd pixel dimensions on `4:2:0` (`yuv420p`) streams are rejected.
* **`MEDIA-3` (True Peak Clipping & Silence Guard):** Audio True Peak (`dBTP`) must not exceed `--max-true-peak` (default `-1.0 dBTP`), and silent audio streams (`integrated_lufs <= -70.0 LUFS` unless `--allow-silent` is passed) are flagged.
* **`MEDIA-4` (Loudness Target Compliance):** When `--target-lufs` is specified, integrated loudness (`LUFS`) must fall within `target_lufs ± lufs_tolerance` (default `--lufs-tolerance 1.5` LU).
* **`MEDIA-5` (DC Offset Guard):** Absolute audio DC offset (`astats` `DC_offset`) must remain `<= --max-dc-offset` (default `0.02`).
* **`MEDIA-6` (Decoder & Pixel Format Compatibility):** `H.264` (`h264`) `.mp4`, `.m4v`, and `.mov` deliverables must use web-safe `yuv420p`, `yuvj420p`, or `nv12` rather than `yuv444p`/`yuv422p` that fail in standard web and mobile players (unless `--allow-high-chroma` is explicitly set for studio archival).
* **`MEDIA-7` (Black / Frozen Video Frame Guard):** Video outputs that are `>= 90%` (`0.90`) black frames (`blackdetect`) or `>= 95%` (`0.95`) frozen frames (`freezedetect` on videos `> 1.0 s`, unless `--allow-static` is set) are rejected.

For every visual or animated deliverable, inspect the generated tiled `contact_sheet.png` with `read_file` (`skills/harness/SKILL.md` §3B Step 4b) to confirm zero text clipping, aspect-ratio distortion, color banding, or framing defects before delivery.
