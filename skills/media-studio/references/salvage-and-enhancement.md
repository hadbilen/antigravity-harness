# Media Salvage, Still-Image Restoration & Fidelity-Bounded Enhancement

Deep-dive companion to `skills/media-studio/SKILL.md`. Load this reference when repairing damaged/unreadable media containers, restoring degraded still photographs, or upscaling low-resolution audio, image, and video assets without altering their original identity ("aslını bozmadan").

---

## 1. Mode 1 — Damaged Container Salvage & Deterministic Defect Repair

### A. Lossless Container & Header Salvage First (`salvage`)
Never re-encode a damaged file before testing whether its underlying compressed packets or raw Pulse-Code Modulation (`PCM`) samples are intact:

```bash
MEDIA_QC="skills/media-studio/scripts/media_qc.py"
for _p in .claude .cursor .agents .aider; do [ -f "$MEDIA_QC" ] || MEDIA_QC="$_p/skills/media-studio/scripts/media_qc.py"; done
[ -f "$MEDIA_QC" ] || MEDIA_QC="$HOME/.gemini/config/skills/media-studio/scripts/media_qc.py"
[ -f "$MEDIA_QC" ] || MEDIA_QC="/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py"

# 1. Attempt zero-generation-loss stream-copy salvage first (-c copy) on timed/multi-frame containers
python3 "$MEDIA_QC" salvage <damaged_input> <salvaged_output> --json

# 2. Only if codec packets themselves are fractured (or recovering intact scanlines from a single-frame
#    bitmap into a lossless .png/.tiff target), run archival re-encode salvage explicitly:
python3 "$MEDIA_QC" salvage <damaged_input> <salvaged_output> --allow-reencode --json
```

* **Truncated `.wav` RIFF / `data` Chunk Headers:** Crash-interrupted recorders often leave a `0`-byte or tiny placeholder size in the `data` chunk header while megabytes of intact `PCM` samples follow. `media_qc.py salvage` applies `-ignore_length true -err_detect ignore_err -c copy`, recovering 100% of raw samples bit-for-bit without re-encoding.
* **Broken Timestamps & Missing Container Indices (`.mp4`, `.mkv`, `.webm`, `.avi`, `.webp`, `.gif`, `.apng`):** `salvage` regenerates Presentation/Decode Timestamps (`-fflags +genpts+igndts+discardcorrupt`) while copying bitstreams verbatim (`-c copy`), and fails closed unless `>= 95%` of declared source duration survives (pass `--allow-partial` only when salvaging partially truncated files with explicit drop reporting). Note that an `.mp4` missing its `moov` atom entirely (unfinalized camera recording with zero index table) cannot be reconstructed by `ffmpeg` alone unless a reference file from the same camera/profile is available via local `untrunc`; `salvage` surfaces that exact diagnostic instead of emitting an empty file.
* **No Silent Drop Accounting:** Compare `pre_duration_sec`, `recovered_duration_sec`, and `source_decode_errors` from `salvage --json`. If unreadable packets caused a duration gap, state the exact lost duration in the delivery report rather than claiming lossless 100% recovery.

### B. Still-Image & Scanned Photograph Restoration (`Pillow`, `OpenCV` & `FFmpeg`)
When repairing old digital images or scanned family/archival photographs (`.jpg`, `.png`, `.tif`, `.tiff`, `.bmp`, `.webp`):

1. **Orientation & Archival Bit-Depth First:**
   * Apply Exchangeable Image File Format (`EXIF`) orientation transposition (`PIL.ImageOps.exif_transpose(img)`) before any spatial filter so rotated smartphone or scanner images are never saved sideways (`media_qc.py` honors stream/frame display rotation so aspect comparisons match transposed geometry).
   * Perform intermediate color and denoising math in `float32` (`[0.0, 1.0]`) or `uint16` and write archival outputs to lossless `.png` or 16-bit `.tiff` (or `-q:v 2` `yuvj444p` `.jpg` only when JPEG delivery is requested).
2. **Targeted Defect Repair Without Texture Destruction:**
   * **Heavy 8x8 JPEG Blocking:** Apply gentle non-local means denoising (`cv2.fastNlMeansDenoisingColored` with `h=3..6`, `hColor=3..6` or `ffmpeg` `-vf nlmeans=s=2.5:p=7:r=15`) rather than wide Gaussian blurs that erase eyelashes, fabric weave, and text edges.
   * **Scanner Dust & Impulse Scratches:** Detect isolated bright/dark impulse outliers via morphological top-hat / black-hat thresholding and apply `cv2.inpaint(..., inpaintRadius=2, flags=cv2.INPAINT_TELEA)` **strictly inside the binary defect mask**, leaving 98%+ of original pixels untouched.
   * **Faded Cast & Dynamic Range Recovery:** Correct yellow/magenta paper aging via gray-world / percentile channel anchoring (`1st`–`99th` percentile stretch with `>= 0.5%` highlight/shadow headroom) so clipped white patches or crushed shadow blocks are never introduced; verify geometry via `compare --min-ssim 0.0 --min-psnr 0.0` (enforcing `<= 2%` aspect lock without penalizing intentional exposure/cast correction) paired with `ab-sheet` visual inspection.

### C. Signal-Restoration Artifact Ceilings (Anti-Plastic & Anti-Metallic Guard)
* **Audio Denoising Ceiling:** Keep `afftdn` noise reduction `nr <= 20` dB (`nr=10..14` typical, matching `skills/media-studio/SKILL.md` §2C). Stronger single-pass spectral subtraction carves holes into speech formants and creates watery "musical noise".
* **Video Denoising Ceiling:** Keep `hqdn3d` `luma_spatial <= 5.0` and `bm3d` `sigma <= 4.5` on human faces and film grain so skin never turns waxy and moving edges do not trail across frames.

---

## 2. Mode 2 — Fidelity-Bounded Quality Enhancement ("Orijinali Bozmadan Yükseltmek")

When an audio, image, or video source is intact (`check` passes) but suffers from low resolution, soft focus, 8-bit banding, or flat dynamics, separate **mathematical enhancement** from **neural synthesis**:

### Tier 1 — Mathematical / Zero-Hallucination Enhancement (Default)
Always apply Tier 1 by default when the user asks to improve quality while preserving the original:
* **Visual Upscaling & Luma-Only Micro-Contrast:**
  * Scale with `scale=<W>:<H>:flags=lanczos,setsar=1` (locking square Sample Aspect Ratio `1:1` so browsers and players never stretch geometry).
  * Follow with mild **luma-only** unsharp masking (`unsharp=5:5:0.45:5:5:0.0` — keeping chroma amount at `0.0` so color subsampling noise is never sharpened) and `deband=1thr=0.02:2thr=0.02:3thr=0.02:range=16:blur=true`, verified with `compare --min-ssim 0.85 --min-psnr 24.0` and `ab-sheet`.
* **Audio Clarity & Headroom Mastering:**
  * Remove subsonic DC/rumble (`highpass=f=20:poles=2` music / `highpass=f=75:poles=2` dialogue), apply gentle presence/mud corrective equalization only where spectral inspection justifies it (`equalizer` `<= +/- 3 dB`), and master via two-pass `EBU R128` (`media_qc.py master-audio`). Never invent fake high-frequency harmonics via aggressive nonlinear exciters without user consent.

### Tier 2 — Local Pinned Neural Super-Resolution / Bandwidth Extension (Explicit User Opt-In Only)
Tiny archival images/videos (`<= 360p`) or narrowband (`8 kHz` telephone/dictaphone) recordings cannot recover missing high-frequency structure through Lanczos interpolation alone. Neural restoration models (`realesrgan-ncnn-vulkan`, `SwinIR`, `CodeFormer` with high fidelity weight `w >= 0.8`, or local speech restoration models) may be used **only** when all three guardrails hold:

1. **Explicit User Opt-In (`ask_question`):** State clearly what Tier 1 mathematical upscaling achieves versus what an installed local neural model reconstructs, and obtain user confirmation before running generative/neural weights.
2. **Local-Only, Hash-Pinned & Safe-Deserialization Supply Chain (`GEMINI.md` Rule 12):** Never upload user audio, photos, or videos to third-party cloud APIs unless explicitly requested by the user; never run unpinned remote installers (`curl | bash`, `npx package@latest`) or automatic first-run checkpoint downloads; verify pre-staged local model weights by SHA-256 digest; and load weights exclusively via `safetensors` or `torch.load(..., weights_only=True)` (never unsafe `pickle`).
3. **Zero-Hallucination Identity, Text & Timbre Gate (`compare` / `check` + `ab-sheet`):**
   * Neural super-resolution and bandwidth extension must **never** alter a person's facial identity, invent fake letters on signs/documents, or shift a speaker's vocal timbre.
   * **Visual streams (images & video):** Run aspect- and duration-locked structural comparison (`compare --min-ssim 0.85 --min-psnr 24.0`) **and** render a side-by-side frame `ab-sheet` inspected via `read_file`.
   * **Audio-only streams (speech/music bandwidth extension):** Run `check` (`MEDIA-1..MEDIA-5`), verify duration drift `<= 50 ms` against `probe <original>`, **and** render a side-by-side spectrogram `ab-sheet` (`modality: "audio_spectrogram"`) inspected via `read_file`:
     ```bash
     MEDIA_QC="skills/media-studio/scripts/media_qc.py"
     for _p in .claude .cursor .agents .aider; do [ -f "$MEDIA_QC" ] || MEDIA_QC="$_p/skills/media-studio/scripts/media_qc.py"; done
     [ -f "$MEDIA_QC" ] || MEDIA_QC="$HOME/.gemini/config/skills/media-studio/scripts/media_qc.py"
     [ -f "$MEDIA_QC" ] || MEDIA_QC="/usr/share/antigravity-harness/skills/media-studio/scripts/media_qc.py"

     # Visual Tier 2 gate (images / video)
     python3 "$MEDIA_QC" compare <original_file> <enhanced_file> --min-ssim 0.85 --min-psnr 24.0
     python3 "$MEDIA_QC" ab-sheet <original_file> <enhanced_file> <scratch_dir>/ab_sheet.png --tile-width 480 --samples 3

     # Audio-only Tier 2 gate (renders side-by-side showspectrumpic sheet)
     python3 "$MEDIA_QC" check <enhanced_audio> --target-lufs -16.0 --max-true-peak -1.5
     python3 "$MEDIA_QC" ab-sheet <original_audio> <enhanced_audio> <scratch_dir>/audio_ab_sheet.png --tile-width 480
     ```
   * Inspect the generated `ab_sheet.png` with `read_file`. If faces look synthetic/waxy, text glyphs mutate, or speech formants distort, blend back toward the Tier 1 reference (for example `50%–70%` mix) or deliver the Tier 1 output and report the finding.
