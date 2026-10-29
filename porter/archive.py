"""
porter/archive.py — Read-only ZIP inspection for Porter.
Zero-dependency: uses the Python standard library only.

inspect_zip() NEVER extracts and never writes to disk: it reads the central directory,
reports hazards, and runs the constitutional SuitabilityAnalyzer on the text members that
pass every limit (read through a bounded in-memory stream). There is deliberately no
extraction or installation path: an archive is evidence to review, not something to unpack.

Hazards (any hazard makes the archive unsafe):
  - more than MAX_MEMBERS members, or more than MAX_TOTAL_UNCOMPRESSED declared bytes
  - a per-member or overall compression ratio above MAX_RATIO (zip bomb)
  - absolute paths, drive letters, '..' segments (after normalising both '/' and '\\')
  - symlink members (unix mode S_IFLNK in external_attr >> 16), encrypted members
  - nested archives (.zip, .tar, .gz, ... inside the archive), duplicate member names
When an archive-level limit is exceeded no member is read at all. Analyzer failures are
reported as an issue of the member they happened on, never swallowed.
"""

from __future__ import annotations

import lzma
import os
import re
import stat
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from porter.models import SuitabilityIssue

MAX_MEMBERS = 200
MAX_TOTAL_UNCOMPRESSED = 25 * 1024 * 1024
MAX_RATIO = 100.0
# Ratios are only meaningful for members/archives of some size: a 300-byte file of spaces is not a bomb.
RATIO_MIN_BYTES = 64 * 1024
# The archive file itself cannot legitimately be much larger than its uncompressed limit.
MAX_ARCHIVE_BYTES = MAX_TOTAL_UNCOMPRESSED + 1024 * 1024
MAX_ANALYZED_MEMBER_BYTES = 2 * 1024 * 1024
TEXT_SUFFIXES = (".md", ".mdc", ".txt", ".json", ".yml", ".yaml", ".toml", ".rules", ".prompt", ".xml")
RULE_BASENAMES = (".cursorrules", ".windsurfrules", ".clinerules", ".continuerules")
BENIGN_ASSET_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".css",
    ".mp3", ".wav", ".ogg", ".mp4", ".webm", ".pdf",
)
BENIGN_DOC_BASENAMES = ("license", "notice", "copying")
EXECUTABLE_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".fish", ".ksh", ".csh",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs",
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
    ".rb", ".pl", ".php", ".lua",
    ".exe", ".dll", ".so", ".dylib", ".wasm", ".bin", ".com", ".scr", ".msi", ".appimage",
)
NESTED_ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".zst", ".7z", ".rar",
                           ".jar", ".war", ".whl", ".apk")
EXECUTABLE_CONFIG_BASENAMES = ("hooks.json", "mcp_config.json", ".mcp.json")
EXECUTABLE_CONFIG_RELPATHS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/mcp.json",
)
_BINARY_EXEC_MAGICS = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\x00asm",
)
_NESTED_ARCHIVE_MAGICS = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b"\xfd7zXZ\x00",
)
_DRIVE = re.compile(r"^[A-Za-z]:")


def _normalized_basename(name: str) -> str:
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()


def _is_analyzable_text_member(name: str) -> bool:
    norm = name.replace("\\", "/").lower().rstrip("/")
    base = _normalized_basename(name)
    if norm.endswith(TEXT_SUFFIXES):
        return True
    if base in RULE_BASENAMES or base.startswith(".aider") or base in BENIGN_DOC_BASENAMES:
        return True
    return False


def _is_benign_asset(name: str) -> bool:
    norm = name.replace("\\", "/").lower().rstrip("/")
    return norm.endswith(BENIGN_ASSET_SUFFIXES)


@dataclass
class ArchiveHazard:
    kind: str       # TOO_MANY_MEMBERS, OVERSIZE, COMPRESSION_RATIO, ABSOLUTE_PATH, DRIVE_LETTER, PATH_TRAVERSAL,
                    # SYMLINK, ENCRYPTED, NESTED_ARCHIVE, DUPLICATE_NAME, INVALID_NAME, MEMBER_TOO_LARGE,
                    # UNREADABLE_MEMBER, ANALYZER_ERROR, INVALID_ARCHIVE
    member: str     # "" for archive-level hazards
    message: str


@dataclass
class MemberReport:
    name: str
    size: int
    compressed_size: int
    analyzed: bool = False
    is_safe_to_import: Optional[bool] = None
    constitutional_score: Optional[int] = None
    recommended_type: str = ""
    issues: List[SuitabilityIssue] = field(default_factory=list)
    error: str = ""


@dataclass
class ArchiveReport:
    archive: str
    member_count: int = 0
    total_uncompressed: int = 0
    total_compressed: int = 0
    hazards: List[ArchiveHazard] = field(default_factory=list)
    members: List[MemberReport] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return not self.hazards and all(m.error == "" and m.is_safe_to_import is not False for m in self.members)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["is_safe"] = self.is_safe
        return data

    def to_markdown(self) -> str:
        status = "✅ NO HAZARDS DETECTED" if self.is_safe else "⚠️ HAZARDS / FINDINGS — DO NOT UNPACK BLINDLY"
        ratio = (self.total_uncompressed / self.total_compressed) if self.total_compressed else 0.0
        lines = [
            "# Porter Archive Inspection Report",
            "",
            f"**Archive:** `{self.archive}`",
            f"**Status:** {status}",
            f"**Members:** {self.member_count} (limit {MAX_MEMBERS})",
            f"**Declared uncompressed size:** {self.total_uncompressed} bytes (limit {MAX_TOTAL_UNCOMPRESSED})",
            f"**Overall compression ratio:** {ratio:.1f}:1 (limit {MAX_RATIO:.0f}:1)",
            "",
            "> Inspection only: nothing was extracted or written. Porter never unpacks archives.",
            "",
            "### 1. Archive Hazards",
        ]
        if not self.hazards:
            lines.append("None.")
        for h in self.hazards:
            where = f" `{h.member}`" if h.member else ""
            lines.append(f"- 🚨 **{h.kind}**{where}: {h.message}")
        lines += ["", "### 2. Analyzed Text Members"]
        analyzed = [m for m in self.members if m.analyzed or m.error]
        if not analyzed:
            lines.append("No text member was analyzed.")
        for m in analyzed:
            if m.error:
                lines.append(f"- `{m.name}` — 🚨 analyzer failed: {m.error}")
                continue
            verdict = "safe" if m.is_safe_to_import else "NOT safe"
            lines.append(f"- `{m.name}` — {verdict} to import (score {m.constitutional_score}/100, {m.recommended_type})")
            for issue in m.issues:
                lines.append(f"  - [{issue.severity}] **{issue.category}**: {issue.message}")
        skipped = [m.name for m in self.members if not m.analyzed and not m.error]
        if skipped:
            lines += ["", f"Not analyzed ({len(skipped)}): " + ", ".join(f"`{n}`" for n in skipped[:20])
                      + (" …" if len(skipped) > 20 else "")]
        return "\n".join(lines)


def _ratio(size: int, compressed: int) -> float:
    return size / max(compressed, 1)


def _path_hazards(name: str) -> List[ArchiveHazard]:
    hazards: List[ArchiveHazard] = []
    if "\x00" in name or not name.strip():
        hazards.append(ArchiveHazard("INVALID_NAME", name, "member name is empty or contains a NUL byte"))
    normalised = name.replace("\\", "/")
    if normalised.startswith("/"):
        hazards.append(ArchiveHazard("ABSOLUTE_PATH", name, "absolute member path would escape any target directory"))
    if _DRIVE.match(normalised):
        hazards.append(ArchiveHazard("DRIVE_LETTER", name, "member path starts with a Windows drive letter"))
    if ".." in normalised.split("/"):
        hazards.append(ArchiveHazard("PATH_TRAVERSAL", name, "member path contains a '..' segment"))
    return hazards


def _member_hazards(info: zipfile.ZipInfo) -> List[ArchiveHazard]:
    name = info.filename
    hazards = _path_hazards(name)
    unix_mode = info.external_attr >> 16
    is_symlink = stat.S_ISLNK(unix_mode)
    if is_symlink:
        hazards.append(ArchiveHazard("SYMLINK", name, "symbolic link member (could point outside any target directory)"))
    if info.flag_bits & 0x1:
        hazards.append(ArchiveHazard("ENCRYPTED", name, "encrypted member cannot be inspected"))
    if info.file_size >= RATIO_MIN_BYTES and _ratio(info.file_size, info.compress_size) > MAX_RATIO:
        hazards.append(ArchiveHazard(
            "COMPRESSION_RATIO", name,
            f"compression ratio {_ratio(info.file_size, info.compress_size):.0f}:1 exceeds {MAX_RATIO:.0f}:1"))
    lower_norm = name.replace("\\", "/").lower().rstrip("/")
    rel_clean = re.sub(r"^(?:\./)+", "", lower_norm)
    base_lower = _normalized_basename(name)
    if lower_norm.endswith(NESTED_ARCHIVE_SUFFIXES):
        hazards.append(ArchiveHazard("NESTED_ARCHIVE", name, "nested archive is not inspected; its content is unknown"))
    elif not info.is_dir() and not is_symlink:
        if (
            base_lower in EXECUTABLE_CONFIG_BASENAMES
            or rel_clean in EXECUTABLE_CONFIG_RELPATHS
            or any(rel_clean.endswith("/" + p) for p in EXECUTABLE_CONFIG_RELPATHS)
            or (
                (rel_clean.startswith(".github/workflows/") or "/.github/workflows/" in rel_clean)
                and lower_norm.endswith((".yml", ".yaml"))
            )
        ):
            hazards.append(ArchiveHazard(
                "EXECUTABLE_CONFIG", name,
                "active hook, MCP server, or CI workflow configuration cannot be imported safely"))
        elif lower_norm.endswith(EXECUTABLE_SUFFIXES) or (unix_mode and not stat.S_ISDIR(unix_mode) and (unix_mode & 0o111)):
            hazards.append(ArchiveHazard(
                "EXECUTABLE_MEMBER", name, "executable or script member cannot be imported safely"))
        elif not _is_analyzable_text_member(name) and not _is_benign_asset(name):
            hazards.append(ArchiveHazard(
                "UNANALYZED_MEMBER", name, "member file type is not analyzed and cannot be verified safe"))
    return hazards


def _stream_verify_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    capture_bytes: bool,
    member_limit: int,
    archive_budget: int,
    archive_size: int = 0,
) -> tuple[Optional[bytes], int, List[ArchiveHazard]]:
    """
    Streams a ZIP member in bounded chunks to verify real decompressed bytes, ratio, and archive budget
    even when central-directory `file_size` or `compress_size` headers are spoofed.
    """
    chunks: List[bytes] = []
    actual_size = 0
    stream_hazards: List[ArchiveHazard] = []
    first_chunk = b""
    declared_size = info.file_size
    effective_comp = min(info.compress_size, archive_size) if archive_size > 0 else info.compress_size
    unbounded_probe = max(declared_size, archive_budget, member_limit) + 65537
    with zf.open(info, "r") as fh:
        if hasattr(fh, "_left"):
            fh._left = unbounded_probe
        while True:
            buf = fh.read(65536)
            if not buf:
                break
            if not first_chunk:
                first_chunk = buf[:8]
            actual_size += len(buf)
            if actual_size > archive_budget:
                stream_hazards.append(ArchiveHazard(
                    "OVERSIZE", info.filename,
                    f"real decompressed content exceeds cumulative archive limit of {MAX_TOTAL_UNCOMPRESSED} bytes"))
                break
            if actual_size >= RATIO_MIN_BYTES and _ratio(actual_size, effective_comp) > MAX_RATIO:
                stream_hazards.append(ArchiveHazard(
                    "COMPRESSION_RATIO", info.filename,
                    f"real compression ratio {_ratio(actual_size, effective_comp):.0f}:1 exceeds {MAX_RATIO:.0f}:1"))
                break
            if capture_bytes and actual_size > member_limit:
                stream_hazards.append(ArchiveHazard(
                    "MEMBER_TOO_LARGE", info.filename,
                    f"real decompressed size exceeds analysis bound of {member_limit} bytes; not analyzed"))
                break
            if capture_bytes:
                chunks.append(buf)
        trailing_compressed = int(getattr(fh, "_compress_left", 0) or 0)
    if first_chunk.startswith((b"#!", b"\xef\xbb\xbf#!")):
        stream_hazards.append(ArchiveHazard(
            "EXECUTABLE_MEMBER", info.filename, "member begins with a script shebang (#!)"))
    elif first_chunk.startswith(_BINARY_EXEC_MAGICS):
        stream_hazards.append(ArchiveHazard(
            "EXECUTABLE_MEMBER", info.filename, "member contains binary executable magic bytes"))
    elif first_chunk.startswith(_NESTED_ARCHIVE_MAGICS):
        stream_hazards.append(ArchiveHazard(
            "NESTED_ARCHIVE", info.filename, "member contains nested archive magic bytes"))
    if not stream_hazards and (actual_size != declared_size or trailing_compressed > 0):
        stream_hazards.append(ArchiveHazard(
            "DECOMPRESSED_MISMATCH", info.filename,
            f"decompressed stream yielded {actual_size} bytes vs declared {declared_size} bytes"))
    payload = b"".join(chunks) if (capture_bytes and not stream_hazards) else None
    return payload, actual_size, stream_hazards


def inspect_zip(path: Path, harness_root: Optional[Path] = None, analyzer=None) -> ArchiveReport:
    """
    Inspects a local ZIP archive without extracting it. `analyzer` defaults to a
    SuitabilityAnalyzer for `harness_root` (used for redundancy checks).
    """
    path = Path(path)
    report = ArchiveReport(archive=str(path))
    try:
        archive_size = os.path.getsize(path)
    except OSError as e:
        report.hazards.append(ArchiveHazard("INVALID_ARCHIVE", "", f"cannot read archive: {e}"))
        return report
    if archive_size > MAX_ARCHIVE_BYTES:
        report.hazards.append(ArchiveHazard(
            "OVERSIZE", "", f"archive file is {archive_size} bytes (limit {MAX_ARCHIVE_BYTES}); not opened"))
        return report
    try:
        zf = zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError) as e:
        report.hazards.append(ArchiveHazard("INVALID_ARCHIVE", "", f"not a readable ZIP archive: {e}"))
        return report

    with zf:
        infos = zf.infolist()
        report.member_count = len(infos)
        report.total_uncompressed = sum(i.file_size for i in infos)
        report.total_compressed = sum(i.compress_size for i in infos)
        for info in infos:
            report.members.append(MemberReport(info.filename, info.file_size, info.compress_size))

        archive_level: List[ArchiveHazard] = []
        if report.member_count > MAX_MEMBERS:
            archive_level.append(ArchiveHazard("TOO_MANY_MEMBERS", "", f"{report.member_count} members (limit {MAX_MEMBERS})"))
        if report.total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
            archive_level.append(ArchiveHazard(
                "OVERSIZE", "", f"declared uncompressed size {report.total_uncompressed} bytes (limit {MAX_TOTAL_UNCOMPRESSED})"))
        overall = _ratio(report.total_uncompressed, report.total_compressed)
        if report.total_uncompressed >= RATIO_MIN_BYTES and overall > MAX_RATIO:
            archive_level.append(ArchiveHazard(
                "COMPRESSION_RATIO", "", f"overall compression ratio {overall:.0f}:1 exceeds {MAX_RATIO:.0f}:1"))
        report.hazards.extend(archive_level)

        seen: Dict[str, int] = {}
        member_hazards: Dict[int, List[ArchiveHazard]] = {}
        sorted_by_offset = sorted(enumerate(infos), key=lambda item: (int(getattr(item[1], "header_offset", 0) or 0), item[0]))
        prev_end_offset = 0
        offset_hazards: Dict[int, ArchiveHazard] = {}
        for idx, info in sorted_by_offset:
            hdr_off = int(getattr(info, "header_offset", 0) or 0)
            min_end = hdr_off + 30 + int(info.compress_size or 0)
            if hdr_off < prev_end_offset or min_end > archive_size:
                offset_hazards[idx] = ArchiveHazard(
                    "OVERLAPPING_OR_SPOOFED_OFFSET",
                    info.filename,
                    "member local header offset overlaps another entry or exceeds archive file bounds",
                )
            prev_end_offset = max(prev_end_offset, min(min_end, archive_size))
        for idx, info in enumerate(infos):
            hazards = _member_hazards(info)
            if idx in offset_hazards:
                hazards.append(offset_hazards[idx])
            key = info.filename.replace("\\", "/").rstrip("/").lower()
            if key in seen:
                hazards.append(ArchiveHazard("DUPLICATE_NAME", info.filename, "member name occurs more than once (case-insensitive)"))
            seen[key] = idx
            member_hazards[idx] = hazards
            report.hazards.extend(hazards)

        if archive_level:
            return report  # enforce the limits: do not read a single member

        if analyzer is None:
            from porter.analyzer import SuitabilityAnalyzer
            analyzer = SuitabilityAnalyzer(harness_root=harness_root)

        actual_total_uncompressed = 0
        for idx, info in enumerate(infos):
            member = report.members[idx]
            if info.is_dir() or member_hazards[idx]:
                continue
            is_text = _is_analyzable_text_member(info.filename)
            if is_text and info.file_size > MAX_ANALYZED_MEMBER_BYTES:
                report.hazards.append(ArchiveHazard(
                    "MEMBER_TOO_LARGE", info.filename,
                    f"{info.file_size} bytes exceeds the analysis bound of {MAX_ANALYZED_MEMBER_BYTES}; not analyzed"))
                actual_total_uncompressed += info.file_size
                continue
            remaining_budget = max(0, MAX_TOTAL_UNCOMPRESSED - actual_total_uncompressed)
            try:
                data, actual_size, stream_hazards = _stream_verify_member(
                    zf,
                    info,
                    capture_bytes=is_text,
                    member_limit=MAX_ANALYZED_MEMBER_BYTES,
                    archive_budget=remaining_budget,
                    archive_size=archive_size,
                )
            except (
                zipfile.BadZipFile,
                zlib.error,
                lzma.LZMAError,
                OSError,
                ValueError,
                NotImplementedError,
                RuntimeError,
                EOFError,
            ) as e:
                member.error = f"could not read member: {type(e).__name__}: {e}"
                report.hazards.append(ArchiveHazard("UNREADABLE_MEMBER", info.filename, member.error))
                continue
            actual_total_uncompressed += actual_size
            member.size = actual_size
            if stream_hazards:
                report.hazards.extend(stream_hazards)
                continue
            if not is_text or data is None:
                continue
            if b"\x00" in data:
                member.error = "text member contains embedded NUL bytes"
                report.hazards.append(ArchiveHazard("BINARY_OR_INVALID_UTF8", info.filename, member.error))
                continue
            try:
                decoded_text = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError as e:
                member.error = f"invalid UTF-8 text member: {e}"
                report.hazards.append(ArchiveHazard("BINARY_OR_INVALID_UTF8", info.filename, member.error))
                continue
            try:
                result = analyzer.analyze(decoded_text,
                                          source_identifier=f"{path.name}!{info.filename}")
            except Exception as e:  # reported on the member and as a hazard, never swallowed
                member.error = f"{type(e).__name__}: {e}"
                member.issues.append(SuitabilityIssue(
                    severity="CRITICAL", category="ARCHIVE", message=f"Analyzer failed on this member: {member.error}",
                    suggested_fix="Inspect the member manually; an unanalyzed rule must not be imported."))
                report.hazards.append(ArchiveHazard("ANALYZER_ERROR", info.filename, f"analyzer failed: {member.error}"))
                continue
            member.analyzed = True
            member.is_safe_to_import = result.is_safe_to_import
            member.constitutional_score = result.constitutional_score
            member.recommended_type = result.recommended_type
            member.issues = list(result.issues)
        if actual_total_uncompressed > report.total_uncompressed:
            report.total_uncompressed = actual_total_uncompressed
        if actual_total_uncompressed >= RATIO_MIN_BYTES and _ratio(actual_total_uncompressed, archive_size) > MAX_RATIO:
            report.hazards.append(ArchiveHazard(
                "COMPRESSION_RATIO",
                "",
                f"real overall archive compression ratio {_ratio(actual_total_uncompressed, archive_size):.0f}:1 exceeds {MAX_RATIO:.0f}:1",
            ))
    return report
