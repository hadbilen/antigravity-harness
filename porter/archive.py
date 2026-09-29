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

import os
import re
import stat
import zipfile
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
TEXT_SUFFIXES = (".md", ".mdc", ".txt", ".json")
NESTED_ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".zst", ".7z", ".rar",
                           ".jar", ".war", ".whl", ".apk")
_DRIVE = re.compile(r"^[A-Za-z]:")


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
    if stat.S_ISLNK(info.external_attr >> 16):
        hazards.append(ArchiveHazard("SYMLINK", name, "symbolic link member (could point outside any target directory)"))
    if info.flag_bits & 0x1:
        hazards.append(ArchiveHazard("ENCRYPTED", name, "encrypted member cannot be inspected"))
    if info.file_size >= RATIO_MIN_BYTES and _ratio(info.file_size, info.compress_size) > MAX_RATIO:
        hazards.append(ArchiveHazard(
            "COMPRESSION_RATIO", name,
            f"compression ratio {_ratio(info.file_size, info.compress_size):.0f}:1 exceeds {MAX_RATIO:.0f}:1"))
    if name.replace("\\", "/").lower().rstrip("/").endswith(NESTED_ARCHIVE_SUFFIXES):
        hazards.append(ArchiveHazard("NESTED_ARCHIVE", name, "nested archive is not inspected; its content is unknown"))
    return hazards


def _read_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with zf.open(info, "r") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"member yields more than {limit} bytes")
    return data


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
        for idx, info in enumerate(infos):
            hazards = _member_hazards(info)
            key = info.filename.replace("\\", "/")
            if key in seen:
                hazards.append(ArchiveHazard("DUPLICATE_NAME", info.filename, "member name occurs more than once"))
            seen[key] = idx
            member_hazards[idx] = hazards
            report.hazards.extend(hazards)

        if archive_level:
            return report  # enforce the limits: do not read a single member

        if analyzer is None:
            from porter.analyzer import SuitabilityAnalyzer
            analyzer = SuitabilityAnalyzer(harness_root=harness_root)

        for idx, info in enumerate(infos):
            member = report.members[idx]
            if info.is_dir() or member_hazards[idx] or not info.filename.lower().endswith(TEXT_SUFFIXES):
                continue
            if info.file_size > MAX_ANALYZED_MEMBER_BYTES:
                report.hazards.append(ArchiveHazard(
                    "MEMBER_TOO_LARGE", info.filename,
                    f"{info.file_size} bytes exceeds the analysis bound of {MAX_ANALYZED_MEMBER_BYTES}; not analyzed"))
                continue
            try:
                data = _read_bounded(zf, info, MAX_ANALYZED_MEMBER_BYTES)
            except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError, RuntimeError, EOFError) as e:
                member.error = f"could not read member: {type(e).__name__}: {e}"
                report.hazards.append(ArchiveHazard("UNREADABLE_MEMBER", info.filename, member.error))
                continue
            try:
                result = analyzer.analyze(data.decode("utf-8", errors="replace"),
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
    return report
