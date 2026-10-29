#!/usr/bin/env python3
"""
installers/packaging/package_linux.py — Native Linux Distribution Package Generator
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Zero external dependencies: uses strictly Python standard library & native OS tools.

Generates:
1. Debian Package (.deb) via dpkg-deb or pure Python ar container.
2. Red Hat / Fedora Package (.rpm) via rpmbuild spec.
3. Arch Linux Package (.pkg.tar.zst / .pkg.tar.xz) with .PKGINFO metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard import __version__ as GUARD_VERSION


def calculate_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class LinuxPackager:
    def __init__(
        self,
        repo_root: Optional[Path] = None,
        version: Optional[str] = None,
        arch: str = "amd64",
        out_dir: Optional[Path] = None,
        binary_path: Optional[Path] = None,
    ):
        self.repo_root = (repo_root or REPO_ROOT).resolve()
        self.version = version or GUARD_VERSION
        self.arch = arch
        self.out_dir = (out_dir or self.repo_root / "dist" / "packages").resolve()
        self.binary_path = Path(binary_path).resolve() if binary_path else None

    def ensure_out_dir(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)

    @property
    def changelog_date(self) -> str:
        """RPM changelog date for this build (honours SOURCE_DATE_EPOCH for reproducible builds)."""
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
        t = time.gmtime(epoch)
        days = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        return f"{days[t.tm_wday]} {months[t.tm_mon - 1]} {t.tm_mday:02d} {t.tm_year}"

    @staticmethod
    def _payload_size(stage: Path) -> int:
        return sum(p.stat().st_size for p in stage.rglob("*") if p.is_file() and p.name != ".PKGINFO")

    def prepare_payload(self, staging_dir: Path) -> None:
        """Public seam: populate a staging directory with the package's FHS payload."""
        self._prepare_payload(staging_dir)

    def build_deb_archive(self, stage: Path, target_deb: Path) -> Path:
        """Public seam: write a .deb (ar archive) from an already prepared stage."""
        return self._build_deb_pure_python(stage, target_deb)

    def validate_inputs(self) -> None:
        """Fail closed if explicit --binary or mandatory repository payload entries are absent."""
        if self.binary_path is not None and not self.binary_path.is_file():
            raise FileNotFoundError(f"Explicit --binary path does not exist: {self.binary_path}")
        for pkg in ("guard", "porter", "scripts"):
            if not (self.repo_root / pkg).is_dir():
                raise FileNotFoundError(f"Mandatory package directory missing: {self.repo_root / pkg}")
        for req_file in (
            "guard.py",
            "porter.py",
            "GEMINI.md",
            "DESIGN.md",
            "MISTAKES.md",
            "README.md",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "hooks.json",
            ".harness/manifest.json",
        ):
            if not (self.repo_root / req_file).is_file():
                raise FileNotFoundError(f"Mandatory package file missing: {self.repo_root / req_file}")
        for folder in ("templates", "skills", "agents"):
            if not (self.repo_root / folder).is_dir():
                raise FileNotFoundError(f"Mandatory governance directory missing: {self.repo_root / folder}")

    def _prepare_payload(self, staging_dir: Path) -> None:
        """Populates staging directory with standard Linux FHS hierarchy."""
        self.validate_inputs()
        bin_dir = staging_dir / "usr" / "bin"
        apps_dir = staging_dir / "usr" / "share" / "applications"
        icons_dir = staging_dir / "usr" / "share" / "icons" / "hicolor" / "scalable" / "apps"
        docs_dir = staging_dir / "usr" / "share" / "antigravity-harness"
        comp_dir = staging_dir / "usr" / "share" / "bash-completion" / "completions"

        for d in (bin_dir, apps_dir, icons_dir, docs_dir, comp_dir):
            d.mkdir(parents=True, exist_ok=True)

        # 1. Binary or launcher (plus Porter & scripts runtime library)
        dest_bin = bin_dir / "agy-guard"
        dest_porter = bin_dir / "agy-porter"
        lib_dir = staging_dir / "usr" / "lib" / "antigravity-guard"
        lib_dir.mkdir(parents=True, exist_ok=True)
        ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")

        if self.binary_path is not None:
            shutil.copy2(self.binary_path, dest_bin)
        else:
            # Standalone launcher invoking system python3
            dest_bin.write_text(
                "#!/bin/sh\nexec python3 /usr/lib/antigravity-guard/guard.py \"$@\"\n",
                encoding="utf-8"
            )

        for pkg in ("guard", "porter", "scripts"):
            shutil.copytree(self.repo_root / pkg, lib_dir / pkg, dirs_exist_ok=True, ignore=ignore)
        shutil.copy2(self.repo_root / "guard.py", lib_dir / "guard.py")
        shutil.copy2(self.repo_root / "porter.py", lib_dir / "porter.py")
        dest_porter.write_text(
            "#!/bin/sh\nexec python3 /usr/lib/antigravity-guard/porter.py \"$@\"\n",
            encoding="utf-8"
        )
        dest_porter.chmod(0o755)
        dest_bin.chmod(0o755)

        # 2. Desktop entry
        desktop_src = self.repo_root / "installers" / "antigravity-guard.desktop"
        if desktop_src.exists():
            shutil.copy2(desktop_src, apps_dir / "antigravity-guard.desktop")
        else:
            (apps_dir / "antigravity-guard.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Antigravity Guard\nComment=OS-Level AI Governance Shield\nExec=agy-guard gui\nIcon=antigravity-guard\nTerminal=false\nCategories=Development;Security;\n",
                encoding="utf-8"
            )

        # 3. Icon
        icon_src = self.repo_root / "installers" / "packaging" / "antigravity-guard.svg"
        if icon_src.exists():
            shutil.copy2(icon_src, icons_dir / "antigravity-guard.svg")

        # 4. Governance Docs, Hooks, Manifest & Templates
        for name in ("GEMINI.md", "DESIGN.md", "MISTAKES.md", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "hooks.json"):
            shutil.copy2(self.repo_root / name, docs_dir / name)

        staged_hooks = docs_dir / "hooks.json"
        hooks_txt = staged_hooks.read_text(encoding="utf-8")
        src_uw = "skills/upstream-auditor/scripts/upstream_watcher.py"
        src_hg = "guard/agy_hooks.py"
        if src_uw not in hooks_txt or src_hg not in hooks_txt:
            raise ValueError(f"Expected hook script paths ({src_uw}, {src_hg}) not found in {staged_hooks}")
        hooks_txt = hooks_txt.replace(
            src_uw,
            "/usr/share/antigravity-harness/skills/upstream-auditor/scripts/upstream_watcher.py",
        ).replace(
            src_hg,
            "/usr/lib/antigravity-guard/guard/agy_hooks.py",
        )
        parsed_hooks = __import__("json").loads(hooks_txt)
        if not isinstance(parsed_hooks, dict):
            raise ValueError(f"Rewritten {staged_hooks} is not a valid JSON object")
        staged_hooks.write_text(hooks_txt, encoding="utf-8")

        manifest_src = self.repo_root / ".harness" / "manifest.json"
        (docs_dir / ".harness").mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest_src, docs_dir / ".harness" / "manifest.json")

        for folder in ("templates", "skills", "agents"):
            shutil.copytree(self.repo_root / folder, docs_dir / folder, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))

        skills_stage = docs_dir / "skills"
        if skills_stage.is_dir():
            for sdir in skills_stage.rglob("scripts"):
                if sdir.is_dir() and not sdir.is_symlink():
                    for sc in sdir.rglob("*"):
                        if sc.suffix in (".py", ".sh", ".mjs") and sc.is_file() and not sc.is_symlink():
                            sc.chmod(0o755)
            ah_stage = skills_stage / "antislop-human"
            if ah_stage.is_dir() and not ah_stage.is_symlink():
                for sc in ah_stage.glob("contrast-*.py"):
                    if sc.is_file() and not sc.is_symlink():
                        sc.chmod(0o755)

        # 5. Bash completion
        comp_content = """# Bash completion for agy-guard
_agy_guard_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="init status lock unlock verify rebaseline env request-unlock lock-complete drift self-audit snapshot porter upstream test-boundary provenance startup boot-check doctor notify gui"
    COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
}
complete -F _agy_guard_completions agy-guard
"""
        (comp_dir / "agy-guard").write_text(comp_content, encoding="utf-8")

    def build_deb(self) -> Optional[Path]:
        """Builds a Debian / Ubuntu .deb package."""
        self.ensure_out_dir()
        deb_arch = "amd64" if self.arch in ("x86_64", "amd64") else ("arm64" if self.arch in ("arm64", "aarch64") else self.arch)
        package_name = f"antigravity-guard_{self.version}_{deb_arch}.deb"
        target_deb = self.out_dir / package_name

        with tempfile.TemporaryDirectory() as tmpdir:
            stage = Path(tmpdir) / "stage"
            self._prepare_payload(stage)

            # Control file
            deb_dir = stage / "DEBIAN"
            deb_dir.mkdir(parents=True, exist_ok=True)

            control_content = f"""Package: antigravity-guard
Version: {self.version}
Section: devel
Priority: optional
Architecture: {deb_arch}
Depends: python3 (>= 3.10)
Recommends: libnotify-bin, python3-tk
Suggests: nodejs, ffmpeg
Maintainer: Had Bilen <https://github.com/hadbilen/antigravity-harness>
Description: OS-Level Governance, Write Protection, & Multi-Environment Integrity Suite
 Antigravity Guard (agy-guard) enforces OS write protection, cryptographic
 SHA-256 file integrity monitoring (FIM), and multi-environment governance
 across Antigravity, Claude Code, GPT Codex, Cursor, and Aider agent environments.
"""
            (deb_dir / "control").write_text(control_content, encoding="utf-8")

            # Try dpkg-deb first
            dpkg_deb = shutil.which("dpkg-deb")
            if dpkg_deb:
                res = subprocess.run([dpkg_deb, "--build", "--root-owner-group", str(stage), str(target_deb)], capture_output=True, text=True)
                if res.returncode != 0:
                    detail = (res.stderr or res.stdout or "").strip()
                    raise RuntimeError(f"dpkg-deb failed with exit code {res.returncode}: {detail}")
                return target_deb

            # Pure Python .deb container creation (ar format)
            return self._build_deb_pure_python(stage, target_deb)

    def _build_deb_pure_python(self, stage: Path, target_deb: Path) -> Path:
        """Pure-Python .deb archive generator (zero external dpkg dependency)."""
        def _root_tar_filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
            tarinfo.uid = 0
            tarinfo.gid = 0
            tarinfo.uname = "root"
            tarinfo.gname = "root"
            return tarinfo

        # 1. debian-binary
        deb_binary = b"2.0\n"

        # 2. control.tar.gz
        control_buf = io.BytesIO()
        with tarfile.open(fileobj=control_buf, mode="w:gz") as tar:
            for f in (stage / "DEBIAN").iterdir():
                tar.add(f, arcname=f.name, filter=_root_tar_filter)
        control_data = control_buf.getvalue()

        # 3. data.tar.gz
        data_buf = io.BytesIO()
        with tarfile.open(fileobj=data_buf, mode="w:gz") as tar:
            for item in stage.iterdir():
                if item.name == "DEBIAN":
                    continue
                tar.add(item, arcname=item.name, filter=_root_tar_filter)
        data_data = data_buf.getvalue()

        # Construct ar archive: Global magic "!<arch>\n" + entries
        def make_ar_header(name: str, size: int) -> bytes:
            name_field = f"{name:<16}"
            timestamp = f"{int(time.time()):<12}"
            owner = f"{'0':<6}"
            group = f"{'0':<6}"
            mode = f"{'100644':<8}"
            size_field = f"{size:<10}"
            fmag = "`\n"
            return f"{name_field}{timestamp}{owner}{group}{mode}{size_field}{fmag}".encode("ascii")

        target_deb.parent.mkdir(parents=True, exist_ok=True)
        with open(target_deb, "wb") as f:
            f.write(b"!<arch>\n")
            # debian-binary
            f.write(make_ar_header("debian-binary", len(deb_binary)))
            f.write(deb_binary)
            if len(deb_binary) % 2 != 0:
                f.write(b"\n")
            # control.tar.gz
            f.write(make_ar_header("control.tar.gz", len(control_data)))
            f.write(control_data)
            if len(control_data) % 2 != 0:
                f.write(b"\n")
            # data.tar.gz
            f.write(make_ar_header("data.tar.gz", len(data_data)))
            f.write(data_data)
            if len(data_data) % 2 != 0:
                f.write(b"\n")

        return target_deb

    def build_rpm(self) -> Optional[Path]:
        """Generates RPM spec and builds .rpm package if rpmbuild is available."""
        self.ensure_out_dir()
        rpm_arch = "x86_64" if self.arch in ("x86_64", "amd64") else ("aarch64" if self.arch in ("arm64", "aarch64") else self.arch)
        package_name = f"antigravity-guard-{self.version}-1.{rpm_arch}.rpm"
        target_rpm = self.out_dir / package_name

        spec_content = f"""Name:           antigravity-guard
Version:        {self.version}
Release:        1%{{?dist}}
Summary:        OS-Level AI Governance Shield & Multi-Environment Integrity Suite
License:        MIT AND Apache-2.0
URL:            https://github.com/hadbilen/antigravity-harness
BuildArch:      {rpm_arch}
Requires:       python3 >= 3.10
Recommends:     python3-tkinter

%description
Antigravity Guard (agy-guard) enforces OS-level write protection, cryptographic
SHA-256 file integrity monitoring (FIM), and multi-environment governance across
Antigravity, Claude Code, GPT Codex, Cursor, and Aider agent environments.

%prep
# No prep required

%build
# Built in stage

%install
rm -rf %{{buildroot}}
mkdir -p %{{buildroot}}
cp -r %{{_sourcedir}}/stage/* %{{buildroot}}/

%files
/usr/bin/agy-guard
/usr/bin/agy-porter
/usr/lib/antigravity-guard
/usr/share/applications/antigravity-guard.desktop
/usr/share/icons/hicolor/scalable/apps/antigravity-guard.svg
/usr/share/antigravity-harness
/usr/share/bash-completion/completions/agy-guard

%changelog
* {self.changelog_date} Had Bilen <hadbilen@users.noreply.github.com> - {self.version}-1
- Release {self.version}; see CHANGELOG.md for details
"""
        spec_path = self.out_dir / "antigravity-guard.spec"
        spec_path.write_text(spec_content, encoding="utf-8")

        rpmbuild = shutil.which("rpmbuild")
        if not rpmbuild:
            print(f"[INFO] rpmbuild not found in PATH. Generated spec at {spec_path}")
            return spec_path

        with tempfile.TemporaryDirectory() as tmpdir:
            rpm_root = Path(tmpdir)
            for d in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
                (rpm_root / d).mkdir()

            stage = rpm_root / "SOURCES" / "stage"
            self._prepare_payload(stage)

            cmd = [
                rpmbuild,
                "-bb",
                f"--define=_topdir {rpm_root}",
                f"--target={rpm_arch}",
                str(spec_path),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                detail = (res.stderr or res.stdout or "").strip()
                raise RuntimeError(f"rpmbuild failed with exit code {res.returncode}: {detail}")
            for f in (rpm_root / "RPMS").rglob("*.rpm"):
                shutil.copy2(f, target_rpm)
                return target_rpm
            raise RuntimeError("rpmbuild exited 0 but produced no .rpm package artifact")

    def build_arch(self) -> Path:
        """Builds an Arch Linux package (.pkg.tar.zst or fallback .pkg.tar.xz)."""
        self.ensure_out_dir()
        arch_name = "x86_64" if self.arch in ("x86_64", "amd64") else ("aarch64" if self.arch in ("arm64", "aarch64") else self.arch)
        package_name = f"antigravity-guard-{self.version}-1-{arch_name}.pkg.tar.zst"
        target_pkg = self.out_dir / package_name

        with tempfile.TemporaryDirectory() as tmpdir:
            stage = Path(tmpdir) / "stage"
            self._prepare_payload(stage)

            pkginfo = f"""pkgname = antigravity-guard
pkgver = {self.version}-1
pkgdesc = OS-Level AI Governance Shield & Multi-Environment Integrity Suite
url = https://github.com/hadbilen/antigravity-harness
builddate = {int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))}
packager = Had Bilen <https://github.com/hadbilen/antigravity-harness>
size = {self._payload_size(stage)}
arch = {arch_name}
license = MIT
license = Apache-2.0
depend = python>=3.10
optdepend = libnotify: Desktop notifications
optdepend = tk: Desktop GUI interface (agy-guard gui)
optdepend = nodejs: JavaScript syntax verification and UI tooling
optdepend = ffmpeg: Media studio audio/video verification and processing
"""
            (stage / ".PKGINFO").write_text(pkginfo, encoding="utf-8")

            # Check if zstd is available, otherwise use .pkg.tar.xz
            has_zstd = shutil.which("zstd") is not None
            if not has_zstd:
                target_pkg = self.out_dir / f"antigravity-guard-{self.version}-1-{arch_name}.pkg.tar.xz"

            entries = [".PKGINFO"] + sorted(p.name for p in stage.iterdir() if p.name != ".PKGINFO")
            tar_cmd = shutil.which("tar")
            if tar_cmd and has_zstd:
                cmd = [
                    tar_cmd,
                    "--zstd",
                    "--owner=0",
                    "--group=0",
                    "--numeric-owner",
                    "-cf",
                    str(target_pkg),
                    *entries,
                ]
                res = subprocess.run(cmd, cwd=stage, capture_output=True)
                if res.returncode != 0:
                    raw_err = res.stderr.decode("utf-8", errors="replace") if isinstance(res.stderr, bytes) else str(res.stderr or "")
                    detail = raw_err.strip()
                    raise RuntimeError(f"tar --zstd failed with exit code {res.returncode}: {detail}")
                return target_pkg

            # Python tarfile fallback
            def _root_tar_filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
                tarinfo.uid = 0
                tarinfo.gid = 0
                tarinfo.uname = "root"
                tarinfo.gname = "root"
                return tarinfo

            target_pkg = self.out_dir / f"antigravity-guard-{self.version}-1-{arch_name}.pkg.tar.xz"
            with tarfile.open(target_pkg, "w:xz") as tar:
                tar.add(stage / ".PKGINFO", arcname=".PKGINFO", filter=_root_tar_filter)
                for entry_name in entries[1:]:
                    tar.add(stage / entry_name, arcname=entry_name, filter=_root_tar_filter)

            return target_pkg


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="package_linux",
        description="Native Linux Distribution Packaging Utility for Antigravity Guard"
    )
    parser.add_argument("--format", choices=["deb", "rpm", "arch", "all"], default="all", help="Target package format")
    parser.add_argument("--all", action="store_true", help="Build all package formats (deb, rpm, arch)")
    parser.add_argument("--arch", choices=["x86_64", "amd64", "arm64", "aarch64"], default="x86_64", help="Architecture")
    parser.add_argument("--binary", help="Path to pre-built pyinstaller standalone binary")
    parser.add_argument("--out-dir", "--output-dir", dest="out_dir", help="Output directory path (default: dist/packages)")
    parser.add_argument("--version", help="Override package version string")
    parser.add_argument("--check-only", action="store_true", help="Validate packaging inputs without building archives")
    args = parser.parse_args()

    if args.all:
        args.format = "all"

    packager = LinuxPackager(
        version=args.version,
        arch=args.arch,
        out_dir=Path(args.out_dir) if args.out_dir else None,
        binary_path=Path(args.binary) if args.binary else None,
    )

    try:
        packager.validate_inputs()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.check_only:
        print("Packaging configuration valid:")
        print(f"  Version: {packager.version}")
        print(f"  Arch   : {packager.arch}")
        print(f"  Output : {packager.out_dir}")
        return 0

    print("=" * 64)
    print(f"   Building Linux Distribution Packages for Antigravity Guard v{packager.version}   ")
    print("=" * 64)

    generated: List[Path] = []
    formats = ["deb", "rpm", "arch"] if args.format == "all" else [args.format]

    try:
        for fmt in formats:
            if fmt == "deb":
                deb_path = packager.build_deb()
                if deb_path and deb_path.is_file():
                    generated.append(deb_path)
                    print(f"✅ [.DEB] Built Debian package: {deb_path.name} ({deb_path.stat().st_size} bytes)")
            elif fmt == "rpm":
                rpm_path = packager.build_rpm()
                if rpm_path and rpm_path.is_file():
                    if rpm_path.suffix == ".spec":
                        if args.format == "rpm":
                            print(
                                f"[ERROR] rpmbuild is not installed; generated spec only ({rpm_path}), no .rpm package built.",
                                file=sys.stderr,
                            )
                            return 1
                        print(f"[INFO] Generated RPM spec (rpmbuild not installed): {rpm_path.name}")
                    else:
                        generated.append(rpm_path)
                        print(f"✅ [.RPM] Built RPM package: {rpm_path.name} ({rpm_path.stat().st_size} bytes)")
            elif fmt == "arch":
                arch_path = packager.build_arch()
                if arch_path and arch_path.is_file():
                    generated.append(arch_path)
                    print(f"✅ [ARCH] Built Arch Linux package: {arch_path.name} ({arch_path.stat().st_size} bytes)")
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print("-" * 64)
    print(f"Summary: Generated {len(generated)} package artifact(s) in {packager.out_dir}")
    for p in generated:
        if p.suffix in (".deb", ".rpm", ".zst", ".xz"):
            print(f"  SHA-256 ({p.name}) = {calculate_sha256(p)}")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
