"""Static attachment checks: real file type, risky extensions, macros, archives.

Archives are inspected via their directory only; nothing is ever extracted or executed.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath

from phishanalyzer.models import Attachment, Email, Finding, Severity

# Executable or script formats that run code when opened on Windows/macOS.
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "pif", "com", "bat", "cmd", "cpl", "msi", "msp", "msc", "dll", "ocx", "sys",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "ws", "hta", "ps1", "psm1", "jar", "reg",
    "chm", "hlp", "lnk", "scf", "url", "inf", "sct", "shb", "shs", "xll", "appx", "msix",
    "appref-ms", "iso", "img", "vhd", "vhdx", "dmg", "app", "pkg", "one", "application",
}  # fmt: skip
HTML_EXTENSIONS = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
MACRO_EXTENSIONS = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "sldm"}
DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "zip"}
OTHER_ARCHIVES = {"rar", "7z", "gz", "tgz", "bz2", "xz", "cab", "arj", "ace", "lzh", "tar"}

# Magic numbers -> file kind.
_MAGIC = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
)
# Kinds each extension may legitimately contain.
_EXPECTED_KINDS = {
    "pdf": {"pdf"},
    "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"}, "msg": {"ole"},
    "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "zip": {"zip"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
    "txt": {None}, "csv": {None},
}  # fmt: skip

_MAX_ZIP_ENTRIES = 1000


def sniff(data: bytes) -> str | None:
    return next((kind for magic, kind in _MAGIC if data.startswith(magic)), None)


def _extensions(filename: str) -> list[str]:
    """`Invoice.PDF.exe` -> ["pdf", "exe"] (lowercased, trailing dots/spaces removed)."""
    name = filename.strip().rstrip(". ").lower()
    return [s.lstrip(".") for s in PurePosixPath(name).suffixes if 1 < len(s) <= 12]


def _has_vba(att: Attachment, kind: str | None) -> bool:
    if kind == "ole":
        return b"_VBA_PROJECT" in att.data or "_VBA_PROJECT".encode("utf-16-le") in att.data
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(att.data)) as zf:
                return any(n.lower().endswith("vbaproject.bin") for n in zf.namelist())
        except (zipfile.BadZipFile, ValueError, OSError):
            return False
    return False


class AttachmentAnalyzer:
    name = "attachments"

    async def analyze(self, email: Email) -> list[Finding]:
        findings: list[Finding] = []
        for att in email.attachments:
            findings += self._check(att)
        return findings

    def _check(self, att: Attachment) -> list[Finding]:
        name = att.filename or "(unnamed)"
        exts = _extensions(att.filename or "")
        final = exts[-1] if exts else ""
        kind = sniff(att.data)
        evidence = {"filename": name, "sha256": att.sha256, "detected_type": kind}
        findings: list[Finding] = []

        def add(signal: str, points: int, severity: Severity, message: str, **extra) -> None:
            findings.append(
                Finding(
                    signal=signal,
                    points=points,
                    severity=severity,
                    message=message,
                    evidence={**evidence, **extra},
                )
            )

        if final in DANGEROUS_EXTENSIONS or kind in ("pe", "elf"):
            add(
                "attachments.dangerous_type",
                40,
                Severity.HIGH,
                f"Attachment '{name}' is an executable or script file.",
            )
        if len(exts) >= 2 and exts[-2] in DECOY_EXTENSIONS and final not in DECOY_EXTENSIONS:
            add(
                "attachments.double_extension",
                25,
                Severity.HIGH,
                f"Attachment '{name}' disguises its real type with a double extension.",
            )
        expected = _EXPECTED_KINDS.get(final)
        if expected is not None and kind not in expected and att.size > 0:
            add(
                "attachments.type_mismatch",
                25,
                Severity.HIGH,
                f"Attachment '{name}' claims to be .{final} but its content is "
                f"{kind or 'something else'}.",
            )
        if final in MACRO_EXTENSIONS or _has_vba(att, kind):
            add(
                "attachments.macro",
                30,
                Severity.HIGH,
                f"Attachment '{name}' contains Office macros, a common malware dropper.",
            )
        if final in HTML_EXTENSIONS:
            add(
                "attachments.html",
                20,
                Severity.HIGH,
                f"Attachment '{name}' is an HTML/SVG page; these are used to show fake "
                "login pages offline or to smuggle malware past filters.",
            )
        if kind == "zip" and final not in {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm"}:
            findings += self._zip(att, name, evidence)
        elif final in OTHER_ARCHIVES or kind in ("rar", "7z"):
            add(
                "attachments.archive_uninspectable",
                10,
                Severity.LOW,
                f"Attachment '{name}' is an archive format that could not be inspected.",
            )
        return findings

    def _zip(self, att: Attachment, name: str, evidence: dict) -> list[Finding]:
        try:
            with zipfile.ZipFile(io.BytesIO(att.data)) as zf:
                entries = zf.infolist()[:_MAX_ZIP_ENTRIES]
        except (zipfile.BadZipFile, ValueError, OSError):
            return []
        findings = []
        if any(e.flag_bits & 0x1 for e in entries):
            findings.append(
                Finding(
                    signal="attachments.encrypted_archive",
                    points=20,
                    severity=Severity.MEDIUM,
                    message=f"Attachment '{name}' is a password-protected archive, which "
                    "hides its contents from security scanners.",
                    evidence=evidence,
                )
            )
        risky = [
            e.filename
            for e in entries
            if (x := _extensions(PurePosixPath(e.filename).name))
            and (x[-1] in DANGEROUS_EXTENSIONS or x[-1] in MACRO_EXTENSIONS)
        ]
        if risky:
            findings.append(
                Finding(
                    signal="attachments.archive_dangerous",
                    points=35,
                    severity=Severity.HIGH,
                    message=f"Archive '{name}' contains executable or macro files "
                    f"({', '.join(risky[:3])}).",
                    evidence={**evidence, "entries": risky[:10]},
                )
            )
        return findings
