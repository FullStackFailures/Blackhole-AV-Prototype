from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SUSPICIOUS_EXT = {".exe", ".dll", ".scr", ".msi", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".sh", ".bin"}
SUSPICIOUS_NAMES = {"hack", "keylog", "inject", "payload", "ransom", "dropper", "backdoor"}
DOUBLE_EXTENSION_MARKERS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip"}


@dataclass(frozen=True)
class DetectionResult:
    suspicious: bool
    reasons: tuple[str, ...]


def analyze(path: str | os.PathLike[str]) -> DetectionResult:
    """Heuristic-only detection. This does not execute the target file."""
    try:
        name = Path(path).name.lower()
        suffix = Path(name).suffix
        reasons: list[str] = []

        if suffix in SUSPICIOUS_EXT:
            reasons.append(f"suspicious extension: {suffix}")

        if any(word in name for word in SUSPICIOUS_NAMES):
            reasons.append("suspicious filename keyword")

        parts = Path(name).name.split(".")
        if len(parts) >= 3 and f".{parts[-2]}" in DOUBLE_EXTENSION_MARKERS and suffix in SUSPICIOUS_EXT:
            reasons.append("double-extension pattern")

        # POSIX executables/scripts are interesting, but executability alone is not malware.
        try:
            if os.name == "posix" and os.access(path, os.X_OK):
                reasons.append("executable filesystem permission")
        except OSError:
            pass

        return DetectionResult(bool(reasons), tuple(dict.fromkeys(reasons)))
    except OSError:
        return DetectionResult(False, ())


def is_suspicious(path: str | os.PathLike[str]) -> bool:
    return analyze(path).suspicious
