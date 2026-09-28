from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

QUARANTINE_DIR = Path.home() / ".blackhole_av" / "quarantine"


def ensure_sandbox() -> Path:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    return QUARANTINE_DIR


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quarantine_file(filepath: str | os.PathLike[str]) -> dict[str, str]:
    """Move a file into a quarantine directory and record metadata.

    This is quarantine storage, not a secure OS-level sandbox and it does not execute files.
    """
    source = Path(filepath).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(str(source))

    destination_dir = ensure_sandbox()
    digest = _sha256(source)
    destination = destination_dir / f"{digest}.quarantined"
    metadata = destination_dir / f"{digest}.json"

    if destination.exists():
        raise FileExistsError(f"Quarantine item already exists: {destination}")

    shutil.move(str(source), str(destination))

    # Best-effort permission lockdown. Windows ignores most POSIX mode bits;
    # real isolation requires an OS sandbox/container/AppContainer-style boundary.
    try:
        destination.chmod(0o000)
    except OSError:
        pass

    record = {
        "original_path": str(source),
        "quarantine_path": str(destination),
        "sha256": digest,
        "timestamp": time.time(),
        "platform": os.name,
    }
    metadata.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def sandbox_file(filepath: str | os.PathLike[str]) -> str:
    record = quarantine_file(filepath)
    return f"Quarantined: {record['original_path']} -> {record['quarantine_path']}"


# Backward-compatible name used by the original prototype.
def run_in_sandbox(filepath: str | os.PathLike[str]) -> str:
    return sandbox_file(filepath)
