from __future__ import annotations

import argparse
import os
import time
from collections.abc import Callable, Sequence

from detector import analyze
from sandbox import quarantine_file

running = False


def monitor(
    callback: Callable[[str, str, str], None],
    paths: Sequence[str],
    *,
    auto_quarantine: bool = False,
    interval: float = 2.0,
) -> None:
    """Continuously scan paths using heuristic detection.

    Detection is report-only by default. Set auto_quarantine=True to move detected
    files into the local quarantine directory. No detected file is executed.
    """
    global running
    running = True
    seen: set[str] = set()

    while running:
        for directory in paths:
            if not os.path.isdir(directory):
                callback(directory, "ERROR", "Scan path does not exist or is not a directory")
                continue

            for root, _, files in os.walk(directory):
                for filename in files:
                    path = os.path.abspath(os.path.join(root, filename))
                    if path in seen:
                        continue
                    seen.add(path)

                    try:
                        result = analyze(path)
                        if not result.suspicious:
                            callback(path, "SAFE", "OK")
                            continue

                        reason = "; ".join(result.reasons) or "heuristic match"
                        if auto_quarantine:
                            record = quarantine_file(path)
                            callback(path, "THREAT", f"QUARANTINED ({reason}) -> {record['quarantine_path']}")
                        else:
                            callback(path, "THREAT", f"DETECTED (report-only): {reason}")
                    except Exception as exc:
                        callback(path, "ERROR", str(exc))

        time.sleep(max(interval, 0.1))


def stop() -> None:
    global running
    running = False


def _console_callback(path: str, status: str, result: str) -> None:
    print(f"[{status}] {path} :: {result}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Blackhole AV prototype scanner")
    parser.add_argument("paths", nargs="+", help="Directories to scan")
    parser.add_argument("--quarantine", action="store_true", help="Quarantine detected files instead of report-only mode")
    parser.add_argument("--once", action="store_true", help="Run one scan pass and exit")
    args = parser.parse_args()

    if args.once:
        global running
        running = True
        seen: set[str] = set()
        for directory in args.paths:
            if not os.path.isdir(directory):
                _console_callback(directory, "ERROR", "Scan path does not exist or is not a directory")
                continue
            for root, _, files in os.walk(directory):
                for filename in files:
                    path = os.path.abspath(os.path.join(root, filename))
                    if path in seen:
                        continue
                    seen.add(path)
                    try:
                        result = analyze(path)
                        if result.suspicious:
                            reason = "; ".join(result.reasons)
                            if args.quarantine:
                                record = quarantine_file(path)
                                _console_callback(path, "THREAT", f"QUARANTINED ({reason}) -> {record['quarantine_path']}")
                            else:
                                _console_callback(path, "THREAT", f"DETECTED (report-only): {reason}")
                        else:
                            _console_callback(path, "SAFE", "OK")
                    except Exception as exc:
                        _console_callback(path, "ERROR", str(exc))
        return 0

    try:
        monitor(_console_callback, args.paths, auto_quarantine=args.quarantine)
    except KeyboardInterrupt:
        stop()
        print("\nScan stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
