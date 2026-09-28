# Blackhole Antivirus Prototype

A **cross-platform Python antivirus prototype** for defensive/security-learning experiments. The current code is a small heuristic scanner with a Tkinter GUI, process viewer, quarantine (“blackhole”) storage, and an experimental hash-based audit logger.

## ⚠️ Project Status

**Work in progress / incomplete prototype.**

The original idea was more ambitious: automatically detect malicious files, pull them into a “black hole”, and execute them inside a strong isolated sandbox for behavioral analysis. **That complete system was never finished.** The current repository does **not** implement a real malware-detonation sandbox and does not execute detected files.

What is implemented today is primarily:

- filename/extension heuristic detection;
- optional scanning of selected directories;
- manual quarantine into a dedicated local directory;
- report-only command-line scanning;
- optional automatic quarantine from the CLI;
- a Tkinter desktop interface;
- basic process listing (`tasklist` on Windows, `ps` on Unix-like systems);
- SHA-256 file hashing and quarantine metadata;
- an experimental append-only audit log module.

The detector is intentionally simple and will produce **false positives and false negatives**. It is not a production antivirus engine.

## Platform Support

The core Python code is designed to run on **Windows and Linux** (and should also work on other Unix-like systems).

The GUI was updated to use platform-appropriate process listing, so it no longer depends on Linux-only `ps` commands on Windows.

However, the original project was clearly more Linux-oriented in places: its first GUI version scanned `/home` and `/etc`, used `chmod`, and called `ps`. These were prototype assumptions, not evidence of a finished cross-platform security product.

## Architecture

```text
Filesystem
   ↓
Heuristic detector
   ↓
SAFE / THREAT / ERROR
   ↓
GUI or CLI report
   ↓
Optional quarantine
   ↓
~/.blackhole_av/quarantine/
   ├── <sha256>.quarantined
   └── <sha256>.json
```

### Important sandbox distinction

The “blackhole” is currently **quarantine storage**, not a hardened sandbox. The project does not create a VM, container, seccomp/AppContainer boundary, network-isolated execution environment, or other strong process isolation layer.

Detected files are **not executed** by the current implementation.

## Requirements

- Python 3.10+ recommended
- Tkinter for the desktop GUI
- No third-party Python packages are currently required

### Windows

A standard Python installation normally includes Tkinter. Verify:

```powershell
python --version
python -m tkinter
```

### Ubuntu/Debian

Install Tkinter and common process/file utilities if needed:

```bash
sudo apt update
sudo apt install -y python3-tk procps file
```

## Run the GUI

From the project directory:

```bash
python gui.py
```

Choose a folder, press **Start**, inspect detected files, and use **Quarantine** only on files you are authorized to isolate.

The default scan location is the current user's home directory. Selecting a specific test folder is recommended.

## Command-Line Scanner

Report-only, one pass:

```bash
python main.py ./test_files --once
```

Continuous report-only scan:

```bash
python main.py ./test_files
```

Opt-in quarantine:

```bash
python main.py ./test_files --once --quarantine
```

The default mode is report-only so a heuristic match does not automatically move files.

## Test the detector safely

The repository contains sample files intended for security research/testing. **Do not execute unknown sample payloads.** For harmless functional checks, create your own benign files such as:

```text
safe.txt
payload_demo.txt
```

Then scan the directory and observe the heuristic result.

## Quarantine

Quarantined files are stored under:

```text
~/.blackhole_av/quarantine/
```

Each item receives a SHA-256-derived filename and a JSON metadata record containing the original path, quarantine path, hash, timestamp, and platform.

On POSIX systems the project attempts to remove normal file permissions after quarantine. On Windows, POSIX mode bits are not a security boundary, so this must **not** be treated as a hardened isolation mechanism.

## What is not finished

The original concept would need substantially more engineering before it could be considered a real antivirus product, including:

- a robust multi-signal malware detection engine;
- Windows-native and Linux-native filesystem/process monitoring;
- real quarantine with strong OS permissions/ACLs;
- safe sample analysis in a disposable VM or hardened sandbox;
- network isolation and controlled egress;
- behavioral telemetry and process/file/network monitoring;
- signature/YARA-style scanning;
- updateable threat intelligence;
- rollback/recovery workflows;
- a secure service/daemon architecture;
- automated tests and CI;
- proper code signing and production packaging.

## Safety

This repository is a defensive security prototype. It should be developed and tested only on systems and files you are authorized to analyze. Do not run unknown malware samples on a normal workstation.

The repository intentionally does **not** provide an automatic “detect → execute malware” path. Any future dynamic analysis system should use a dedicated disposable analysis environment with strong isolation rather than relying on a normal application process.

## License

MIT — see [`LICENSE`](LICENSE).
