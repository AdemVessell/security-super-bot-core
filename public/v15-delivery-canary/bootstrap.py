#!/usr/bin/env python3
"""Hash gate for the V15 delivery canary.

The public template must pin this file's final SHA-256 out of band. This
bootstrap refuses any runner or bundled case-byte mismatch before it invokes
the reviewed runner. It accepts no command of its own; all arguments are
passed unchanged only after the hash gate succeeds.
"""

from __future__ import annotations

import sys


if not (sys.flags.isolated and sys.flags.no_site):
    print("bootstrap refused: invoke with python3 -I -S", file=sys.stderr)
    raise SystemExit(2)

import hashlib
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "secbot_toolkit.py"
EXPECTED_RUNNER_SHA256 = "85211f975cb9e98671ad7cd81bbc260a1b042fee5b998d6bebf1131b0c1fb52e"
EXPECTED_FILES = {
    "cases/access_case.mjs": "dcac3a642fd242ff31c6a326d206949c32612f4d96feb91ca14b75ee79a724f1",
    "cases/run_controls.mjs": "c288c7d35a9eaf8b89ba93e97c7b3e6b2c651e65a2ab3608d5bb0dc9b81acd1e",
    "cases/path_case.py": "41916b15943b4e04ef9cb44eb80121955db3267297a8f7758e48800aefe9bf5b",
    "cases/path_controls.py": "ee7cfb5002faf805ff48a83a052da5935136f9dbd3e3f34792afa338000ec60a",
    "cases/node-tmp-historical/harness.mjs": "a704fc03f1b476a3a13541eda900540288077de6f30662cab0a3593c75234734",
    "cases/node-tmp-historical/lib/tmp.js": "5f5eef7faf6251c16f3b75668e463fb17b2d9fab3f9a29a5f9ac65b082dd7e76",
    "cases/node-tmp-historical/LICENSE": "162413c61e0982abe89a06bf7a02ec760dc49a7364d838bd9f01daebb5b95954",
}
RUNTIME_FILES = {"bootstrap.py", "secbot_toolkit.py", *EXPECTED_FILES}
EXPECTED_DIRECTORIES = {"cases", "cases/node-tmp-historical", "cases/node-tmp-historical/lib"}
MINIMAL_ENV = {
    "HOME": "/tmp",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1",
    "TMPDIR": "/tmp",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory() -> None:
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT).as_posix()
        if path.is_symlink():
            raise RuntimeError(f"bootstrap refused: symlink in runtime inventory: {relative}")
        if path.is_dir():
            if relative not in EXPECTED_DIRECTORIES:
                raise RuntimeError(f"bootstrap refused: unlisted directory: {relative}")
            continue
        if not path.is_file():
            raise RuntimeError(f"bootstrap refused: special file in runtime inventory: {relative}")
        if relative not in RUNTIME_FILES:
            raise RuntimeError(f"bootstrap refused: unlisted runtime file: {relative}")


def verify(*, check_inventory: bool = False) -> dict[str, object]:
    if check_inventory:
        inventory()
    if len(EXPECTED_RUNNER_SHA256) != 64 or EXPECTED_RUNNER_SHA256.startswith("__"):
        raise RuntimeError("bootstrap runner pin is not initialized")
    if not RUNNER.is_file() or sha256(RUNNER) != EXPECTED_RUNNER_SHA256:
        raise RuntimeError("bootstrap refused: runner hash mismatch")
    actual_files = {}
    for relative, expected in EXPECTED_FILES.items():
        path = ROOT / relative
        if not path.is_file() or sha256(path) != expected:
            raise RuntimeError(f"bootstrap refused: bundled file hash mismatch: {relative}")
        actual_files[relative] = expected
    return {"runner_sha256": EXPECTED_RUNNER_SHA256, "files": actual_files}


def main() -> int:
    verify_only = "--verify-only" in sys.argv[1:]
    if verify_only and len(sys.argv) != 2:
        print("bootstrap refused: --verify-only accepts no other arguments", file=sys.stderr)
        return 2
    try:
        summary = verify(check_inventory=verify_only)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if verify_only:
        import json
        print(json.dumps({"schema": "secbot.bootstrap.verify.v1", **summary}, sort_keys=True, separators=(",", ":")))
        return 0
    os.execve(sys.executable, [sys.executable, "-I", "-S", str(RUNNER), *sys.argv[1:]], dict(MINIMAL_ENV))
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
