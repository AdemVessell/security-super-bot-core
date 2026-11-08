#!/usr/bin/env python3
"""Bounded, replayable proof runner for three bundled fixtures.

This command never accepts a user-supplied executable, target, URL, or shell
fragment. It only runs immutable source packs shipped beside this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parent
CASES_DIR = ROOT / "cases"
RUNNER_PATH = Path(__file__).resolve()
SCHEMA = "secbot.toolkit.result.v1"
HASH_BASIS = "sha256(canonical-json-with-packet_sha256-omitted)"
TIMEOUT_SECONDS = 10
MAX_OUTPUT_BYTES = 64 * 1024
TRUSTED_BWRAP = Path("/usr/bin/bwrap")
MINIMAL_ENV = {
    "HOME": "/tmp",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1",
    "TMPDIR": "/tmp",
}


@dataclass(frozen=True)
class CaseSpec:
    name: str
    files: Tuple[Tuple[str, str], ...]
    command: Tuple[str, ...]
    positive_marker: str
    negative_marker: str


CASES: Dict[str, CaseSpec] = {
    "access-control": CaseSpec(
        name="access-control",
        files=(
            ("access_case.mjs", "dcac3a642fd242ff31c6a326d206949c32612f4d96feb91ca14b75ee79a724f1"),
            ("run_controls.mjs", "c288c7d35a9eaf8b89ba93e97c7b3e6b2c651e65a2ab3608d5bb0dc9b81acd1e"),
        ),
        command=("node", "run_controls.mjs"),
        positive_marker="PASS positive: alice receives bob note through missing owner check",
        negative_marker="PASS negative: owner check denies the same cross-user request",
    ),
    "path-boundary": CaseSpec(
        name="path-boundary",
        files=(
            ("path_case.py", "41916b15943b4e04ef9cb44eb80121955db3267297a8f7758e48800aefe9bf5b"),
            ("path_controls.py", "ee7cfb5002faf805ff48a83a052da5935136f9dbd3e3f34792afa338000ec60a"),
        ),
        command=("python3", "-E", "-S", "path_controls.py"),
        positive_marker="PASS positive: in-root member resolves inside permitted root",
        negative_marker="PASS negative: traversal is rejected before file access",
    ),
    "node-tmp-historical": CaseSpec(
        name="node-tmp-historical",
        files=(
            ("node-tmp-historical/harness.mjs", "a704fc03f1b476a3a13541eda900540288077de6f30662cab0a3593c75234734"),
            ("node-tmp-historical/lib/tmp.js", "5f5eef7faf6251c16f3b75668e463fb17b2d9fab3f9a29a5f9ac65b082dd7e76"),
        ),
        command=("node", "node-tmp-historical/harness.mjs"),
        positive_marker='"array_prefix": "ESCAPED_INNER_BUT_INSIDE_OUTER"',
        negative_marker='"string_prefix": "REJECTED"',
    ),
}


def canonical_bytes(value: Dict[str, Any]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("packet_sha256", None)
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def runner_sha256() -> str:
    """Hash this exact runner before preview, run, or packet validation."""
    return hashlib.sha256(RUNNER_PATH.read_bytes()).hexdigest()


def spec(name: str) -> CaseSpec:
    try:
        return CASES[name]
    except KeyError as exc:
        raise ValueError("unknown case; choose an allowlisted case") from exc


def source_hashes(case: CaseSpec) -> Dict[str, str]:
    actual: Dict[str, str] = {}
    for filename, expected in case.files:
        path = CASES_DIR / filename
        if not path.is_file():
            raise ValueError(f"bundled source missing: {filename}")
        actual[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual[filename] != expected:
            raise ValueError(f"bundled source hash mismatch: {filename}")
    return actual


def _runtime_command(case: CaseSpec, sandbox: str) -> List[str]:
    if case.name == "access-control":
        executable = shutil.which("node")
        if not executable:
            raise RuntimeError("node is unavailable; access-control cannot run")
        if sandbox == "bwrap" and Path("/usr/local/lib/nodejs/node").is_file():
            executable = "/usr/local/lib/nodejs/node"
        return [executable, "run_controls.mjs"]
    if case.name == "path-boundary":
        return [sys.executable, "-E", "-S", "path_controls.py"]
    if case.name == "node-tmp-historical":
        executable = shutil.which("node")
        if not executable:
            raise RuntimeError("node is unavailable; node-tmp-historical cannot run")
        if sandbox == "bwrap" and Path("/usr/local/lib/nodejs/node").is_file():
            executable = "/usr/local/lib/nodejs/node"
        return [executable, "node-tmp-historical/harness.mjs"]
    raise RuntimeError("unreachable case")


def _runtime_metadata(case: CaseSpec, sandbox: str) -> Tuple[List[str], str, str]:
    command = _runtime_command(case, sandbox)
    executable = str(Path(command[0]).resolve())
    command[0] = executable
    executable_hash = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    return command, executable, executable_hash


def _bwrap_profile() -> List[str]:
    return [
        "--new-session",
        "--die-with-parent",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]


def _trusted_bwrap() -> Optional[Path]:
    if TRUSTED_BWRAP.is_file() and os.access(str(TRUSTED_BWRAP), os.X_OK):
        return TRUSTED_BWRAP
    return None


def _sandbox_argv_template(sandbox: str, runtime_executable: str, runtime_args: Sequence[str]) -> List[str]:
    if sandbox != "bwrap":
        return []
    return [
        str(TRUSTED_BWRAP),
        *_bwrap_profile(),
        "--ro-bind",
        "<WORKDIR>",
        "/work",
        "--chdir",
        "/work",
        "--clearenv",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--setenv",
        "LANG",
        "C",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "PYTHONNOUSERSITE",
        "1",
        "--setenv",
        "PATH",
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "--",
        "<RUNTIME_EXECUTABLE>",
        *runtime_args,
    ]


def _sandbox_metadata(sandbox: str, runtime_executable: str, runtime_args: Sequence[str]) -> Dict[str, Any]:
    profile = _bwrap_profile() if sandbox == "bwrap" else []
    profile_hash = hashlib.sha256(json.dumps(profile, separators=(",", ":")).encode("utf-8")).hexdigest()
    argv_template = _sandbox_argv_template(sandbox, runtime_executable, runtime_args)
    argv_template_hash = hashlib.sha256(json.dumps(argv_template, separators=(",", ":")).encode("utf-8")).hexdigest()
    if sandbox == "bwrap":
        trusted = _trusted_bwrap()
        if trusted is None:
            raise RuntimeError("trusted /usr/bin/bwrap is unavailable")
        return {
            "sandbox_executable": str(trusted),
            "sandbox_executable_sha256": hashlib.sha256(trusted.read_bytes()).hexdigest(),
            "sandbox_profile": profile,
            "sandbox_profile_sha256": profile_hash,
            "sandbox_argv_template": argv_template,
            "sandbox_argv_template_sha256": argv_template_hash,
        }
    return {
        "sandbox_executable": None,
        "sandbox_executable_sha256": None,
        "sandbox_profile": profile,
        "sandbox_profile_sha256": profile_hash,
        "sandbox_argv_template": argv_template,
        "sandbox_argv_template_sha256": argv_template_hash,
    }


def approval_record(case: CaseSpec, sandbox: str, runtime_executable: str, runtime_hash: str, sandbox_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if sandbox_metadata is None:
        sandbox_metadata = _sandbox_metadata(sandbox, runtime_executable, case.command[1:])
    return {
        "schema": "secbot.toolkit.approval.v1",
        "runner_sha256": runner_sha256(),
        "execution_env": dict(MINIMAL_ENV),
        "case": case.name,
        "source_hashes": {filename: expected for filename, expected in case.files},
        "command": list(case.command),
        "timeout_seconds": TIMEOUT_SECONDS,
        "sandbox": sandbox,
        "runtime_executable": runtime_executable,
        "runtime_executable_sha256": runtime_hash,
        **sandbox_metadata,
    }


def approval_digest(case: CaseSpec, sandbox: str) -> str:
    _, executable, executable_hash = _runtime_metadata(case, sandbox)
    return digest(approval_record(case, sandbox, executable, executable_hash))


def effective_sandbox(requested: str) -> str:
    if requested == "auto":
        return "bwrap" if _trusted_bwrap() else "direct"
    if requested == "bwrap" and _trusted_bwrap() is None:
        raise RuntimeError("trusted /usr/bin/bwrap is unavailable")
    return requested


def enforce_case_sandbox(case: CaseSpec, requested: str) -> None:
    if case.name == "node-tmp-historical" and requested != "bwrap":
        raise RuntimeError("node-tmp-historical requires --sandbox bwrap")


def _bwrap_command(runtime: Sequence[str], workdir: Path) -> List[str]:
    bwrap = _trusted_bwrap()
    if not bwrap:
        raise RuntimeError("trusted /usr/bin/bwrap is unavailable")
    # Bind only interpreter/runtime directories and the newly-created fixture.
    # The fixture files are copied into /work; no home directory is mounted.
    command = list(runtime)
    # Cloud images may expose node through a shell wrapper. Execute the real
    # binary inside the restricted mount set so its interpreter is available.
    node_binary = Path("/usr/local/lib/nodejs/node")
    if command and Path(command[0]).name == "node" and node_binary.is_file():
        command[0] = str(node_binary)
    template = _sandbox_argv_template("bwrap", command[0], command[1:])
    return [str(workdir) if item == "<WORKDIR>" else command[0] if item == "<RUNTIME_EXECUTABLE>" else item for item in template]


def _copy_sources(case: CaseSpec, workdir: Path) -> None:
    for filename, expected in case.files:
        source = CASES_DIR / filename
        target = workdir / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"copied source hash mismatch: {filename}")


def _clip_output(value: Optional[str]) -> str:
    if value is None:
        return ""
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_OUTPUT_BYTES:
        return value
    return encoded[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace") + "\n[output truncated]"


def _safe_output_path(path: Path) -> Path:
    candidate = path.expanduser().resolve(strict=False)
    temp_root = Path(tempfile.gettempdir()).resolve()
    try:
        candidate.relative_to(temp_root)
    except ValueError as exc:
        raise ValueError("output must be inside the system temporary directory") from exc
    if candidate == temp_root or not candidate.name:
        raise ValueError("output must name a file inside the system temporary directory")
    try:
        os.lstat(candidate)
    except FileNotFoundError:
        return candidate
    raise ValueError("refusing to overwrite an existing output path")


def _write_exclusive(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise ValueError("refusing to overwrite an existing output path") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def _packet_base(case: CaseSpec, sandbox: str, approval: str, command: Sequence[str], runtime_executable: str, runtime_hash: str) -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "runner_sha256": runner_sha256(),
        "execution_env": dict(MINIMAL_ENV),
        "case": case.name,
        "approval_digest": approval,
        "source_hashes": {filename: expected for filename, expected in case.files},
        "command": list(case.command),
        "sandbox": sandbox,
        "timeout_seconds": TIMEOUT_SECONDS,
        "positive_marker": case.positive_marker,
        "negative_marker": case.negative_marker,
        "runtime_command": list(command),
        "runtime_executable": runtime_executable,
        "runtime_executable_sha256": runtime_hash,
        **_sandbox_metadata(sandbox, runtime_executable, case.command[1:]),
        "exit_code": None,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
        "elapsed_ms": None,
        "hash_basis": HASH_BASIS,
        "packet_sha256": "",
    }


def validate_packet(packet: Dict[str, Any]) -> None:
    allowed = {
        "schema", "runner_sha256", "execution_env", "case", "approval_digest", "source_hashes", "command", "sandbox",
        "timeout_seconds", "positive_marker", "negative_marker", "runtime_command",
        "runtime_executable", "runtime_executable_sha256",
        "sandbox_executable", "sandbox_executable_sha256", "sandbox_profile", "sandbox_profile_sha256",
        "sandbox_argv_template", "sandbox_argv_template_sha256",
        "exit_code", "timed_out", "stdout", "stderr", "elapsed_ms", "hash_basis", "packet_sha256",
    }
    if set(packet) != allowed:
        raise ValueError("packet fields are not closed")
    if packet["schema"] != SCHEMA:
        raise ValueError("unsupported packet schema")
    if packet["runner_sha256"] != runner_sha256():
        raise ValueError("runner hash does not match the current reviewed runner")
    if packet["execution_env"] != MINIMAL_ENV:
        raise ValueError("execution environment is not the fixed minimal environment")
    if not isinstance(packet["case"], str):
        raise ValueError("case must be text")
    case = spec(packet["case"])
    if not isinstance(packet["sandbox"], str) or packet["sandbox"] not in {"direct", "bwrap"}:
        raise ValueError("sandbox must be direct or bwrap")
    expected_hashes = {filename: expected for filename, expected in case.files}
    if packet["source_hashes"] != expected_hashes:
        raise ValueError("source hashes are not the approved bundled hashes")
    if packet["command"] != list(case.command):
        raise ValueError("command does not match the approved case")
    if packet["positive_marker"] != case.positive_marker or packet["negative_marker"] != case.negative_marker:
        raise ValueError("control markers do not match the approved case")
    if not isinstance(packet["runtime_executable"], str) or not Path(packet["runtime_executable"]).is_absolute():
        raise ValueError("runtime executable must be an absolute path")
    runtime_hash = packet["runtime_executable_sha256"]
    if not isinstance(runtime_hash, str) or len(runtime_hash) != 64 or any(c not in "0123456789abcdef" for c in runtime_hash):
        raise ValueError("runtime executable hash must be lowercase SHA-256")
    profile = packet["sandbox_profile"]
    if not isinstance(profile, list) or any(not isinstance(item, str) for item in profile):
        raise ValueError("sandbox profile must be a list of strings")
    profile_hash = packet["sandbox_profile_sha256"]
    if not isinstance(profile_hash, str) or len(profile_hash) != 64 or any(c not in "0123456789abcdef" for c in profile_hash):
        raise ValueError("sandbox profile hash must be lowercase SHA-256")
    computed_profile_hash = hashlib.sha256(json.dumps(profile, separators=(",", ":")).encode("utf-8")).hexdigest()
    if profile_hash != computed_profile_hash:
        raise ValueError("sandbox profile hash mismatch")
    argv_template = packet["sandbox_argv_template"]
    if not isinstance(argv_template, list) or any(not isinstance(item, str) for item in argv_template):
        raise ValueError("sandbox argv template must be a list of strings")
    argv_template_hash = packet["sandbox_argv_template_sha256"]
    if not isinstance(argv_template_hash, str) or len(argv_template_hash) != 64 or any(c not in "0123456789abcdef" for c in argv_template_hash):
        raise ValueError("sandbox argv template hash must be lowercase SHA-256")
    computed_argv_hash = hashlib.sha256(json.dumps(argv_template, separators=(",", ":")).encode("utf-8")).hexdigest()
    if argv_template_hash != computed_argv_hash:
        raise ValueError("sandbox argv template hash mismatch")
    sandbox_executable = packet["sandbox_executable"]
    sandbox_hash = packet["sandbox_executable_sha256"]
    if packet["sandbox"] == "bwrap":
        if sandbox_executable != str(TRUSTED_BWRAP) or not isinstance(sandbox_hash, str) or len(sandbox_hash) != 64 or any(c not in "0123456789abcdef" for c in sandbox_hash):
            raise ValueError("bwrap packet must bind trusted /usr/bin/bwrap and its SHA-256")
        if profile != _bwrap_profile():
            raise ValueError("sandbox profile does not match the approved bwrap profile")
        expected_template = _sandbox_argv_template("bwrap", packet["runtime_executable"], case.command[1:])
        if argv_template != expected_template:
            raise ValueError("sandbox argv template does not match the approved profile")
    elif sandbox_executable is not None or sandbox_hash is not None or profile:
        raise ValueError("direct packet must not claim a sandbox executable or profile")
    elif argv_template:
        raise ValueError("direct packet must not claim a sandbox argv template")
    sandbox_metadata = {
        "sandbox_executable": sandbox_executable,
        "sandbox_executable_sha256": sandbox_hash,
        "sandbox_profile": profile,
        "sandbox_profile_sha256": profile_hash,
        "sandbox_argv_template": argv_template,
        "sandbox_argv_template_sha256": argv_template_hash,
    }
    expected_approval = digest(approval_record(case, packet["sandbox"], packet["runtime_executable"], runtime_hash, sandbox_metadata))
    if packet["approval_digest"] != expected_approval:
        raise ValueError("approval digest does not match case, command, runtime, or sandbox")
    if not isinstance(packet["runtime_command"], list) or any(not isinstance(item, str) for item in packet["runtime_command"]) or len(packet["runtime_command"]) != len(case.command):
        raise ValueError("runtime command shape is invalid")
    if packet["runtime_command"][0] != packet["runtime_executable"] or packet["runtime_command"][1:] != list(case.command[1:]):
        raise ValueError("runtime command does not match approved arguments")
    if packet["timeout_seconds"] != TIMEOUT_SECONDS:
        raise ValueError("timeout does not match approved case")
    if not isinstance(packet["timed_out"], bool):
        raise ValueError("timed_out must be boolean")
    if packet["exit_code"] is not None and (not isinstance(packet["exit_code"], int) or isinstance(packet["exit_code"], bool)):
        raise ValueError("exit_code must be an integer or null")
    if packet["elapsed_ms"] is not None and (not isinstance(packet["elapsed_ms"], int) or isinstance(packet["elapsed_ms"], bool) or packet["elapsed_ms"] < 0):
        raise ValueError("elapsed_ms must be an integer or null")
    if not isinstance(packet["stdout"], str) or not isinstance(packet["stderr"], str):
        raise ValueError("captured output must be text")
    if packet["timed_out"] or packet["exit_code"] != 0:
        raise ValueError("execution was incomplete or failed")
    if case.positive_marker not in packet["stdout"]:
        raise ValueError("positive control marker is missing")
    if case.negative_marker not in packet["stdout"]:
        raise ValueError("negative control marker is missing")
    if packet["hash_basis"] != HASH_BASIS:
        raise ValueError("invalid hash basis")
    current = packet["packet_sha256"]
    if not isinstance(current, str) or current != digest(packet):
        raise ValueError("packet_sha256 mismatch")


def cmd_doctor() -> int:
    result = {
        "schema": "secbot.toolkit.doctor.v1",
        "python": sys.version.split()[0],
        "node": shutil.which("node"),
        "bwrap": shutil.which("bwrap"),
        "docker": "not required by this candidate",
        "cases": sorted(CASES),
        "network": "not used by bundled fixtures",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_preview(case_name: str, sandbox: str) -> int:
    case = spec(case_name)
    enforce_case_sandbox(case, sandbox)
    sandbox = effective_sandbox(sandbox)
    hashes = source_hashes(case)
    _, runtime_executable, runtime_hash = _runtime_metadata(case, sandbox)
    record = approval_record(case, sandbox, runtime_executable, runtime_hash)
    result = dict(record)
    result["source_hashes"] = hashes
    result["approval_digest"] = digest(record)
    result["execution"] = "preview only; no source or command executed"
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_run(case_name: str, sandbox: str, approved: str, output: Path) -> int:
    case = spec(case_name)
    enforce_case_sandbox(case, sandbox)
    sandbox = effective_sandbox(sandbox)
    runtime, runtime_executable, runtime_hash = _runtime_metadata(case, sandbox)
    if approved != digest(approval_record(case, sandbox, runtime_executable, runtime_hash)):
        print("REFUSED: approval digest does not match the exact runner, case, command, timeout, and sandbox", file=sys.stderr)
        return 2
    output = _safe_output_path(output)
    source_hashes(case)
    packet: Dict[str, Any]
    with tempfile.TemporaryDirectory(prefix="secbot-v13-") as temp:
        workdir = Path(temp)
        _copy_sources(case, workdir)
        command = runtime if sandbox == "direct" else _bwrap_command(runtime, workdir)
        packet = _packet_base(case, sandbox, approved, runtime, runtime_executable, runtime_hash)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=str(workdir) if sandbox == "direct" else None,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=TIMEOUT_SECONDS,
                shell=False,
                check=False,
                env=dict(MINIMAL_ENV),
            )
            packet["exit_code"] = completed.returncode
            packet["stdout"] = _clip_output(completed.stdout)
            packet["stderr"] = _clip_output(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            packet["timed_out"] = True
            packet["stdout"] = _clip_output(exc.stdout if isinstance(exc.stdout, str) else "")
            packet["stderr"] = _clip_output(exc.stderr if isinstance(exc.stderr, str) else "")
        packet["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        packet["packet_sha256"] = digest(packet)
    _write_exclusive(output, json.dumps(packet, indent=2, sort_keys=True) + "\n")
    try:
        validate_packet(packet)
    except ValueError as exc:
        print(f"INCOMPLETE packet written to {output}: {exc}", file=sys.stderr)
        return 2
    print(f"VALID packet written to {output} packet_sha256={packet['packet_sha256']}")
    return 0


def cmd_verify(path: Path) -> int:
    try:
        packet = json.loads(path.read_text(encoding="utf-8"))
        validate_packet(packet)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"VALID packet_sha256={packet['packet_sha256']}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    for command_name in ("preview", "run"):
        command = sub.add_parser(command_name)
        command.add_argument("case", choices=sorted(CASES))
        command.add_argument("--sandbox", choices=("auto", "direct", "bwrap"), default="auto")
        if command_name == "run":
            command.add_argument("--approve", required=True)
            command.add_argument("--out", required=True, type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("packet", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            return cmd_doctor()
        if args.command == "preview":
            return cmd_preview(args.case, args.sandbox)
        if args.command == "run":
            return cmd_run(args.case, args.sandbox, args.approve, args.out)
        return cmd_verify(args.packet)
    except (RuntimeError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
