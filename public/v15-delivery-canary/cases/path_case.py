"""Synthetic path-boundary fixture. It uses only temporary fake data."""

from pathlib import Path


def resolve_member(root: Path, user_path: str) -> Path:
    root = root.resolve()
    candidate = (root / user_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise PermissionError("path escapes the permitted root")
    return candidate
