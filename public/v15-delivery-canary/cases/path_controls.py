"""Bounded controls for the synthetic path-boundary fixture."""

import tempfile
from pathlib import Path

from path_case import resolve_member


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="secbot-path-") as temp:
        root = Path(temp) / "records"
        root.mkdir()
        (root / "public.txt").write_text("public", encoding="utf-8")

        own = resolve_member(root, "public.txt")
        assert own == (root / "public.txt").resolve()
        print("PASS positive: in-root member resolves inside permitted root")

        try:
            resolve_member(root, "../outside.txt")
        except PermissionError:
            print("PASS negative: traversal is rejected before file access")
        else:
            raise AssertionError("path traversal escaped the permitted root")

        assert resolve_member(root, "records/../public.txt") == own
        print("PASS normalization: safe dot segments stay inside root")


if __name__ == "__main__":
    main()
