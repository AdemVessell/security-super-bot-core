#!/usr/bin/env python3
"""One-shot, public npm dependency advisory lookup. Python standard library only."""

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MAX_INPUT_BYTES = 10_000_000
MAX_RESPONSE_BYTES = 8_000_000
MAX_PACKAGES = 200
MAX_PAGES = 10
OSV_URL = "https://api.osv.dev/v1/querybatch"
NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
VERSION = re.compile(r"^[0-9][0-9A-Za-z.+_-]{0,127}$")


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def read_json(path, limit=MAX_INPUT_BYTES):
    raw = Path(path).read_bytes()
    if len(raw) > limit:
        raise ValueError(f"input exceeds {limit} bytes")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def atomic_json(path, data):
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_name(dest.name + ".tmp")
    temp.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temp.replace(dest)


def parse_lockfile(path):
    lock, digest = read_json(path)
    if not isinstance(lock, dict) or lock.get("lockfileVersion") not in (2, 3):
        raise ValueError("expected npm package-lock.json version 2 or 3")
    entries = lock.get("packages")
    if not isinstance(entries, dict):
        raise ValueError("lockfile has no packages object")
    packages = set()
    unresolved = 0
    for location, entry in entries.items():
        if location == "":
            continue
        if not isinstance(location, str) or not isinstance(entry, dict):
            unresolved += 1
            continue
        if entry.get("link"):
            unresolved += 1
            continue
        name = entry.get("name") or location.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        resolved = entry.get("resolved")
        if isinstance(resolved, str) and resolved and not resolved.startswith("https://registry.npmjs.org/"):
            # Local, Git, and custom-registry dependencies need separate review.
            # Do not persist their URLs or query their names automatically.
            unresolved += 1
            continue
        if not isinstance(name, str) or not isinstance(version, str):
            unresolved += 1
            continue
        if len(name) > 214 or not NAME.fullmatch(name) or not VERSION.fullmatch(version):
            unresolved += 1
            continue
        # The inventory contains only package coordinates and flags. Registry URLs,
        # source paths, scripts, descriptions, and any arbitrary fields are dropped.
        packages.add((name, version, bool(entry.get("dev")), bool(entry.get("optional"))))
    if len(packages) > MAX_PACKAGES:
        raise ValueError(f"more than {MAX_PACKAGES} unique packages; split the inventory")
    return {
        "schema": "secbot.inventory.v1",
        "created_utc": utc_now(),
        "source": "npm package-lock.json v2/v3",
        "source_sha256": digest,
        "packages": [
            {"name": n, "version": v, "dev": d, "optional": o}
            for n, v, d, o in sorted(packages)
        ],
        "unresolved_count": unresolved,
    }


def query_osv(queries):
    """Return per-query IDs and receipt. A failure is never represented as empty results."""
    ids = [set() for _ in queries]
    pending = list(range(len(queries)))
    tokens = {}
    codes = []
    response_hashes = []
    pages = 0
    error = None
    while pending:
        if pages >= MAX_PAGES:
            error = "pagination limit reached"
            break
        request_queries = []
        for i in pending:
            q = dict(queries[i])
            if i in tokens:
                q["page_token"] = tokens[i]
            request_queries.append(q)
        body = json.dumps({"queries": request_queries}, separators=(",", ":")).encode()
        req = urllib.request.Request(
            OSV_URL,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "secbot-core/0.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as response:
                codes.append(response.status)
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("OSV response too large")
            response_hashes.append(hashlib.sha256(raw).hexdigest())
            data = json.loads(raw)
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(pending):
                raise ValueError("OSV result count does not match queries")
            next_pending = []
            for i, result in zip(pending, results):
                if not isinstance(result, dict) or not isinstance(result.get("vulns", []), list):
                    raise ValueError("OSV result has unexpected shape")
                for vuln in result.get("vulns", []):
                    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                        raise ValueError("OSV vulnerability has no ID")
                    ids[i].add(vuln["id"])
                if result.get("next_page_token"):
                    tokens[i] = result["next_page_token"]
                    next_pending.append(i)
            pending = next_pending
            pages += 1
        except urllib.error.HTTPError as exc:
            codes.append(exc.code)
            error = f"OSV HTTP {exc.code}"
            break
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            error = f"OSV request or response failure: {type(exc).__name__}"
            break
    return [sorted(x) for x in ids], {
        "source": "OSV querybatch",
        "endpoint": OSV_URL,
        "status": "complete" if error is None else ("partial" if pages else "failed"),
        "http_codes": codes,
        "pages_fetched": pages,
        "response_sha256_per_page": response_hashes,
        "error": error,
        "finished_utc": utc_now(),
    }


def check_inventory(path):
    inventory, digest = read_json(path)
    if not isinstance(inventory, dict) or inventory.get("schema") != "secbot.inventory.v1":
        raise ValueError("expected secbot.inventory.v1 JSON")
    packages = inventory.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > MAX_PACKAGES:
        raise ValueError("inventory must contain 1 to 200 packages")
    queries = []
    for item in packages:
        if not isinstance(item, dict):
            raise ValueError("invalid inventory package")
        name, version = item.get("name"), item.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not NAME.fullmatch(name) or not VERSION.fullmatch(version):
            raise ValueError("invalid package coordinate")
        queries.append({"package": {"ecosystem": "npm", "name": name}, "version": version})
    ids, receipt = query_osv(queries)
    status = receipt["status"]
    return {
        "schema": "secbot.report.v1",
        "created_utc": utc_now(),
        "inventory_sha256": digest,
        "coverage": status if not inventory.get("unresolved_count") else "partial",
        "unresolved_count": inventory.get("unresolved_count", 0),
        "findings": [
            {"name": q["package"]["name"], "version": q["version"], "advisory_ids": found}
            for q, found in zip(queries, ids)
        ],
        "receipt": receipt,
        "interpretation": (
            "OSV returned matching advisory IDs for the queried package versions. "
            "Deployment, exploitability, fixes, and absence of other vulnerabilities are unverified."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory", help="parse locally; no network")
    inventory.add_argument("lockfile")
    inventory.add_argument("--out", required=True)
    check = commands.add_parser("check", help="send approved public package coordinates to OSV")
    check.add_argument("inventory")
    check.add_argument("--out", required=True)
    check.add_argument("--public-packages-approved", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inventory":
            data = parse_lockfile(args.lockfile)
            atomic_json(args.out, data)
            print(json.dumps({"packages": len(data["packages"]), "unresolved": data["unresolved_count"], "out": args.out}))
            return 0
        if not args.public_packages_approved:
            raise ValueError("approve the exact public package list before external lookup")
        data = check_inventory(args.inventory)
        atomic_json(args.out, data)
        print(json.dumps({"coverage": data["coverage"], "advisory_count": sum(len(x["advisory_ids"]) for x in data["findings"]), "out": args.out}))
        return 0 if data["receipt"]["status"] == "complete" and data["coverage"] == "complete" else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
