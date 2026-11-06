#!/usr/bin/env python3
"""Validate a Security Super Bot v1 evidence packet without third-party deps."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


HEX64 = re.compile(r"^[0-9a-f]{64}$")
WATCH_STATES = {"NO_CHANGE", "NEW_DELTA", "PARTIAL", "FAILED"}
CANDIDATE_STATES = {
    "KILLED",
    "HOLD",
    "LOCAL_PROOF_READY",
    "LOCALLY_REPRODUCED",
    "REPORT_ROUTE_UNVERIFIED",
    None,
}
_UNSET = object()
ROOT_KEYS = {
    "schema",
    "watch_state",
    "candidate_state",
    "source",
    "scope",
    "candidate",
    "parked_alternatives",
    "evidence",
    "next_action",
    "hash_basis",
    "packet_sha256",
    "acknowledged_packet_sha256",
}
REQUIRED_ROOT_KEYS = {
    "schema",
    "watch_state",
    "candidate_state",
    "source",
    "scope",
    "evidence",
    "next_action",
    "hash_basis",
    "packet_sha256",
    "acknowledged_packet_sha256",
}
SOURCE_KEYS = {"repository", "baseline", "acknowledged_head", "head", "retrieved_at", "changed_paths"}
REQUIRED_SOURCE_KEYS = {"repository", "baseline", "acknowledged_head", "head", "retrieved_at", "changed_paths"}
SCOPE_KEYS = {"authority", "program", "live_testing_allowed"}
REQUIRED_SCOPE_KEYS = {"authority", "live_testing_allowed"}
CANDIDATE_KEYS = {"fingerprint", "source", "control", "sink", "protected_effect", "preconditions", "counterevidence", "prior_art"}
EVIDENCE_KEYS = {"citations", "positive_test", "negative_test", "actions_taken", "actions_not_taken"}


class PacketError(ValueError):
    """A packet violates a structural, state, or hash invariant."""


def canonical_packet_bytes(packet: dict[str, Any]) -> bytes:
    """Return canonical packet bytes with only the current hash omitted."""
    unsigned = dict(packet)
    unsigned.pop("packet_sha256", None)
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def packet_digest(packet: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_packet_bytes(packet)).hexdigest()


def trusted_previous_state(previous: dict[str, Any]) -> tuple[str, str | None]:
    """Validate a prior packet and derive the state a next packet must carry."""
    if not isinstance(previous, dict):
        raise PacketError("previous state must be an object")
    if previous.get("schema") == "secbot.research_packet.v1":
        validate_packet(previous)
        source = _require_object(previous["source"], "previous.source")
        if previous["watch_state"] == "NEW_DELTA":
            expected_head = source["head"]
            expected_hash = previous["packet_sha256"]
        else:
            expected_head = source["acknowledged_head"]
            expected_hash = previous["acknowledged_packet_sha256"]
        if not isinstance(expected_head, str) or (expected_hash is not None and not isinstance(expected_hash, str)):
            raise PacketError("previous packet does not contain an acknowledged head/hash")
        return expected_head, expected_hash
    expected_head = previous.get("acknowledged_head")
    expected_hash = previous.get("packet_sha256")
    if not isinstance(expected_head, str) or not isinstance(expected_hash, str):
        raise PacketError("previous state must provide acknowledged_head and packet_sha256")
    return expected_head, expected_hash


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PacketError(f"{name} must be an object")
    return value


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PacketError(f"{name} must be a non-empty string")
    return value


def _require_string_list(value: Any, name: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PacketError(f"{name} must be a list of non-empty strings")
    if nonempty and not value:
        raise PacketError(f"{name} must not be empty")
    return value


def _check_closed(value: dict[str, Any], allowed: set[str], required: set[str], name: str) -> None:
    missing = required - set(value)
    if missing:
        raise PacketError(f"missing {name} fields: {', '.join(sorted(missing))}")
    extra = set(value) - allowed
    if extra:
        raise PacketError(f"unexpected {name} fields: {', '.join(sorted(extra))}")


def validate_packet(
    packet: dict[str, Any],
    *,
    expected_ack_head: str | None | object = _UNSET,
    expected_ack_hash: str | None | object = _UNSET,
) -> str:
    """Validate and return the packet's computed current digest."""
    _require_object(packet, "packet")
    missing = REQUIRED_ROOT_KEYS - set(packet)
    if missing:
        raise PacketError(f"missing root fields: {', '.join(sorted(missing))}")
    extra = set(packet) - ROOT_KEYS
    if extra:
        raise PacketError(f"unexpected root fields: {', '.join(sorted(extra))}")
    if packet["schema"] != "secbot.research_packet.v1":
        raise PacketError("unsupported schema")
    watch = packet["watch_state"]
    candidate_state = packet["candidate_state"]
    if watch not in WATCH_STATES:
        raise PacketError(f"invalid watch_state: {watch!r}")
    if candidate_state not in CANDIDATE_STATES:
        raise PacketError(f"invalid candidate_state: {candidate_state!r}")
    source = _require_object(packet["source"], "source")
    _check_closed(source, SOURCE_KEYS, REQUIRED_SOURCE_KEYS, "source")
    for field in ("repository", "baseline", "acknowledged_head", "retrieved_at"):
        _require_text(source.get(field), f"source.{field}")
    parsed_repository = urlparse(source["repository"])
    if not parsed_repository.scheme or not parsed_repository.netloc:
        raise PacketError("source.repository must be an absolute URI")
    if "head" not in source:
        raise PacketError("source.head is required")
    head = source["head"]
    if head is not None:
        _require_text(head, "source.head")
    _require_string_list(source["changed_paths"], "source.changed_paths")
    scope = _require_object(packet["scope"], "scope")
    _check_closed(scope, SCOPE_KEYS, REQUIRED_SCOPE_KEYS, "scope")
    _require_text(scope["authority"], "scope.authority")
    if "program" in scope and scope["program"] is not None:
        _require_text(scope["program"], "scope.program")
    if not isinstance(scope["live_testing_allowed"], bool):
        raise PacketError("scope.live_testing_allowed must be boolean")
    evidence = _require_object(packet["evidence"], "evidence")
    _check_closed(evidence, EVIDENCE_KEYS, EVIDENCE_KEYS, "evidence")
    _require_string_list(evidence["citations"], "evidence.citations", nonempty=True)
    for field in ("actions_taken", "actions_not_taken"):
        _require_string_list(evidence[field], f"evidence.{field}")
    for field in ("positive_test", "negative_test"):
        if evidence[field] is not None and not isinstance(evidence[field], str):
            raise PacketError(f"evidence.{field} must be a string or null")
    if "parked_alternatives" in packet:
        _require_string_list(packet["parked_alternatives"], "parked_alternatives")
    if "candidate" in packet:
        candidate = _require_object(packet["candidate"], "candidate")
        _check_closed(candidate, CANDIDATE_KEYS, CANDIDATE_KEYS, "candidate")
        for field in ("fingerprint", "source", "control", "sink", "protected_effect"):
            _require_text(candidate[field], f"candidate.{field}")
        for field in ("preconditions", "counterevidence", "prior_art"):
            _require_string_list(candidate[field], f"candidate.{field}")
    _require_text(packet["next_action"], "next_action")
    if packet["hash_basis"] != "sha256(canonical-json-with-packet_sha256-omitted)":
        raise PacketError("invalid hash_basis")
    current = packet["packet_sha256"]
    if not isinstance(current, str) or not HEX64.fullmatch(current):
        raise PacketError("packet_sha256 must be lowercase hex SHA-256")
    acknowledged = packet["acknowledged_packet_sha256"]
    if acknowledged is not None and (not isinstance(acknowledged, str) or not HEX64.fullmatch(acknowledged)):
        raise PacketError("acknowledged_packet_sha256 must be lowercase hex SHA-256 or null")

    if watch == "NO_CHANGE":
        if head != source["acknowledged_head"]:
            raise PacketError("NO_CHANGE requires head == acknowledged_head")
        if candidate_state is not None:
            raise PacketError("NO_CHANGE requires candidate_state null")
        if "candidate" in packet:
            raise PacketError("NO_CHANGE must not include candidate")
        if source["changed_paths"]:
            raise PacketError("NO_CHANGE requires empty changed_paths")
    elif watch == "NEW_DELTA":
        if head is None or head == source["acknowledged_head"]:
            raise PacketError("NEW_DELTA requires a head different from acknowledged_head")
        if candidate_state is None:
            raise PacketError("NEW_DELTA requires a candidate_state")
        _require_string_list(source["changed_paths"], "source.changed_paths", nonempty=True)
        if candidate_state in {"LOCAL_PROOF_READY", "LOCALLY_REPRODUCED", "REPORT_ROUTE_UNVERIFIED"} and "candidate" not in packet:
            raise PacketError(f"{candidate_state} requires candidate details")
        if candidate_state in {"LOCAL_PROOF_READY", "LOCALLY_REPRODUCED", "REPORT_ROUTE_UNVERIFIED"}:
            if evidence["positive_test"] is None or not evidence["positive_test"].strip():
                raise PacketError(f"{candidate_state} requires a positive_test")
            if evidence["negative_test"] is None or not evidence["negative_test"].strip():
                raise PacketError(f"{candidate_state} requires a negative_test")
    else:
        if candidate_state != "HOLD":
            raise PacketError(f"{watch} requires candidate_state HOLD")

    if expected_ack_head is not _UNSET and source["acknowledged_head"] != expected_ack_head:
        raise PacketError("acknowledged_head does not match trusted prior state")
    if expected_ack_hash is not _UNSET:
        if expected_ack_hash is not None and not HEX64.fullmatch(expected_ack_hash):
            raise PacketError("trusted prior packet hash must be lowercase hex SHA-256")
        if acknowledged != expected_ack_hash:
            raise PacketError("acknowledged_packet_sha256 does not match trusted prior state")

    computed = packet_digest(packet)
    if current != computed:
        raise PacketError(f"packet_sha256 mismatch: expected {computed}, got {current}")
    return computed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--expected-ack-head")
    parser.add_argument("--expected-ack-hash")
    parser.add_argument("--previous-state", type=Path, help="JSON packet or {acknowledged_head, packet_sha256} state")
    args = parser.parse_args()
    try:
        packet = json.loads(args.packet.read_text(encoding="utf-8"))
        expected_head: str | None | object = _UNSET
        expected_hash: str | None | object = _UNSET
        if args.expected_ack_head is not None:
            expected_head = args.expected_ack_head
        if args.expected_ack_hash is not None:
            expected_hash = args.expected_ack_hash
        if args.previous_state:
            previous = json.loads(args.previous_state.read_text(encoding="utf-8"))
            expected_head, expected_hash = trusted_previous_state(previous)
        kwargs = {}
        if expected_head is not _UNSET:
            kwargs["expected_ack_head"] = expected_head
        if expected_hash is not _UNSET:
            kwargs["expected_ack_hash"] = expected_hash
        digest = validate_packet(packet, **kwargs)
    except (OSError, json.JSONDecodeError, PacketError) as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"VALID packet_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
