import copy
import hashlib
import json
import unittest

from validate_packet import PacketError, packet_digest, trusted_previous_state, validate_packet


def packet(watch="NEW_DELTA", candidate_state="HOLD", head="head-2", acknowledged="head-1"):
    result = {
        "schema": "secbot.research_packet.v1",
        "watch_state": watch,
        "candidate_state": candidate_state,
        "source": {
            "repository": "https://example.test/repo",
            "baseline": "head-1",
            "acknowledged_head": acknowledged,
            "head": head,
            "retrieved_at": "2026-11-07T00:00:00Z",
            "changed_paths": ["src/auth.py"],
        },
        "scope": {"authority": "public source only", "live_testing_allowed": False},
        "candidate": {
            "fingerprint": "candidate-1",
            "source": "src/auth.py:10",
            "control": "auth gate",
            "sink": "protected route",
            "protected_effect": "unauthorized access",
            "preconditions": ["deployment config"],
            "counterevidence": ["no live proof"],
            "prior_art": [],
        },
        "parked_alternatives": [],
        "evidence": {
            "citations": ["https://example.test/repo/commit/head-2"],
            "positive_test": "mock positive",
            "negative_test": "mock negative",
            "actions_taken": ["read public source"],
            "actions_not_taken": ["no host traffic"],
        },
        "next_action": "hold for scope review",
        "hash_basis": "sha256(canonical-json-with-packet_sha256-omitted)",
        "packet_sha256": "",
        "acknowledged_packet_sha256": None,
    }
    if watch == "NO_CHANGE":
        result.pop("candidate", None)
        result["candidate_state"] = None
        result["source"]["head"] = result["source"]["acknowledged_head"]
        result["source"]["changed_paths"] = []
    result["packet_sha256"] = packet_digest(result)
    return result


class PacketValidatorTests(unittest.TestCase):
    def test_first_delta_hashes_and_validates(self):
        candidate = packet()
        self.assertEqual(validate_packet(candidate), candidate["packet_sha256"])
        self.assertEqual(len(candidate["packet_sha256"]), 64)

    def test_no_change_carries_prior_ack_and_has_no_candidate(self):
        first = packet()
        unchanged = packet(watch="NO_CHANGE", candidate_state=None, head="head-1", acknowledged="head-1")
        unchanged["acknowledged_packet_sha256"] = first["packet_sha256"]
        unchanged["packet_sha256"] = packet_digest(unchanged)
        self.assertEqual(validate_packet(unchanged), unchanged["packet_sha256"])

    def test_no_change_with_new_head_is_rejected(self):
        bad = packet(watch="NO_CHANGE", candidate_state=None, head="head-2", acknowledged="head-1")
        bad["source"]["head"] = "head-2"
        with self.assertRaisesRegex(PacketError, "NO_CHANGE requires head"):
            validate_packet(bad)

    def test_no_change_with_changed_paths_is_rejected(self):
        bad = packet(watch="NO_CHANGE", candidate_state=None, head="head-1", acknowledged="head-1")
        bad["source"]["changed_paths"] = ["should-not-be-present"]
        bad["packet_sha256"] = packet_digest(bad)
        with self.assertRaisesRegex(PacketError, "empty changed_paths"):
            validate_packet(bad)

    def test_new_delta_without_candidate_state_is_rejected(self):
        bad = packet(candidate_state=None)
        with self.assertRaisesRegex(PacketError, "NEW_DELTA requires a candidate_state"):
            validate_packet(bad)

    def test_failure_must_hold(self):
        bad = packet(watch="FAILED", candidate_state=None, head=None, acknowledged="head-1")
        with self.assertRaisesRegex(PacketError, "FAILED requires"):
            validate_packet(bad)

    def test_tampered_current_hash_is_rejected(self):
        bad = packet()
        bad["next_action"] = "tampered"
        with self.assertRaisesRegex(PacketError, "packet_sha256 mismatch"):
            validate_packet(bad)

    def test_forged_prior_state_is_rejected(self):
        first = packet()
        unchanged = packet(watch="NO_CHANGE", candidate_state=None, head="head-1", acknowledged="head-1")
        unchanged["acknowledged_packet_sha256"] = first["packet_sha256"]
        unchanged["packet_sha256"] = packet_digest(unchanged)
        with self.assertRaisesRegex(PacketError, "trusted prior state"):
            validate_packet(unchanged, expected_ack_head="head-1", expected_ack_hash="0" * 64)

    def test_p1_p2_p3_transition_preserves_original_ack(self):
        p1 = packet()
        p2 = packet(watch="NO_CHANGE", candidate_state=None, head="head-1", acknowledged="head-1")
        p2["acknowledged_packet_sha256"] = p1["packet_sha256"]
        p2["packet_sha256"] = packet_digest(p2)
        p3 = packet(watch="NO_CHANGE", candidate_state=None, head="head-1", acknowledged="head-1")
        p3["source"]["retrieved_at"] = "2026-11-07T00:01:00Z"
        p3["acknowledged_packet_sha256"] = p1["packet_sha256"]
        p3["packet_sha256"] = packet_digest(p3)
        self.assertEqual(trusted_previous_state(p1), ("head-2", p1["packet_sha256"]))
        self.assertEqual(trusted_previous_state(p2), ("head-1", p1["packet_sha256"]))
        expected_head, expected_hash = trusted_previous_state(p2)
        self.assertEqual(
            validate_packet(p3, expected_ack_head=expected_head, expected_ack_hash=expected_hash),
            p3["packet_sha256"],
        )

    def test_p3_forged_to_carry_p2_hash_is_rejected(self):
        p1 = packet()
        p2 = packet(watch="NO_CHANGE", candidate_state=None, head="head-1", acknowledged="head-1")
        p2["acknowledged_packet_sha256"] = p1["packet_sha256"]
        p2["packet_sha256"] = packet_digest(p2)
        forged = packet(watch="NO_CHANGE", candidate_state=None, head="head-1", acknowledged="head-1")
        forged["acknowledged_packet_sha256"] = p2["packet_sha256"]
        forged["packet_sha256"] = packet_digest(forged)
        expected_head, expected_hash = trusted_previous_state(p2)
        with self.assertRaisesRegex(PacketError, "trusted prior state"):
            validate_packet(forged, expected_ack_head=expected_head, expected_ack_hash=expected_hash)

    def test_promoted_candidate_requires_nonempty_evidence(self):
        bad = packet(candidate_state="LOCAL_PROOF_READY")
        bad["evidence"]["positive_test"] = ""
        bad["packet_sha256"] = packet_digest(bad)
        with self.assertRaisesRegex(PacketError, "positive_test"):
            validate_packet(bad)

    def test_nested_unknown_field_is_rejected(self):
        bad = packet()
        bad["scope"]["untrusted"] = "x"
        bad["packet_sha256"] = packet_digest(bad)
        with self.assertRaisesRegex(PacketError, "unexpected scope"):
            validate_packet(bad)

    def test_new_delta_requires_changed_path(self):
        bad = packet()
        bad["source"]["changed_paths"] = []
        bad["packet_sha256"] = packet_digest(bad)
        with self.assertRaisesRegex(PacketError, "changed_paths"):
            validate_packet(bad)


if __name__ == "__main__":
    unittest.main()
