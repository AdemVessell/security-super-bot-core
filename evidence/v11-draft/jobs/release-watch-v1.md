# Release watch job v1

## Inputs

- Public repository URL and an exact baseline commit, tag, or release.
- Optional public head ref or release feed.
- Owner-selected cadence and timezone.
- Acknowledged state: last successfully acknowledged head and its `packet_sha256`. Record the newly observed head separately; it can be unknown after a failed fetch.

## Each run

1. Fetch public metadata and the bounded compare range. Do not clone or execute source unless the owner separately requests a pinned local proof.
2. If the head equals the acknowledged head, return `NO_CHANGE` with the pin and timestamp.
3. For a new head, list changed paths and inspect only security-relevant boundaries: authority, identity, data flow, sandbox, parser, dependency, secret, or state transition.
4. Produce one packet using `schemas/research-packet-v1.json`. Set `watch_state` to `NEW_DELTA` and set the separate `candidate_state` to `KILLED`, `HOLD`, or `LOCAL_PROOF_READY`. Include at most one promoted candidate and list parked alternatives.
5. Compute `packet_sha256` from the current packet with only `packet_sha256` omitted: recursively sort object keys, encode compact UTF-8 JSON, and hash the bytes. Carry the previous acknowledged packet's `packet_sha256` in `acknowledged_packet_sha256` (null on the first packet). `REPORT_ROUTE_UNVERIFIED` is reserved for an actually unverified disclosure route, not a fetch, parse, or coverage failure.
6. For `NO_CHANGE`, require `head == acknowledged_head`, `candidate_state == null`, no `candidate` object, empty `changed_paths`, and carry the prior `acknowledged_packet_sha256` unchanged. For `NEW_DELTA`, require `head != acknowledged_head`, a non-null `candidate_state`, and set `acknowledged_packet_sha256` to the prior acknowledged value until this packet is written and read back. Only then advance the saved head and treat this packet's `packet_sha256` as the new acknowledged hash. If a run fails or coverage is partial, set `watch_state` to `FAILED` or `PARTIAL`, set `candidate_state` to `HOLD`, explain the coverage limitation, and retain the prior acknowledged state. Do not contact a vendor, scan a service, submit, or update a public post.
7. Run the bundled dependency-free validator (`python3 validate_packet.py PACKET.json --previous-state PREVIOUS.json`) before accepting state. It verifies closed nested fields, non-empty citations and changed paths for deltas, promoted candidate evidence, the current packet hash, and continuity with the trusted prior head/hash. A packet that fails validation is `FAILED`/`HOLD` and cannot advance state.

## Routine guardrails

- Read-only public GitHub/GitLab/API metadata only.
- No secrets, private repositories, external targets, broad enumeration, or third-party messages.
- A scheduled routine may report a state change; it may not authorize live validation.
- A future local proof must use a disposable fixture, a positive oracle, and a negative control.
