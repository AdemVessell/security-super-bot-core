# Optional V11 evidence-packet validator

This directory is an optional, offline evidence layer for the Security Super Bot V11 lab. It validates a research packet's closed structure, current `packet_sha256`, and state transition rules for `NEW_DELTA`, `NO_CHANGE`, `PARTIAL`, and `FAILED` watches.

It does not change `secbot.py`, the npm lockfile parser, the OSV approval flow, or any existing beta behavior. It makes no network requests and does not execute repository or target code. The Grok Bot must not treat this directory as an automatically installed plugin or as authorization to run a live test.

## Offline test

From this directory:

```sh
python3 -m unittest -v test_validate_packet.py
```

For a saved packet transition, validate the current packet against a trusted prior packet:

```sh
python3 validate_packet.py CURRENT.json --previous-state PREVIOUS.json
```

`PREVIOUS.json` must be the accepted packet or a dedicated saved state whose acknowledged head and acknowledged packet hash were read back from the Bot. A self-consistent packet is not evidence of persistence by itself.

The validator is a local test aid, not a vulnerability scanner, report generator, or proof of deployed impact.
