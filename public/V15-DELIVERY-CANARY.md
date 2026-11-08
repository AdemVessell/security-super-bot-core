# V15 delivery canary

This directory is a bounded delivery-integrity canary for Security Super Bot.
It is a dependency-free, offline fixture pack. It is not a scanner, a live-target
pentest tool, a bounty report, or evidence of a current vulnerability.

The delivery check is integrity-only. After fetching the nine files from an
exact commit, independently check the bootstrap hash pinned in the Bot
instructions, then run only `python3 -I -S bootstrap.py --verify-only` from a
clean staging directory. A recipient must return `HOLD` on any missing,
changed, extra, symlinked, or special file. Stop before fixture execution,
package installation, host scans, routine creation, or any network request
beyond the nine pinned GitHub file fetches.

Runtime manifest (nine files):

| Path | SHA-256 |
| --- | --- |
| `bootstrap.py` | `800f76a8a4609c3f7851e386bc07d79ff3470bf0d8b62a072e44c64613d4a1a5` |
| `secbot_toolkit.py` | `85211f975cb9e98671ad7cd81bbc260a1b042fee5b998d6bebf1131b0c1fb52e` |
| `cases/access_case.mjs` | `dcac3a642fd242ff31c6a326d206949c32612f4d96feb91ca14b75ee79a724f1` |
| `cases/run_controls.mjs` | `c288c7d35a9eaf8b89ba93e97c7b3e6b2c651e65a2ab3608d5bb0dc9b81acd1e` |
| `cases/path_case.py` | `41916b15943b4e04ef9cb44eb80121955db3267297a8f7758e48800aefe9bf5b` |
| `cases/path_controls.py` | `ee7cfb5002faf805ff48a83a052da5935136f9dbd3e3f34792afa338000ec60a` |
| `cases/node-tmp-historical/harness.mjs` | `a704fc03f1b476a3a13541eda900540288077de6f30662cab0a3593c75234734` |
| `cases/node-tmp-historical/lib/tmp.js` | `5f5eef7faf6251c16f3b75668e463fb17b2d9fab3f9a29a5f9ac65b082dd7e76` |
| `cases/node-tmp-historical/LICENSE` | `162413c61e0982abe89a06bf7a02ec760dc49a7364d838bd9f01daebb5b95954` |

The historical source is included under its MIT notice for replay only. Its
result is a known-fixed behavior and must not be described as a new finding or
permission to test a live target.
