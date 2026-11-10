# Threat model

Method: list the assets, the people who might attack them, then go through STRIDE
for each part of the data flow. Every row says whether this version handles it and
where.

## Assets

| Asset | Why it matters |
|---|---|
| Station results | The thing being protected. Wrong totals = wrong outcome. |
| Device private keys | Whoever holds a key can submit results for that station. |
| Device registry | Decides which keys are trusted. Changing it is as good as stealing a key. |
| Audit log | The evidence of what happened. |
| Public trust | People need to be able to check, not just believe. |

## Attackers

| Who | Can do |
|---|---|
| Network attacker | Read, change, replay or inject traffic between station and server. |
| Rogue or faulty device | Send well-signed but wrong numbers, report for the wrong station. |
| Insider with DB access | Edit or delete rows directly. |
| Public user | Load the dashboard, try to inject content or overload it. |

## STRIDE

| # | Threat | Example | Handled? | How / where |
|---|---|---|---|---|
| S1 | **Spoofing** a device | Attacker posts results claiming to be SCN-003 | Yes | Signature must verify against the registered key (`service.py` step 3) |
| S2 | Spoofing a station | A real device reports for a different station | Yes | Device ↔ station binding from provisioning (step 5) |
| T1 | **Tampering** in transit | Votes changed between scanner and server | Yes | Ed25519 over canonical JSON; any change fails verification |
| T2 | Tampering with stored results | Insider edits `results` table | Partly | Each stored row keeps the device signature, and the audit log keeps the payload hash, so an edited row can be detected. Automated re-check is on the [roadmap](roadmap.md). |
| T3 | Tampering with the audit log | Insider edits or deletes an entry | Yes | Hash chain breaks at that entry (`audit.py`, tests in `test_audit.py`) |
| T4 | Rewriting the whole log / cutting off the end | Insider rebuilds the chain from scratch | Partly | Detectable only against a head hash someone saved earlier (dashboard + `--expect-head`). Periodic external anchoring is on the roadmap. |
| T5 | Type confusion | `"ballots_cast": "80"` or extra fields | Yes | Strict model: no coercion, unknown fields rejected |
| R1 | **Repudiation** by a station | "We never sent that" | Yes | Only that device's key could have signed it; receipt hash returned |
| R2 | Repudiation by the server | "We never received that" | Yes | Station keeps the receipt (audit entry hash) |
| I1 | **Information disclosure** of private keys | Key file readable by others | Partly | Key files created `0600`. A real device would use a hardware module (TPM / secure element). |
| I2 | Disclosure of flagged data | Public sees raw review items | Yes | Public API exposes only counts, not flagged payloads |
| D1 | **Denial of service** | Flood the intake endpoint | No | Out of scope here. Needs rate limiting, size limits and a reverse proxy. |
| D2 | Replay flood | Same valid message sent many times | Yes (correctness) | Rejected by sequence + nonce; each attempt is still audited |
| E1 | **Elevation of privilege** | Adding a device to the registry | Partly | Registry is a file loaded at start-up, not writable through the API. Needs signing by an election authority key (roadmap). |
| E2 | XSS via dashboard | Candidate name with `<script>` | Yes | `textContent` only, strict CSP with no inline scripts |

## Faults that are not attacks

| Fault | Handling |
|---|---|
| Scanner miscounts, numbers don't add up | Reconciliation flags it for review, not counted |
| Two results for the same station (e.g. recount) | The first accepted result stands; later ones go to review ([ADR 0002](adr/0002-flag-dont-fix.md)) |
| Device clock wrong | Results timestamped more than 5 minutes in the future are rejected |
| Network drops, scanner retries | Retrying the *same* message is a replay (409), so the scanner should check its receipt first. A new sequence number is a new submission. |

## Known gaps (honest list)

1. A stolen device key lets an attacker submit one result for that station before the
   real device does. Mitigation: key in hardware, plus a second channel (paper results
   sheet) for reconciliation.
2. A malicious server operator could refuse to accept results. The receipts show what
   was accepted, not what was refused silently at the network level.
3. The registry itself is not signed.
4. No rate limiting or TLS termination in the app. In a deployment this sits behind a
   reverse proxy that does both.
