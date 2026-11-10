# ADR 0004: Hash-chained audit log with public checkpoints

**Status:** accepted

## Context

Logs are evidence. A normal log table can be edited by anyone with database access,
and nobody would know. Options considered:

| Option | Trade-off |
|---|---|
| Plain table / log file | No tamper evidence at all. |
| Write-once storage (WORM, S3 Object Lock) | Strong, but depends on a specific platform. Good addition later. |
| Blockchain | Heavy, slow and unnecessary: we have one writer and want public *verifiability*, not decentralised consensus. |
| **Hash chain + published checkpoints** | Simple, no dependencies, anyone can verify. |

## Decision

Each audit entry stores `prev_hash`, and its own hash is
`SHA-256(canonical_json({seq, ts, event, details, prev_hash}))`. The current head hash
is shown on the public dashboard. `eri-audit verify --expect-head <hash>` checks the
whole chain offline, read-only.

Every submission attempt is logged, including rejected ones, in the same transaction as
the data change.

## Consequences

- Editing, inserting or deleting an entry breaks the chain at that point, and the
  verifier says where.
- Cutting entries off the end, or rebuilding the entire chain, is only detectable
  against a checkpoint someone saved. So checkpoints need to leave the system:
  observers, the press, a timestamping service (RFC 3161), or a public transparency log.
- Verification is O(n). Fine for thousands of entries. A Merkle tree would allow
  efficient proofs for single entries if needed.
