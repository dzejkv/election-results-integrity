# ADR 0003: SQLite with a single serialised writer

**Status:** accepted (for this scale)

## Context

The intake must be correct under concurrent requests: two results arriving at once
must not both get the same audit sequence number, and a result must never be stored
without its audit entry (or the other way round).

## Decision

One SQLite connection, guarded by a lock. Each submission runs in a single
`BEGIN IMMEDIATE ... COMMIT` transaction that covers the checks, the data change and
the audit entry. WAL mode is on.

## Consequences

- Correctness is easy to reason about: submissions are processed one at a time.
- No database server to run; the whole demo is one process.
- Throughput is limited to one writer. That's fine here: even a large election has a
  few thousand stations, each reporting once or twice.
- To scale out: PostgreSQL with `SERIALIZABLE` transactions (or an advisory lock on
  the audit head), multiple API instances behind a load balancer.
