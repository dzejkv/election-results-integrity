# ADR 0002: Flag for human review; the first accepted result is final

**Status:** accepted

## Context

A result can be correctly signed and still wrong: a miscount, a configuration error, a
device that's been tampered with physically. And a station may send a second result
(a recount, an operator pressing "send" twice, or an attacker with a stolen key).

The tempting options are to "fix" small arithmetic errors automatically, or to let a
newer result overwrite an older one.

## Decision

- Results that fail reconciliation are **stored in `flagged`, not counted**, with the
  list of problems. The device gets `202 flagged`.
- For each station, the **first accepted result stands**. Any later result for that
  station also goes to `flagged`, even if it reconciles.
- Nothing is ever deleted or overwritten by the system itself.

## Consequences

- The system never makes a judgement call that belongs to election officials.
- Totals only ever go up as stations report; they never silently change.
- A legitimate correction needs a person to review it. A review workflow (two-person
  approval, reason recorded in the audit log) is on the [roadmap](../roadmap.md).
- If an attacker with a stolen key reports first, the real result ends up in review.
  That's visible on the dashboard ("under review") rather than hidden.
