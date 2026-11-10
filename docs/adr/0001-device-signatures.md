# ADR 0001: Per-device Ed25519 signatures over canonical JSON

**Status:** accepted

## Context

Results travel over networks we don't control. We need to know who sent a result and
that it hasn't changed. Options considered:

| Option | Problem |
|---|---|
| TLS only | Protects the connection, not the message. Once the server has it, nothing proves what the device sent. |
| Shared secret / HMAC | The server holds the same secret, so the server (or anyone who breaches it) could forge results. |
| One key for all devices | One stolen device compromises every station. |
| **Per-device asymmetric key** | Server holds public keys only. One stolen key affects one station. |

## Decision

Each device gets its own **Ed25519** key pair at provisioning. It signs the
**canonical JSON** of the payload (sorted keys, no whitespace, no NaN). The server
verifies the signature over the payload exactly as received, before parsing it.

Ed25519: small keys and signatures, fast, deterministic (no random nonce that can
leak the key if the RNG is bad), and widely supported.

## Consequences

- The server can't forge results, which supports non-repudiation in both directions.
- Signatures are checked before any field is trusted ("authenticate, then parse").
- Canonical JSON is a simple scheme. A production system might use a standard like
  RFC 8785 (JCS) or a binary format (CBOR/COSE) to remove any cross-language ambiguity.
- Key storage on the device is now the weak point (see threat model I1).
