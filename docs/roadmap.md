# Roadmap: what I would improve next

Ordered by how much each one reduces risk.

1. **Signed device registry.** The registry is the root of trust. It should be signed by
   an election-authority key (ideally with two people required), and the server should
   refuse to start with an unsigned or modified registry.
2. **Review workflow for flagged results.** An authenticated reviewer role, two-person
   approval to accept a correction, and the decision plus reason written to the audit log.
3. **External audit checkpoints.** Publish the head hash on a schedule to somewhere the
   operator doesn't control (RFC 3161 timestamping, a public transparency log).
4. **Periodic re-verification of stored results.** Re-check each row in `results`
   against its stored signature and the audit log; expose the result as a metric.
5. **Monitoring stack.** `docker compose` with Prometheus + Grafana dashboard and alert
   rules (audit chain broken, spike in rejections, station silent too long).
6. **Hardware-backed keys** on devices (TPM / secure element simulation), and key
   revocation in the registry.
7. **Deployment hardening.** Reverse proxy with TLS and rate limiting, request size
   limits, container image scanning in CI, SBOM.
8. **Paper-trail reconciliation.** Compare each electronic result with a second,
   independently entered results sheet; differences go to review.
