# Architecture

This document captures durable project context, constraints, and design decisions that should survive beyond temporary planning notes.

## Documents

| Path | Role |
|---|---|
| [`spec/ssrf-guard-spec.md`](spec/ssrf-guard-spec.md) | The normative contract. Language-agnostic: threat model, L0/L1/L2 layers, request lifecycle, 14 invariants, reason codes, conformance. A second-language implementation shares this, not code. |
| [`spec/r-binding.md`](spec/r-binding.md) | R/libcurl specifics: transport option names, empirically verified constraints, test architecture. |
| [`decisions/ADR-001-network-safety-policy.md`](decisions/ADR-001-network-safety-policy.md) | The policy layer. What carries over from `sitemapr` ADR-003, what is reversed, and which inherited gaps are closed. |

Keep libcurl detail out of `spec/ssrf-guard-spec.md`; it belongs in `spec/r-binding.md`.
