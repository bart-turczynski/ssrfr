# Architecture

This document captures durable project context, constraints, and design decisions that should survive beyond temporary planning notes.

## Documents

| Path | Role |
|---|---|
| [`spec/ssrf-guard-spec.md`](spec/ssrf-guard-spec.md) | The normative contract. Language-agnostic: threat model, L0/L1/L2 layers, request lifecycle, 14 invariants, reason codes, conformance. A second-language implementation shares this, not code. |
| [`spec/ssrfr-v1.md`](spec/ssrfr-v1.md) | `ssrfr`'s own v1 specification: purpose, layer contracts, the guarded-hop binding primitive, URL input contract, dependency contract, refusal rule, result model. §10 lists the amendments it requires in the documents below. |
| [`spec/r-binding.md`](spec/r-binding.md) | R/libcurl specifics: transport option names, empirically verified constraints, test architecture. |
| [`decisions/ADR-001-network-safety-policy.md`](decisions/ADR-001-network-safety-policy.md) | The policy layer. What carries over from `sitemapr` ADR-003, what is reversed, and which inherited gaps are closed. |
| [`decisions/ADR-002-v1-dependency-and-policy-model.md`](decisions/ADR-002-v1-dependency-and-policy-model.md) | The current dependency and exception model. Makes `rurl`/`raddr` hard dependencies and amends ADR-001's allow/built-in precedence. |

Keep libcurl detail out of `spec/ssrf-guard-spec.md`; it belongs in `spec/r-binding.md`.
