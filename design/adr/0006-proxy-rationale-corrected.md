---
status: accepted
date: 2026-09-25
tracking: SSRF-nbcgyled
---

# ADR 0006: No proxy in v1, for a corrected reason

## Context

ADR 0004 §6 removed the proxy opt-in from INV-10 because "a proxy resolves the
hostname itself, so an opted-in proxy returns what looks like a guarded fetch
while guarding nothing". Its Consequences repeat the premise for `sitemapr`'s
`request_policy(proxy = )`. `ssrfr-v1.md` INV-10 and §14 carried the same
premise.

The premise holds for a proxy handed the hostname, which is how the reference
Ruby implementation lost its pin. It does not hold under the pin `ssrfr` uses.
With `connect_to` set, libcurl 8.14.1 hands every proxy type it was probed with
the pinned address: an HTTP proxy receives `CONNECT <pinned IP>:<port>`, even
for an `http://` URL, and a SOCKS5 or `socks5h` proxy receives the IPv4 literal
(`design/evidence/2026-09-24-proxy-probes.R`). The pinned address reaches the
proxy intact.

The decision still stands. L2's guarantee names the TCP peer, and with a proxy
the peer is the proxy. The proxy dials the address from its own network
position, where `ssrfr` never classified it, and INV-5's peer check sees the
proxy's address, not the pin.

## Decision

1. **The ruling in ADR 0004 §6 is unchanged:** v1 has no proxy opt-in, and a
   trusted-proxy mode stays deferred beyond v1.
2. **Its reason is replaced.** A proxy moves the connection off the pinned path:
   it becomes the TCP peer and reaches the destination from a network position
   `ssrfr` never evaluated. A proxy given the hostname also resolves it itself.
   ADR 0004's "a proxy resolves the hostname itself" is not the reason, and is
   false for `ssrfr`'s pin.

`ssrfr-v1.md` INV-10 and §14 state the rule and its rationale.

## Consequences

- ADR 0004's decision and its `sitemapr` consequence stand: a `sitemapr`
  request through a proxy has no SSRF protection. The reason is the one above.
- Do not cite the pinned address reaching the proxy as grounds for a proxy
  opt-in. The trusted-proxy contract ADR 0004 names is still the precondition.
- Revisit together with that trusted-proxy mode, or if a probe on another
  platform or libcurl version (spec §8 item 6) shows a proxy handed the hostname
  under `connect_to`.
