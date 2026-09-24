---
status: accepted
date: 2026-09-24
tracking: SSRF-aqrgqdhi, SSRF-pffrmkdr, SSRF-uitcvnif, SSRF-iuqixghb
---

# ADR 0004: v1 decision-brief rulings that supersede parts of 0001 and 0002

## Context

On 2026-09-24 the open items of `ssrfr-v1.md` §8 were compared against about 40
SSRF libraries and collected in the v1 decision brief (fp brainstorm
`nftbfuli`). A second opinion from another model family reviewed every item, and
the maintainer ratified the result the same day. Most rulings only flip spec
markers. Six of them contradict text in accepted ADRs, which are frozen, so they
are recorded here. ADR 0003 records the earlier corrections.

## Decision

1. **Provider endpoints are overridable only by an exact entry.** ADR 0002 §2
   lets `allow_ranges` override every determinate built-in address refusal. For
   the provider-endpoint table (`ssrfr-v1.md` §5, gate 2) that is narrowed: only
   an `allow_ranges` entry that names the endpoint exactly (a /32 or /128)
   overrides it. `allow_ranges = "169.254.0.0/16"` no longer unblocks IMDS.
   Mature application guards keep metadata blocked under a broad private-network
   opt-in; a never-overridable rule would break legitimate agents running on the
   VM.
2. **A `reserved` reason code.** ADR 0001 §2.2 files reserved, IETF-protocol and
   benchmarking space under `private`. It gets its own public code, `reserved`,
   instead. The change is additive: the inherited denylist never covered these
   ranges, so no consumer has ever received `private` for them, and no code is
   renamed. Azure WireServer stays under `cloud-metadata`, with its kind
   (`provider-internal`) in operator detail.
3. **`ssrfr` owns policy data, not general classification tables.** ADR 0002 §1
   says `ssrfr` owns no classification tables. It owns no *general*
   address-classification tables; it does own the metadata hostname list and the
   provider-endpoint table, which `raddr` assigns to it.
4. **Limits are finite and raisable, with no ceiling.** ADR 0001 §6 left open
   whether any limit is a non-overridable floor. None is. Every limit has a
   finite default, can be raised without a ceiling, and has no "unlimited"
   sentinel. The defaults are 10 redirects, 3 s connect, 30 s total for the
   whole redirect chain, 10 MiB of decoded body, and 16 KiB or 128 header fields
   per hop. No surveyed library ships a non-overridable ceiling.
5. **The default User-Agent.** ADR 0001 §8 left it open. It is
   `ssrfr/<version> (+https://gitlab.com/bart-turczynski/ssrfr)`, assembled at
   runtime from `DESCRIPTION`, overridable, and refused if it contains CR, LF or
   NUL.
6. **No proxy opt-in in v1.** INV-10, inherited from the guard spec, disabled
   proxies "unless the caller explicitly opts in". The opt-in is removed. A proxy
   resolves the hostname itself, so an opted-in proxy returns what looks like a
   guarded fetch while guarding nothing. A trusted-proxy mode, in which the proxy
   enforces destination policy and `ssrfr`'s claim narrows to match, is deferred
   beyond v1.

`ssrfr-v1.md` states each rule: §5.0 (1), §6.5 (2), §4 (3), §5.3 (4, 5) and
INV-10 (6).

## Consequences

- An operator who authorizes a link-local range for an appliance must list any
  provider endpoint they really want, one address at a time.
- Consumers see one new code, `reserved`. `robotstxtr` and `sitemapr` add it when
  they adopt `ssrfr`.
- Applications that can reach the internet only through a mandatory egress proxy
  cannot use the guarded fetch in v1. `sitemapr`'s `request_policy(proxy = )`
  must be documented as SSRF protection off when it moves onto `ssrfr`. In
  effect it already is, because the proxy resolves the hostname itself.
- Do not reintroduce a proxy switch without the trusted-proxy contract. Revisit
  when a consumer needs a proxy and can name the proxy's destination policy.
