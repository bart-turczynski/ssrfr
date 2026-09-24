---
status: accepted
date: 2026-09-24
tracking: SSRF-ibxdyzcy
---

# ADR 0003: One normative spec, and what 0001 and 0002 no longer get right

## Context

By September the design lived in five documents that restated each other. The
allow/deny precedence model was written out in full four times (the guard spec
§8, `ssrfr-v1.md` §5.0, ADR 0001 §5's amendment box, ADR 0002 §2), and INV-8's
header rules twice. `ssrfr-v1.md` §10 listed eleven amendments the guard spec and
`r-binding.md` needed; about seven were never applied, so the guard spec still
stated superseded positions. The guard spec's reason for being separate — that a
second-language implementation would share it — never materialized: the sibling
TypeScript project, `linklint`, has its own documents and codes and never cites
`ssrfr`.

A review of the siblings on 2026-09-24, with probes committed as
`design/evidence/2026-09-24-dependency-probes.R`, also found premises under
ratified text that are no longer true. `rurl` 3.0 parses in-tree and no longer
wraps `curl`; `raddr` answers reachability for an outer NAT64 address without
consulting what it embeds.

The family convention (`seor` `design/README.md`) keeps design documents in
`design/`, leaves `docs/` to pkgdown, and freezes accepted ADRs: they are
superseded, never edited.

## Decision

1. **`design/specs/ssrfr-v1.md` is the only normative document.** The guard spec
   is merged into it as Part II (threat model, lifecycle, invariants INV-1 to
   INV-14, transport requirements, compliance claims) and deleted. Its §10 maps
   every retired section to its new home, so citations such as "the guard spec
   §5.2" stay resolvable. Each rule is stated once; other sections point to it.
2. **`design/specs/r-binding.md` holds evidence, not policy.** R and libcurl
   option names, verified behaviour, test layers.
3. **ADRs record why.** 0001 and 0002 stay as history with their bodies
   unchanged, including the amendment boxes 0001 received before this convention
   applied. Where they are wrong today, the list below says so.
4. **A ratified clause whose premise breaks is suspended, not rewritten.** It
   keeps its text under a **[suspended]** marker, with the correction and a
   **[proposed]** replacement beside it, until the maintainer ratifies the
   replacement. Sections carried from the guard spec are marked **[inherited]**
   until ratified.
5. **Evidence behind new `[verified]` claims is committed** under
   `design/evidence/`.

### What ADR 0001 no longer gets right

| 0001 | Says | Now |
|---|---|---|
| §0, row "§1 malformed IPv6 literals fail open → Reversed" | `sitemapr` fails open | `sitemapr` amended its ADR-003 on 2026-07-25 to fail closed with `malformed-address`; not a divergence any more. |
| §2.3 | 6to4 `2002::/16` and Teredo `2001::/32` "are legitimately globally reachable" | IANA marks both "Globally Reachable: N/A"; `raddr` reports `NA`, and `ssrfr` refuses both at tier 1 (`ssrfr-v1.md` §5.1). |
| §2.4, and INV-13 as it stood | Equinix Metal and IBM VPC metadata have no link-local address | IBM's is `169.254.169.254` or `api.metadata.cloud.ibm.com`; Equinix Metal was sunset on 2026-06-30. The hostname layer stands, justified by endpoint identity (`ssrfr-v1.md` §5, gate 5). |
| §2.4 | the dual-host (`host` + `raw_host`) L0 signature survives | `rurl`'s numeric-literal diagnostics carry the raw-host shape (`r-binding.md` §2.3). |
| §7, second constraint | `ssrfr` must not delegate its parse to a foreign parser | Still the rule. What changed is that `rurl` is no longer a wrapper over the transport's parser, so the spec proposes keying the pin on `curl_parse_url()` (`ssrfr-v1.md` §4.1, suspended). |
| §9 | the two ADR-003 corrections are "tracked separately" | `sitemapr` made both on 2026-07-25. |
| Revisit conditions | "`raddr` reaches CRAN" | Met: `raddr` 0.1.2 is on CRAN (2026-09-21). |
| links | `docs/spec/…`, `docs/decisions/…` | The files are now under `design/specs/` and `design/adr/`. |

### What ADR 0002 no longer gets right

| 0002 | Says | Now |
|---|---|---|
| §1 | "`rurl` owns URL parsing" | `rurl` owns reference resolution, IDNA and the layered verdicts; the host libcurl dials is proposed to come from libcurl's own parse (`ssrfr-v1.md` §4.1, suspended). |
| §1 | `ssrfr` owns no "classification tables" | Proposed amendment: no *general* classification tables. `ssrfr` owns provider-endpoint policy data, which `raddr` assigns to it (`ssrfr-v1.md` §4, §5 gate 2). |
| Consequences | `raddr` grades embeddings, so an allow range only matches the wrapper | Still true, but `ssrfr` must read the embedding rows itself; the outer reachability does not reflect them (`ssrfr-v1.md` §5.2, suspended). |

## Consequences

- One place to change a rule, and a checker (`scripts/check-design.py`) that
  keeps accepted ADRs frozen.
- A second-language implementation would now have to extract a shared contract
  from Part II again. That is the right time to pay that cost, not before.
- Suspension makes stale ratified text visible without deciding for the
  maintainer; `ssrfr-v1.md` §8 items 10, 11 and 14 track what awaits
  ratification.
- Sibling repositories that cite `ssrfr` `docs/decisions/ADR-001-…` or "the
  guard spec §N" keep working through the map in `ssrfr-v1.md` §10 and this
  ADR's tables; updating their links is their own change.
- Revisit if a second implementation is started, or if Part II grows a second
  normative home.
