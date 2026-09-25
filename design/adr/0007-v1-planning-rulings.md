---
status: accepted
date: 2026-09-25
tracking: SSRF-cnljaaek
---

# ADR 0007: v1 planning rulings on the off switch and consumer migration

## Context

`ssrfr-v1.md` §8 items 25–31 were left for v1 planning (`SSRF-cnljaaek`): a
loop helper, where INV-14's off switch lives, the class names of misuse
conditions, whether a response prints its body, a consumer test helper, a
runtime check on dependency major versions, and how `robotstxtr` and `sitemapr`
migrate. Each was put to four independent voters on 2026-09-25: Claude Opus,
GPT-6 Sol and GPT-6 Astra (both through Codex, at high effort) and Claude Fable.
None was shown another's pick. Under the maintainer's rule, a unanimous vote is
applied, a majority is applied and flagged, and a split is escalated. All seven
votes were unanimous.

Most rulings only close §8 rows and add spec text. Two contradict ADR 0001,
which is frozen, so they are recorded here.

## Decision

1. **`ssrfr` has no off switch; the consumer owns it.** ADR 0001 §5 says
   "`ssrfr` therefore provides exactly one" off switch, and INV-14's corollary
   asks an implementation for one. Neither `ssrf_prepare_hop()` nor any other
   `ssrfr` function takes an argument that disables the guard. A disabled
   `prepare` has no coherent result: a binding asserts a validated address set,
   and one produced without validation would be the detached guard §9 counts
   among the causes of two-thirds of the surveyed CVEs. The one explicit off
   switch INV-14 asks for is the consumer's, as ADR 0001 §5's own ownership
   table already assigns it (`ssrf_guard = FALSE` in `robotstxtr` and
   `sitemapr`). ADR 0001 §5's constraints on its shape (a single top-level
   argument, an unmistakable name, never the default) now bind the consumer.
   ADR 0002's `allow_ranges` and `allow_hosts` remain the way to a deliberately
   authorized internal target.
2. **The consumers migrate to the guarded fetch, not to an L0 adapter.** ADR
   0001 §5 notes that "the matcher moves to `ssrfr` while per-package fetch
   integration ... stay[s] put". `ssrfr` ships no L0 compatibility adapter that
   stands in for the consumers' vendored `R/ssrf.R`. Such an adapter would keep
   an L0 check running as a gate under `ssrfr`'s name, which `ssrfr-v1.md` §1.1
   calls non-conforming, and would add a second compatibility contract. Each
   consumer replaces its vendored matcher with `ssrf_prepare_hop()` and
   `ssrf_fetch()` called from its own redirect loop once L2 ships. That
   migration is tracked in the consumer's own repository.

## Consequences

- INV-14's corollary is amended to place the switch with the consumer. A
  consumer that wants to bypass `ssrfr` calls its own transport, never an
  `ssrfr` function in a disabled mode.
- Do not add a `guard`, `enabled` or similarly named argument to any `ssrfr`
  primitive. A request for one is answered with an `allow_ranges` or
  `allow_hosts` exception, or with the consumer's toggle.
- The consumers' 17 published reason codes stay a compatibility obligation
  (§6.5); they reach the consumers through L2's refusals.
- Both consumers fetch with `httr2`, and v1's transport is the `curl` package
  only (§8 item 17). Migrating before an `httr2` adapter exists means the
  consumer calls `ssrf_fetch()` for each hop in place of `httr2`.
- Revisit item 1 if a consumer shows a need a policy exception cannot express;
  revisit item 2 if the migration cannot wait for L2.
