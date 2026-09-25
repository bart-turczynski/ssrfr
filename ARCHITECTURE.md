# Architecture

`ssrfr` is an SSRF guard for R applications that fetch URLs an attacker can
influence: `plumber` endpoints, Shiny apps, webhook receivers, crawlers. It is in
development. `R/` holds the policy, the result model, the closed
vocabularies with the policy data, and the structural layer (L0): the parse
boundary and the gates an address-literal host meets without resolution.
Resolution and the guarded fetch are not implemented yet.

## Where the design lives

| Path | Role |
|---|---|
| [`design/specs/ssrfr-v1.md`](design/specs/ssrfr-v1.md) | **The contract**, and the only normative document: purpose, guard layers, the guarded-hop binding, input and dependency contracts, refusal rule, reason codes, conformance (Part I); threat model, lifecycle, invariants INV-1 to INV-14, transport requirements (Part II). §8 lists the open decisions. |
| [`design/specs/r-binding.md`](design/specs/r-binding.md) | R and libcurl evidence: option names, verified transport behaviour, test layers L0–L4. No policy of its own. |
| [`design/adr/`](design/adr/) | Why. 0001 network-safety policy lineage, 0002 dependency and precedence model, 0003 the single-spec layout and what 0001/0002 no longer get right, 0004 the v1 decision-brief rulings that supersede parts of 0001 and 0002, 0005 the Fetch-Standard redirect default, 0006 the corrected reason for v1 having no proxy, 0007 the v1 planning rulings that place the off switch with the consumer and send the consumers straight to the guarded fetch. Accepted ADRs are frozen. |
| [`design/evidence/`](design/evidence/) | Committed probe scripts behind `[verified]` claims, including the July transport probes re-run on 2026-09-24. |
| [`design/references.md`](design/references.md) | Pinned source URLs for `[sourced]` claims, keyed by spec section. Non-normative. |
| [`design/README.md`](design/README.md) | The lifecycle: markers, ADRs, specs, evidence. |

The retired `ssrf-guard-spec.md` lives on as Part II of the contract; its section
map is `ssrfr-v1.md` §10.

## Guard layers

| Layer | Does | Is a defense |
|---|---|---|
| L0 structural | classifies a URL and host with no I/O | no |
| L1 resolved | resolves once and classifies every returned address | no |
| L2 guarded hop | `ssrf_prepare_hop()` returns a refusal or a binding; `ssrf_fetch(binding)` connects only to a validated, pinned address | **yes** |

L0–L4 in `r-binding.md` §7 are *test* layers, a different thing.

## Ownership across the stack

The living version of ADR 0001 §7's table.

| Concern | Owner |
|---|---|
| URL components, reference resolution, IDNA, layered parse verdicts | `rurl` (IDNA via `punycoder`, public suffixes via `pslr`) |
| The host libcurl dials, and the pin key | libcurl's own parse, `curl::curl_parse_url()` (`ssrfr-v1.md` §4.1) |
| Address parsing, IANA registry snapshots, reachability facts, embedding extraction | `raddr` |
| Policy, precedence, refusal semantics, reason codes, operational causes | `ssrfr` |
| Metadata hostname list; provider-endpoint address table | `ssrfr` (policy data, versioned separately, `ssrfr-v1.md` §6.1) |
| DNS resolution and answer-set validation (L1) | `ssrfr` |
| Pinning, transport hardening, the per-hop contract (L2) | `ssrfr` |
| Conformance corpus and parse-vector table | `ssrfr` |
| Whether to fetch a URL at all; protocol-layer URL rules | the consumer |
| Consumer-facing opt-out (`ssrf_guard = FALSE`) | the consumer |
| `X-Forwarded-For` extraction; "most restrictive reading" convenience | declined by `ssrfr` (`ssrfr-v1.md` §8 item 12); `raddr`'s ownership table is to be corrected |

`ssrfr` owns no parser and no general classification tables: `rurl` parses,
`raddr` classifies, and `ssrfr` owns only policy data such as the
provider-endpoint table (`ssrfr-v1.md` §4, ADR 0004). A vendored matcher was
tried and reverted (`19f08fb`).

## Package layout

- `R/` — package source: policy, result model, closed vocabularies and policy
  data, the dependency wrappers, and the L0 parse boundary and gates so far.
- `tests/testthat/` — testthat tests and cucumber feature specs;
  `fixtures/` holds the conformance corpus (`ssrfr-v1.md` §7).
- `vignettes/` — long-form documentation.
- `man/`, `NAMESPACE` — roxygen2 output; edit roxygen comments in `R/`.
- `design/` — specs, ADRs, evidence (above). Not built into the package.
- `scripts/check-design.py` — design-doc hygiene: frontmatter, frozen ADRs, this
  file naming every source directory.
- `scripts/corpus-manifest.R` — rewrites the corpus row counts and checksums
  (`ssrfr-v1.md` §7.2).
- `scripts/verify.R` — the verify gate, run by the pre-push hook and by CI.
- `scripts/check-toolchain.R` — pre-push check that names machine drift
  (roxygen2 skew, packages built under a newer R) before the gate runs.
- `site/` — pkgdown output (`_pkgdown.yml`), git-ignored; the CI `pages` job
  publishes it. Neither it nor `docs/` holds design documents.
- `.gitlab-ci.yml` — CI, on `main` only; see
  [`design/agent-workflow.md`](design/agent-workflow.md).

## Consumers

`robotstxtr` and `sitemapr` each ship a vendored structural matcher and publish
the 17 reason codes `ssrfr` must keep (`ssrfr-v1.md` §6.5). Neither depends on
`ssrfr` or `raddr` yet. Details: `r-binding.md` §8.
