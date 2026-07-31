# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

@FP_CLAUDE.md

## What this package is

`ssrfr` is an R package providing an SSRF guard for applications that fetch
attacker-supplied URLs (`plumber` endpoints, Shiny apps, webhook receivers). It
extracts the structural matcher vendored in `robotstxtr/R/ssrf.R` and
`sitemapr/R/ssrf.R` and grows it into a full guard that owns DNS resolution,
address pinning, transport hardening, and the redirect loop.

## Current state — read before writing code

The package is **specification-complete and implementation-empty.** `R/scaffold.R`
is still the template placeholder; the only test is the scaffold cucumber feature.

A vendored L0 matcher was landed (`a978f8d`, PR #4) and then reverted (`19f08fb`,
PR #5). Read that revert message before proposing any classification code — it is
the load-bearing decision in this repo's history. Summary: the port was faithful,
but what it was faithful to is a *denylist with a default allow*, and ADR-001 §2
requires classification to gate on a positive routability predicate. Landing the
denylist and scheduling "close the gaps" as a follow-up is the treadmill the ADR
exists to reject — the structure was the defect, the missing ranges only its
symptoms.

**`docs/spec/ssrfr-v1.md` answers that revert** and is now the document to read
first. Its §4 replaces the vendored classifier with a hard dependency on `raddr`,
which already implements the positive model. The correct response to `a978f8d` was
never to close the denylist's gaps range by range; it was to stop having a
vendored classifier. `SSRF-aqrgqdhi` shrinks accordingly, from "design the
positive classification model" to "specify the mapping from `raddr` facts to
refusals and reason codes."

Still open and blocking the v1 API freeze: whether any limit is a non-overridable
floor (`SSRF-pffrmkdr`), the refusal rule (`ssrfr-v1.md` §5, proposed but
unratified), and `raddr` ↔ published reason-code alignment (§6.3, unverified).
Component-wise vs whole-URL API (`SSRF-tnxmqvou`) is closed: URL string only.

## Commands

```sh
# Dependencies (from DESCRIPTION, plus dev tooling)
Rscript -e 'pak::local_install_deps(dependencies = TRUE)'

# Enable the hooks once per clone
pre-commit install && pre-commit install --hook-type pre-push

# Verify — the exact chain the pre-push hook runs. There is no .github/ CI
# workflow in this repo; this local gate is the only gate.
Rscript -e 'lints <- lintr::lint_package(); if (length(lints)) { print(lints); quit(status = 1) }' \
  && Rscript -e 'rcmdcheck::rcmdcheck(args = "--as-cran", error_on = "warning")'

# Regenerate NAMESPACE and man/ after editing roxygen comments
Rscript -e 'devtools::document()'

# One test file / one expectation
Rscript -e 'devtools::test(filter = "cucumber")'
Rscript -e 'testthat::test_local(filter = "cucumber")'

# Integration layer (real DNS, TLS chains, IPv6 pinning) — never runs on CRAN
SSRFR_INTEGRATION_TESTS=1 Rscript -e 'devtools::test()'
```

The cucumber features run inside the normal `testthat` pass (`test-cucumber.R`
calls `cucumber::run(".")`, with steps registered by `setup-steps.R`), so
`R CMD check` verifies the behavior specs. There is no separate BDD step. Step
registration is guarded on `requireNamespace("cucumber")` so the CRAN
suggests-only check (`_R_CHECK_DEPENDS_ONLY_=true`) degrades to a skip.

`/cran` runs the fuller pre-submission chain when CRAN readiness is the question.

## Document hierarchy

Durable knowledge lives in `docs/`, and the split between the three documents is
enforced deliberately:

| Document | Role |
|---|---|
| `docs/spec/ssrfr-v1.md` | **Read first.** `ssrfr`'s own v1 spec: purpose, layer contracts, the guarded-hop binding primitive, URL input contract, dependency contract, refusal rule, result model. Sections are marked `[ratified]` / `[proposed]` / `[open]`; only ratified sections may be implemented against. |
| `docs/spec/ssrf-guard-spec.md` | The normative contract. Language-agnostic: threat model, L0/L1/L2, request lifecycle, 14 invariants, reason codes, conformance. A second-language implementation shares *this*, not code. |
| `docs/spec/r-binding.md` | R/libcurl specifics: option names, empirically verified transport constraints, the five-layer test architecture. |
| `docs/decisions/ADR-001-network-safety-policy.md` | The policy layer. What carries over from `sitemapr` ADR-003, what is reversed, which inherited gaps are closed. |

Keep libcurl detail out of the spec — it belongs in `r-binding.md`. ADR-001
supersedes `sitemapr` ADR-003 §1 and §4 **for `ssrfr`'s scope only**; ADR-003
remains in force for `sitemapr` and is not amended by anything here.

Claims in the specs are tagged `[verified]` (tested empirically), `[sourced]`
(external evidence), or `[assumption]`. Preserve the tags when editing, and do
not promote an assumption without doing the work. The evidence base
(`_scratch/research/`, 11 reports) is local-only and not committed.

## Architecture

### The layer model is the API design

| Layer | I/O | Guarantee |
|---|---|---|
| L0 structural classification | none | not *self-evidently* prohibited. **Not an SSRF defense.** |
| L1 resolved check | DNS | every address this host currently resolves to is permitted; still TOCTOU-exposed |
| L2 guarded fetch | DNS + TCP | the connection went to a validated address. The only layer that is a defense. |

Spec §2.1 makes L0 naming normative: `is_safe()`, `check()`, `validate()` on L0
are **non-conforming**. The reverted PR's `ssrf_classify_host()` returning a
`prohibited` flag was the right naming instinct; the two-state flag was itself a
finding, since it could not express "indeterminate" and so made fail-closed
unrepresentable in the type.

L2 must be invocable **per hop from someone else's redirect loop** — both
existing consumers (`robotstxtr`, `sitemapr`) already run their own loops.
"We own the fetch" as the only shape is non-conforming.

### Invariants to check any diff against

The 14 invariants in spec §4 are the safety properties, each with a CVE behind
it. The ones most likely to be violated by a plausible-looking change:

- **INV-1** — parse with the parser whose result the transport dials. In R that
  is libcurl, via `rurl::safe_parse_url(url, url_standard = "whatwg")`. The
  standard is fixed internally and MUST NOT be exposed. Never parse addresses
  with `ipaddress` (`ip_address("0177.0.0.1")` → `177.0.0.1`, while curl dials
  `127.0.0.1`).
- **INV-3** — rules match the decoded numeric value, never the literal string.
  The sibling packages shipped the same IPv6 string-matching bug twice, and it
  survived a first fix.
- **INV-5/6** — resolve exactly once per hop; pin with `connect_to = "HOST::IP:"`
  (no port key, so the verified port-key fail-open cannot occur). Always emit the
  trailing colon. Prefer `connect_to` over `resolve`, which is skipped entirely
  when a pooled connection matches.
- **INV-11** — fail closed. There is no path from "we could not determine this"
  to "proceed". An absent or `NA` host is a refusal.
- **INV-13** — positive routability predicate, not an enumerated denylist. This is
  now `raddr`'s job: `addr_global_reachability()` is registry-driven, returns
  `TRUE`/`FALSE`/`NA`, and grades embeddings by their extracted address. `ssrfr`
  MUST NOT re-extract embedded addresses — a second decoder inventory would
  diverge, and divergence in exactly this code is the documented history of the
  stack (`ssrfr-v1.md` §5.2).
- **INV-14** — deny wins over allow, uniformly, with exactly one explicit,
  unmistakably named off switch.

### Reason codes are a public compatibility surface

The vocabulary in spec §5.2 is `kebab-case` and constrained by values already
published in downstream reference docs — renaming breaks consumers. Codes must be
enumerable at runtime. Policy refusal and operational (wire) failure are distinct
outcomes callers branch on without string matching. Two inherited misnomers are
corrected deliberately rather than propagated: CGNAT `100.64.0.0/10` and IPv6
unique-local space were both reported as `cloud-metadata`.

### Ownership across the four-package stack

`rurl` owns URL parsing/normalization; `raddr` owns address parsing and
classification tables; `ssrfr` owns L0/L1/L2, the reason-code vocabulary, the
result model, and the conformance corpus; the consumer owns whether to fetch at
all and its own `ssrf_guard = FALSE` toggle. Full table in ADR-001 §7.

**`ssrfr` owns no parser and no classification tables** (`ssrfr-v1.md` §4).
`curl`, `rurl`, and `raddr` are hard dependencies; `ssrfr` consumes their facts
and owns policy, refusal semantics, per-hop revalidation, pinning, and the
conformance corpus. Release ordering is a submission-time scheduling concern, not
a design input — all local versions are ahead of CRAN and expected to change.

This reverses `ADR-001` §7's *"`ssrfr` does not block on `raddr`"* and the
vendored-core position in `r-binding.md` §1. Those documents are not yet amended;
`ssrfr-v1.md` §10 lists every contradiction and calls for **ADR-002** rather than
silent supersession. Measured weights invert BRAINSTORM §8's assumption: `raddr`
is `rlang` + `vctrs` with no `src/`, while `rurl` pulls `stringi` plus two
compiled packages.

### Testing architecture (r-binding.md §7)

Five layers: L0 golden tables; L1 `local_mocked_bindings()` on an internal,
unexported `nslookup` wrapper, with a **counting mock proving resolve-once**; L2
loopback `webfakes` app pinned via a `.invalid` hostname; L3 raw
`base::serverSocket()` wire-byte reads; L4 env-gated integration. Only L4 needs
the network, so `R CMD check` stays offline-clean.

Hard constraints: **no public `resolver` argument, ever** (add a test asserting
the seam cannot be overridden from outside the namespace); `.invalid` hosts are a
free negative control, since a passing L2 test then *proves* the pin was
load-bearing; `webfakes` cannot bind `::1`; `webmockr`/`vcr`/`httptest2` cannot
intercept raw `curl`; no fake DNS server is possible in R.

`debugfunction` is the only way to observe the dialed address from R. It is a
**detector, never the gate** — by the time it reports `Trying …`, `connect()` has
been issued. Any matching on its output must fail safe.

## Compliance claims

Permitted with citation: OWASP SSRF Prevention Cheat Sheet, ASVS 5.0 (V1.3.6,
V13.2.4, V13.2.5, V15.3.2, V1.5.3), CWE-918, CAPEC-664, WSTG, RFC 6874 §4.
Not permitted (spec §11): a year-less "OWASP Top 10 A10 = SSRF", "ASVS V50", PCI
DSS or CIS benchmarks, any claim that the library replaces network-level egress
control, and any claim that L0 provides SSRF protection.

## Conventions

- `NAMESPACE` and `man/` are roxygen2-generated — edit the roxygen comments in
  `R/`, never the generated files.
- `.lintr` disables `object_usage_linter` because the cucumber/testthat DSL
  (`when`/`then`/`expect_*`) reads as undefined globals. Re-enabling it once real
  code exists is worth doing.
- `.Rbuildignore` excludes the whole dev-tooling layer (`docs/`, `_scratch/`,
  `.fp/`, agent instruction files); new top-level tooling files need an entry or
  `R CMD check --as-cran` flags non-standard files.
- `DESCRIPTION` is still template placeholder text (Title, Authors@R,
  Description) and must be filled in before any CRAN submission.
