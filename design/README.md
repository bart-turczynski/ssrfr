# Design docs

Durable, tracked design documentation. Unlike `_scratch/` (git-ignored, never on
a fresh clone), everything here is committed and travels with the code.

Design docs never live in `docs/`, which belongs to pkgdown.

## Layout

- [`specs/ssrfr-v1.md`](specs/ssrfr-v1.md) — the contract. The only normative
  document.
- [`specs/r-binding.md`](specs/r-binding.md) — R and libcurl evidence for the
  contract.
- [`adr/`](adr/) — Architecture Decision Records: one file per load-bearing
  decision, capturing the *why* and a status. Start from
  [`adr/0000-template.md`](adr/0000-template.md).
- [`evidence/`](evidence/) — probe scripts that reproduce `[verified]` claims.
  Name them `YYYY-MM-DD-topic.R` and record the environment in the header.

See also [`../ARCHITECTURE.md`](../ARCHITECTURE.md) for the structural map.

## Lifecycle

Drafts start in `_scratch/`. A draft graduates to `specs/` when it stops being
"what if" and becomes what we are building. On ship, distill the durable facts
into `ARCHITECTURE.md` and the load-bearing choices into an ADR, then set the
spec's status to `shipped` and never update it again.

Inside a spec, only **[ratified]** sections may be implemented against. The
other markers — **[proposed]**, **[open]**, **[inherited]**, **[suspended]** —
are defined at the top of `ssrfr-v1.md`. When a ratified premise turns out to be
false, mark the clause **[suspended]**, add the correction and a **[proposed]**
replacement beside it, and leave ratification to the maintainer (ADR 0003).

State each rule once. Other sections and documents point to it.

## Writing an ADR

1. Copy `adr/0000-template.md` to `adr/NNNN-short-slug.md` (next number).
2. Fill in Context / Decision / Consequences; set `status: accepted`.
3. When a later ADR overturns it, set this one's `status: superseded` and
   `superseded-by:` rather than deleting it. Never edit the body of an accepted
   ADR; `scripts/check-design.py` enforces it.
4. Link the ADR from `ARCHITECTURE.md` where the structure it governs is
   described.
