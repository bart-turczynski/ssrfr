R package: an SSRF guard for applications that fetch attacker-supplied URLs (`plumber` endpoints, Shiny apps, webhook receivers).

- L0/L1/L2 = guard layers: structural, resolved, guarded fetch. Only L2 is a defense. The L0–L4 in `r-binding.md` §7 are test layers.
- Binding = the guarded-hop result of `ssrfr-v1.md` §2, not an R language binding.
- `design/specs/ssrfr-v1.md` is the only normative document. State a rule once there; elsewhere point to it.
- Implement only against `[ratified]` sections. `[suspended]` marks ratified text whose premise broke; don't re-ratify it yourself.
- No vendored parser or classifier: parsing comes from `rurl` and libcurl, classification from `raddr`. `19f08fb` reverted a vendored denylist matcher.
- Check each diff against the 14 invariants, `ssrfr-v1.md` §13.
- Reason codes are public API; downstream packages publish them (`ssrfr-v1.md` §6.5).
- Evidence tags `[verified]`, `[sourced]`, `[assumption]` stay; promote one only with new evidence, committed under `design/evidence/`.
- Accepted ADRs are frozen: supersede, never edit. `python3 scripts/check-design.py` enforces it.
- `docs/` is pkgdown output, never design docs.
- No CI yet. The pre-push hooks (`verify`, `check-design`) are the only gate; enable them per clone with `pre-commit install && pre-commit install --hook-type pre-push`.
- New top-level tooling files need a `.Rbuildignore` entry.
- `_scratch/` is local-only; durable knowledge goes in `design/`.

For setup, verification, and the roxygen-generated `NAMESPACE` and `man/`, see README.md.
For the document map and package ownership across the stack, see ARCHITECTURE.md.
For open decisions blocking v1, see design/specs/ssrfr-v1.md §8.
For R and libcurl specifics and the test layers, see design/specs/r-binding.md.
For permitted compliance claims, see design/specs/ssrfr-v1.md §15.
For the design-doc lifecycle and status markers, see design/README.md.
