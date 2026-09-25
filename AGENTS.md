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
- pkgdown builds into `site/` (git-ignored). Design docs never go in `docs/` or `site/`.
- Verify gate: `Rscript scripts/verify.R`, run by the pre-push `verify` hook and by CI. Enable the hooks per clone: `pre-commit install && pre-commit install --hook-type pre-push`.
- CI runs only on `main`, tags and hand-started pipelines. On a branch the pre-push hooks are the only gate; an empty pipeline list is not a pass.
- Gate red on an untouched tree: check toolchain drift first, `Rscript scripts/check-toolchain.R`.
- New top-level tooling files need a `.Rbuildignore` entry.
- `_scratch/` is disposable working space: never cite it, never update it, never read it as
  documentation. Durable knowledge goes in `design/`, ideas in an fp brainstorm.

For setup, verification, and the roxygen-generated `NAMESPACE` and `man/`, see README.md.
For R style, tests, lints and formatting, see AGENTS_LANG.md.
For the hooks, the CI jobs and the Pages KEEP list, see design/agent-workflow.md.
For the document map and package ownership across the stack, see ARCHITECTURE.md.
For open decisions blocking v1, see design/specs/ssrfr-v1.md §8.
For R and libcurl specifics and the test layers, see design/specs/r-binding.md.
For permitted compliance claims, see design/specs/ssrfr-v1.md §15.
For the design-doc lifecycle and status markers, see design/README.md.
