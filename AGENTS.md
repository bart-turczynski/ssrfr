R package: an SSRF guard for applications that fetch attacker-supplied URLs (`plumber` endpoints, Shiny apps, webhook receivers).

- L0/L1/L2 = guard layers: structural, resolved, guarded fetch. Only L2 is a defense. The L0–L4 in `r-binding.md` §7 are test layers.
- Binding = the guarded-hop result of `ssrfr-v1.md` §2, not an R language binding.
- `design/specs/ssrfr-v1.md` is the only normative document. Implement only against `[ratified]` sections.
- No vendored parser or classifier: parsing comes from `rurl` and libcurl, classification from `raddr`. `19f08fb` reverted a vendored denylist matcher.
- Check each diff against the 14 invariants, `ssrfr-v1.md` §13.
- Reason codes are public API; downstream packages publish them (`ssrfr-v1.md` §6.5).
- New top-level tooling files need a `.Rbuildignore` entry.
- `_scratch/` is disposable working space: not documentation, never cited. Durable knowledge goes in `design/`, ideas in an fp brainstorm.

## Verification

Gate: local
Verify: .fleet-ci/gate auto

The merge gate is fleet-ci's local gate, run in the fleet image by the pre-push hook (install it once per clone with `.fleet-ci/pre-push --install`); its settings are `.fleet-ci.yml`. A diff against `main` the classifier calls docs-only (`design/**/*.md` and the like; `_pkgdown.yml` is excluded here) gets T0, spelling and `pkgdown::check_pkgdown()`; any other gets T1, the cheap gates and `R CMD check` with the hostile-locale assertion.
Branch pushes, merge requests and pushes to `main` create no pipeline, so an empty pipeline list is not a pass. CI runs fleet-ci's template: T2 on the weekly `deep-check` schedule, T3 on a `RELEASE=1` web pipeline and on the `v*` tag (seor ADR 0012).

For setup and the roxygen-generated `NAMESPACE` and `man/`, see README.md.
For R style, tests, lints, formatting and a red gate on an untouched tree, see AGENTS_LANG.md.
For the tiers, the hooks, the CI jobs, the Pages keep-list and the gaps the fleet-ci migration accepted, see design/agent-workflow.md.
For the document map and package ownership across the stack, see ARCHITECTURE.md.
For the design-doc lifecycle and ADRs, see design/README.md.
For status markers, evidence tags, open v1 decisions and compliance claims, see design/specs/ssrfr-v1.md: its top, §8 and §15.
