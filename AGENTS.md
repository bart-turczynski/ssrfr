R package: an SSRF guard for applications that fetch attacker-supplied URLs (`plumber` endpoints, Shiny apps, webhook receivers).

- L0/L1/L2 = guard layers: structural, resolved, guarded fetch. Only L2 is a defense. The L0–L4 in `r-binding.md` §7 are test layers.
- Binding = the guarded-hop result of `ssrfr-v1.md` §2, not an R language binding.
- Implement only against `[ratified]` sections of `docs/spec/ssrfr-v1.md`.
- No vendored parser or classifier: `rurl` parses, `raddr` classifies. `19f08fb` reverted a vendored denylist matcher.
- Check each diff against the 14 invariants, `docs/spec/ssrf-guard-spec.md` §4.
- Reason codes are public API; downstream packages publish them.
- Evidence tags `[verified]`, `[sourced]`, `[assumption]` stay; promote one only with new evidence.
- No CI. The pre-push `verify` hook is the only gate; enable it per clone with `pre-commit install && pre-commit install --hook-type pre-push`.
- New top-level tooling files need a `.Rbuildignore` entry.
- `_scratch/` is local-only; durable knowledge goes in `docs/`.

For setup, verification, and the roxygen-generated `NAMESPACE` and `man/`, see README.md.
For the document map, see docs/architecture.md.
For open decisions blocking v1, see docs/spec/ssrfr-v1.md §8.
For R and libcurl specifics and the test layers, see docs/spec/r-binding.md.
For permitted compliance claims, see docs/spec/ssrf-guard-spec.md §11.
For package ownership across the stack, see docs/decisions/ADR-001-network-safety-policy.md §7 and ADR-002.

@FP_AGENTS.md
