# Agent workflow

The gates this repository runs, where each runs, and what a green or an empty
result means. ssrfr runs fleet-ci's tiered CI (seor ADR 0012):
`.gitlab-ci.yml` includes fleet-ci's `templates/r-package.yml`, pinned by
commit SHA, and sets only package variables and its `x-*` jobs;
`.fleet-ci.yml` holds the local gate's settings, and `.fleet-ci/` is
fleet-ci's vendored gate (re-run fleet-ci's `bin/vendor`, never edit it). R
style, tests and lints are in [`../AGENTS_LANG.md`](../AGENTS_LANG.md).

## The tiers

| Tier | Where | What runs |
| --- | --- | --- |
| hygiene hooks | pre-commit, at commit and at push | `.pre-commit-config.yaml` (below) |
| T0 | every push whose diff against `main` is docs-only (`design/**/*.md` and the like; `_pkgdown.yml` is excluded here), locally, the pre-push hook | the gate's docs tier, `.fleet-ci/gate` in the fleet image: spelling (`scripts/check-spelling.R`) and `pkgdown::check_pkgdown()` |
| T1 | every other push, locally, the pre-push hook | the gate's full tier: T0's checks, then docs drift (`scripts/check-docs-drift.R`), lintr, README drift (`scripts/check-readme-drift.sh`), the NEWS heading (`scripts/check-news-version.R`), the URL check (`scripts/check-urls.R`), one `R CMD check --as-cran` (`NOT_CRAN=true`, incoming checks off), and one more check under `LC_ALL=C.UTF-8` followed by the locale assertion (`scripts/check-locale-legs.R`) |
| T2 | the weekly `deep-check` schedule; every T3 run | `t2-check-release`, `t2-check-oldrel`, `t2-check-devel`, `x-floor` (R 4.1.3, in place of `t2-floor`), `t2-locale`, `t2-ascran` (incoming and URLs on), `coverage` (fails below 95%), `osv-audit`, `security-audit`, `citation-version`, `x-fossa`; on the schedule only, `x-renovate` |
| T3 | a `RELEASE=1` web pipeline on `main`; a `v*` tag | all of T2 but `x-renovate`, plus `t3-manual` (the PDF manual); the tag, or `RELEASE=1` on a tag, adds `pages` |

Pushes to `main` or a branch, merge requests and API pipelines (`glab ci run`)
create no pipeline at all. An empty pipeline list is not a pass: the merge
gate is the local gate (T0 or T1), run before the branch leaves the machine.

Before a CRAN submission, start T3 on `main` from **Build > Pipelines > Run
pipeline**, ref `main`, variable `RELEASE=1` (see
[release-deltas.md](release-deltas.md)). `PAGES=1` on a `v*` tag runs `pages`
alone.

## Hooks

The [pre-commit](https://pre-commit.com) config (`.pre-commit-config.yaml`) is
cloned with the repo. `pre-commit` is a Python tool: `uv tool install
pre-commit` or `pipx install pre-commit`. Each clone installs the hooks once,
from the package root:

```bash
pre-commit install
.fleet-ci/pre-push --install
```

`pre-commit install` writes both hook types
(`default_install_hook_types`); `.fleet-ci/pre-push --install` then replaces
the pre-push one with fleet-ci's, which runs the gate on each pushed ref's
tip and then the pre-commit pre-push stage. Two commands drop it:
`pre-commit install -f`, and `pre-commit install -f --hook-type pre-push`;
re-run the install after either. Without `-f`, `pre-commit install` (with or
without `--hook-type pre-push`) moves the hook to `hooks/pre-push.legacy`
(pre-commit's migration mode), which still runs the gate first; `-f
--hook-type pre-commit` leaves it alone. `.fleet-ci/gate auto` runs the gate
by hand on `HEAD`. A pass is stamped by tree, tier, classifier version, image
and (full tier) resolved dependency lock, and a stamped commit is skipped.

**On every commit:** end-of-file and trailing-whitespace fixers, merge-conflict
detection, YAML/TOML validation, mixed-line-ending and case-conflict guards, a
5 MB `check-added-large-files` guard, `air-format` on staged R files, and
`codespell` with only its en-GB_to_en-US dictionary, which rejects British
spellings in the files `spelling` never reads: code, comments, test names,
fixtures, tooling and design prose. It runs again on every push. Its
exclusions, and why, are commented in the config.

**On every push**, after the gate, in order:

| Hook | Runs | Guards |
|---|---|---|
| `check-design` | `python3 scripts/check-design.py` | frozen ADRs, frontmatter, `ARCHITECTURE.md` naming every source directory, citations of git-ignored working space |
| `check-bugreports` | `python3 scripts/check-bugreports.py` | `DESCRIPTION`'s `BugReports:`, `codemeta.json` and every tracker link name `/-/work_items`, and no human-facing file links `/-/issues` ([seor ADR 0011](https://gitlab.com/bart-turczynski/seor/-/blob/main/design/adr/0011-bugreports-names-work-items.md)); its `--self-test` runs when the script changes |
| `news-terse` | `python3 scripts/check-news.py NEWS.md` | every top-level `NEWS.md` bullet is one terse line: one source line, at most 32 words besides one trailing reference, no housekeeping, no `Internal` section ([seor's fleet standard](https://gitlab.com/bart-turczynski/seor/-/blob/main/design/fleet-standard.md)); its `--self-test` runs when the script changes |
| `fleet-ci-hook-installed` | `sh scripts/check-fleet-hook.sh` | warns, without failing, when this clone's pre-push hook is not fleet-ci's, so the push ran without the gate (time-boxed by seor SEOR-cjxarlcq) |
| `check-toolchain` | `Rscript scripts/check-toolchain.R` | the machine: roxygen2 against `Config/roxygen2/version`, packages built under a newer R, and the local pandoc against the fleet image's (`.fleet-ci/toolchain`), so a local `devtools::document()` or README knit writes what the gate accepts |
| `check-citation` | `python3 scripts/check-citation.py` | `CITATION.cff` and `.zenodo.json` name the version `DESCRIPTION` points at, and only URLs it declares |

`citation-version` runs `check-citation.py` again in every T2 and T3
pipeline.

## Project settings CI depends on, which are not in this repository

These live in GitLab's project settings, so a clone does not carry them:

- **Pipeline schedule 4459714** (Build > Pipeline schedules), `0 12 * * 1`
  Europe/Warsaw on `main`, carrying `SCHEDULE_KIND=deep-check`: T2's only
  unattended run, `x-renovate`'s too.
- **Pipeline schedule 4472814**, `SCHEDULE_KIND=dependency-audit`. The
  template starts no pipeline for it any more (the audits run in T2); its
  removal is owner-gated, seor SEOR-uldurjev.
- **`OSSINDEX_USER` / `OSSINDEX_TOKEN`**. `security-audit` sets
  `OSSINDEX_AUDIT_REQUIRED=true`, so without them it fails rather than
  passing having audited nothing.
- **`FOSSA_API_KEY`** (masked) for `x-fossa`, and **`RENOVATE_TOKEN`** for
  `x-renovate`, which skips loudly without it.
- **The Pages site** at `https://bart-turczynski.gitlab.io/ssrfr/`, which
  `_pkgdown.yml` and `DESCRIPTION` name.

Never set `SCHEDULE_KIND` as a project or group variable: every schedule
would inherit it.

Renovate follows the deep-check cadence alone: `renovate.json` sets no
`schedule`, and `prHourlyLimit` is `0` so one weekly run can open every MR it
is allowed to. A window there is read in UTC unless `timezone` is set, and a
run outside it silently creates no branch, as happened to the weekly run under
`"before 6am on monday"` (`SSRF-iyuaowff`). Renovate reads its config from
`main`, so a manual run on a branch does not test a `renovate.json` change.

## The Pages keep-list

pkgdown renders every top-level `.md` into the site, so agent instruction files
would be published next to the reference. The template's `pages` job moves
every top-level `.md` not named in `.fleet-ci.yml`'s `pages_keep` out of the
tree before `build_site`. That makes a new agent file of any name private by
default, and means a new top-level `.md` meant for the site is **not**
published until it is added to `pages_keep` in the same commit. A
`pages_keep` entry whose file is missing fails the job. `pages_keep` names
only user-facing pages; never add an agent file to it. `pages` deploys only
from a `v*` tag, so the site shows the released version. It publishes
pkgdown's default output directory, `docs/`, so `_pkgdown.yml` sets no
`destination`.

## Gaps accepted in the fleet-ci migration

- **The floor leg is `x-floor`, not the template's `t2-floor`
  (`FLEET_FLOOR: "false"`).** `t2-floor` installs every dependency from one
  dated snapshot, and ssrfr's floor closure cannot come from one: curl (>=
  7.0.0), webfakes (>= 1.4.0) and the fleet packages postdate the last
  snapshot inside R 4.1's support window, and rurl comes from a commit until
  CRAN serves its R 4.1 IPv6 fix. `x-floor` (on `.t2-job`) keeps the former
  `floor-check` unchanged; `.gitlab-ci.yml` has the detail.
- **No sanitizer leg (`FLEET_SANITIZERS: "false"`).** ssrfr has no compiled
  code; the former CI had none either.
- **No hostile locales in `x-floor`**, so `test-locale.R` skips its legs
  there; `t2-locale` and the local gate run them, and the locale assertion
  fails when they could not.
- **No Latin-5 legs.** `test-locale.R` also runs `tr_TR.ISO8859-9` and
  `tr_TR.iso88599` where the machine has them, and the former CI built them
  (`localedef -i tr_TR -f ISO-8859-9`). fleet-ci's `locales` takes the
  charmap from the name after the dot, and glibc has no charmap `ISO8859-9`:
  the local gate's build is unusable, and `t2-locale`'s is accepted with an
  ASCII codeset, a leg that is not Latin-5. So `.fleet-ci.yml` lists only
  the UTF-8 locales, the assertion requires those, and the two Latin-5 legs
  run nowhere until fleet-ci can build a locale whose charmap is not its
  name's suffix.
- **The locale leg runs under `C.UTF-8`, not `C`** (`.fleet-ci.yml`'s
  `locale_legs`). Under `LC_ALL=C` the session charset is ASCII, R cannot
  translate the test files' UTF-8 literals, and two tests fail
  (`test-resolve.R:155` among them); the former CI never ran a `C` leg. The
  hostile locales run inside `test-locale.R` whatever the leg.
- **`NOT_CRAN=true` in T1 and the T2 check legs.** The former `verify` ran
  its tests with `NOT_CRAN=true` and its check with `NOT_CRAN=false`; now
  one check, with `NOT_CRAN=true`, does both, so the `skip_on_cran()` tests
  (`test-fetch-tls.R`, `test-transport.R`) run in it. The T2 check legs also
  run `test-osv.R` and `test-security.R` against the network (the latter
  skips there without the OSS Index credentials); T1 excludes both
  (`.fleet-ci.yml`'s `exclude_tests`), and `osv-audit` and `security-audit`
  run them. A skipped test still fails T1: `allowed_skips` is empty.
- **No incoming check before a merge.** T1's check runs with
  `_R_CHECK_CRAN_INCOMING_=false`; the incoming feasibility and URL checks
  the former `verify` ran on every push run in `t2-ascran` (T2 and T3), and
  `scripts/check-urls.R` still checks every declared URL in T1.
- **`fossa analyze` runs weekly and at each release**, not on every push to
  `main` (`x-fossa`, ADR 0012), so the FOSSA badges can lag `main` by a
  week.
- **Pandoc** comes from the fleet image (`.fleet-ci/toolchain`, 3.10), which
  reproduces the committed `README.md`. `scripts/check-toolchain.R` checks a
  local pandoc against it.
