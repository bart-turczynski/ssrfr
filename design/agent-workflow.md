# Agent workflow

The gates this repository runs, where each runs, and what a green or an empty
result means. Ported from the reference sibling `seor`, trimmed to what applies
here. R style, tests and lints are in [`../AGENTS_LANG.md`](../AGENTS_LANG.md).

## Hooks

The [pre-commit](https://pre-commit.com) config (`.pre-commit-config.yaml`) is
cloned with the repo; each clone enables the hooks once:

```bash
pre-commit install && pre-commit install --hook-type pre-push
```

`pre-commit` is a Python tool: `uv tool install pre-commit` or
`pipx install pre-commit`.

**On every commit:** end-of-file and trailing-whitespace fixers, merge-conflict
detection, YAML/TOML validation, mixed-line-ending and case-conflict guards, a
5 MB `check-added-large-files` guard, `air-format` on staged R files, and
`codespell` with only its en-GB_to_en-US dictionary, which rejects British
spellings in the files `spelling` never reads: code, comments, test names,
fixtures, tooling and design prose. It runs again on every push. Its
exclusions, and why, are commented in the config.

**On every push**, in order:

| Hook | Runs | Guards |
|---|---|---|
| `check-design` | `python3 scripts/check-design.py` | frozen ADRs, frontmatter, `ARCHITECTURE.md` naming every source directory, citations of git-ignored working space |
| `check-bugreports` | `python3 scripts/check-bugreports.py` | the BugReports split: `DESCRIPTION` on `/-/issues`, human-facing tracker links on `/-/work_items` (SEOR-ocbtrrnl); its `--self-test` runs when the script changes |
| `check-toolchain` | `Rscript scripts/check-toolchain.R` | the machine: roxygen2 against `Config/roxygen2/version`, packages built under a newer R |
| `check-citation` | `python3 scripts/check-citation.py` | `CITATION.cff` and `.zenodo.json` name the version `DESCRIPTION` points at, and only URLs it declares |
| `check-urls` | `Rscript scripts/check-urls.R` | every URL the package declares answers; a dead one fails, an unreachable host only warns, and the only exemption is `BugReports`' `/-/issues` 404 |
| `spelling` | `Rscript scripts/check-spelling.R` | spelling of `DESCRIPTION`, `man/`, vignettes, README and NEWS against en-US and `inst/WORDLIST` |
| `verify` | `Rscript scripts/verify.R` | the package; stages listed in the script's header |

`verify` is the same file the CI `verify` job runs. CI also runs
`check-bugreports`, `check-citation` and `spelling` (see below);
`check-design`, `check-toolchain` and `check-urls` run only locally.

## CI

`.gitlab-ci.yml` has a top-level `workflow:` block that admits only a tag, a
push to `main`, or a hand-started (`web`) pipeline. **A branch push and a merge
request create no pipeline**, so on a feature branch the pre-push `verify` hook
is the only gate that runs anywhere. A branch's empty pipeline list is not a
pass: there is no result. For a server-side answer before merging, start one by
hand at **Build > Pipelines > Run pipeline** and pick the ref.

| Job | When | Does |
|---|---|---|
| `verify` | `main` (a schedule too), `web` | `scripts/verify.R` |
| `gates` | `main` (a schedule too), `web` | `scripts/gates.sh`: README drift against a fresh knit of `README.Rmd` (pandoc pinned), and spelling |
| `citation-version` | `main` (a schedule too), `web` | `check-citation.py` and `check-bugreports.py`, each with its self-test |
| `coverage` | `main` (a schedule too), `web` | `covr`, reported as a GitLab coverage artifact; fails below 95% |
| `full-check` | a `deep-check` schedule, `web` (manual) | `scripts/verify.R` on R release, oldrel and devel |
| `floor-check` | a `deep-check` schedule, `web` (manual) | `R CMD check --as-cran` on R 4.1.3, the declared floor, with dependencies from a dated package snapshot |
| `pages` | `main` only (a schedule too) | the pkgdown site, published to GitLab Pages |
| `renovate` | a `deep-check` schedule, `web` (manual) | CI image bumps (`renovate.json`) |
| `osv-audit` | a `dependency-audit` schedule, `web` (manual) | `tests/testthat/test-osv.R`: OSV advisories against the runtime closure |
| `security-audit` | a `dependency-audit` schedule, `web` (manual) | `tests/testthat/test-security.R`: OSS Index advisories, each needing a row in `helper-security.R` |
| `fossa` | a push to `main` | `fossa analyze`, for the README's FOSSA badges |

A schedule runs `full-check`, `floor-check` and `renovate` only when it sets
the variable `SCHEDULE_KIND=deep-check` on the schedule itself, and
`osv-audit` and `security-audit` only when it sets
`SCHEDULE_KIND=dependency-audit`; any other schedule skips them. A schedule's
pipeline is on `main`, so `verify`, `gates`, `citation-version`, `coverage`
and `pages` run on every schedule, whatever its kind. Never set
`SCHEDULE_KIND` as a project or group variable: every schedule would inherit
it.

Renovate follows that cadence alone: `renovate.json` sets no `schedule`, and
`prHourlyLimit` is `0` so one weekly run can open every MR it is allowed to. A
window there is read in UTC unless `timezone` is set, and a run outside it
silently creates no branch, as happened to the weekly run under
`"before 6am on monday"` (`SSRF-iyuaowff`). Renovate reads its config from `main`, so a manual run on a
branch does not test a `renovate.json` change.

`pages` is pinned to `main` because it publishes rather than reports; a
hand-started pipeline on a branch must not deploy unmerged code.

## The Pages KEEP list

pkgdown renders every top-level `.md` into the site, so agent instruction files
would be published next to the reference. The `pages` job moves every
top-level `.md` not named in its `KEEP` variable out of the tree before
`build_site`. That makes a new agent file of any name private by default, and
means a new top-level `.md` meant for the site is **not** published until it is
added to `KEEP` in the same commit. A `KEEP` entry whose file is missing fails
the job. `KEEP` names only user-facing pages; never add an agent file to it.
