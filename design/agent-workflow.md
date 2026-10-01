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
| `spelling` | `Rscript scripts/check-spelling.R` | spelling of `DESCRIPTION`, `man/`, vignettes, README and NEWS against en-US and `inst/WORDLIST` |
| `verify` | `Rscript scripts/verify.R` | the package; stages listed in the script's header |

`verify` is the same file the CI `verify` job runs. `check-design`,
`check-bugreports`, `check-toolchain` and `spelling` run only locally.

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
| `coverage` | `main` (a schedule too), `web` | `covr`, reported as a GitLab coverage artifact |
| `full-check` | a `deep-check` schedule, `web` (manual) | `scripts/verify.R` on each R version in its matrix |
| `pages` | `main` only (a schedule too) | the pkgdown site, published to GitLab Pages |
| `renovate` | a `deep-check` schedule, `web` (manual) | CI image bumps (`renovate.json`) |

A schedule runs `full-check` and `renovate` only when it sets the variable
`SCHEDULE_KIND=deep-check` on the schedule itself, as the weekly one must; any
other schedule skips them. A schedule's pipeline is on `main`, so `verify`,
`coverage` and `pages` run on every schedule, whatever its kind. Never set
`SCHEDULE_KIND` as a project or group variable: every schedule would inherit
it and run the deep checks.

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
