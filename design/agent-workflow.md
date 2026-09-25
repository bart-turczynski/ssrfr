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
5 MB `check-added-large-files` guard, and `air-format` on staged R files.

**On every push**, in order:

| Hook | Runs | Guards |
|---|---|---|
| `check-design` | `python3 scripts/check-design.py` | frozen ADRs, frontmatter, `ARCHITECTURE.md` naming every source directory, citations of git-ignored working space |
| `check-toolchain` | `Rscript scripts/check-toolchain.R` | the machine: roxygen2 against `Config/roxygen2/version`, packages built under a newer R |
| `verify` | `Rscript scripts/verify.R` | the package; stages listed in the script's header |

`verify` is the same file the CI `verify` job runs. `check-design` and
`check-toolchain` run only locally.

## CI

`.gitlab-ci.yml` has a top-level `workflow:` block that admits only a tag, a
push to `main`, or a hand-started (`web`) pipeline. **A branch push and a merge
request create no pipeline**, so on a feature branch the pre-push `verify` hook
is the only gate that runs anywhere. A branch's empty pipeline list is not a
pass: there is no result. For a server-side answer before merging, start one by
hand at **Build > Pipelines > Run pipeline** and pick the ref.

| Job | When | Does |
|---|---|---|
| `verify` | `main`, `web` | `scripts/verify.R` |
| `coverage` | `main`, `web` | `covr`, reported as a GitLab coverage artifact |
| `full-check` | schedule, `web` (manual) | `scripts/verify.R` on each R version in its matrix |
| `pages` | `main` only | the pkgdown site, published to GitLab Pages |
| `renovate` | schedule, `web` (manual) | CI image bumps (`renovate.json`) |

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
