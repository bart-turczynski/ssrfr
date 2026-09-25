# ssrfr

Server-side request forgery (SSRF) protection for R applications that fetch URLs
an attacker can influence: `plumber` endpoints, Shiny apps, webhook receivers,
crawlers following redirects.

**Status: design phase.** There is no usable API yet. The contract is
[`design/specs/ssrfr-v1.md`](design/specs/ssrfr-v1.md); its §8 lists what is
still undecided. [`ARCHITECTURE.md`](ARCHITECTURE.md) is the map.

The planned shape: `ssrf_prepare_hop()` parses a URL, resolves it once,
classifies every address, and returns either a refusal with a stable reason code
or an opaque binding; `ssrf_fetch(binding)` connects only to the validated,
pinned address. Callers with their own redirect loops call it once per hop.
Parsing comes from [`rurl`](https://gitlab.com/bart-turczynski/rurl) and libcurl,
address classification from [`raddr`](https://gitlab.com/bart-turczynski/raddr).

`ssrfr` is defense in depth. It does not replace egress firewalls or network
isolation, and it cannot protect code that fetches through R's unguarded
primitives (`download.file()`, `url()`, direct `curl` or `httr2` calls).

## Setup

Install package dependencies (from `DESCRIPTION`) plus the dev tooling used by
the checks:

```sh
Rscript -e 'pak::local_install_deps(dependencies = TRUE)'
```

## Verification

```sh
Rscript -e 'lints <- lintr::lint_package(); if (length(lints)) { print(lints); quit(status = 1) }'
NOT_CRAN=true Rscript -e 'res <- as.data.frame(testthat::test_local(stop_on_failure = TRUE)); if (any(res$skipped)) { print(res[res$skipped, c("file", "test")]); quit(status = 1) }'
Rscript -e 'rcmdcheck::rcmdcheck(args = "--as-cran", error_on = "warning")'
python3 scripts/check-design.py
```

The second command runs the testthat and cucumber specs with `NOT_CRAN=true`
and fails on any skipped test, or one with no expectation
(`design/specs/ssrfr-v1.md` §7.2). `R CMD check` then runs them again as CRAN
would. All four run as pre-push hooks (`verify` and `check-design`).

## Project Layout

- `R/` contains the package source.
- `man/` contains generated help pages (regenerate with `devtools::document()`).
- `NAMESPACE` and `man/` are roxygen2-generated — edit the roxygen comments in `R/`, not these.
- `tests/testthat/` contains testthat tests and the cucumber feature specs.
- `vignettes/` contains long-form documentation.
- `DESCRIPTION` declares package metadata and dependencies.
- `design/` contains the specification, ADRs and committed evidence; `ARCHITECTURE.md` maps them.
- `docs/` is reserved for pkgdown output.
- `_scratch/` is local-only planning space and is ignored by git.
