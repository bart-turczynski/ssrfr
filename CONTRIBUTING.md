# Contributing

Install dependencies:

```sh
Rscript -e 'pak::local_install_deps(dependencies = TRUE)'
```

Run verification:

```sh
Rscript -e 'lints <- lintr::lint_package(); if (length(lints)) { print(lints); quit(status = 1) }' && Rscript -e 'rcmdcheck::rcmdcheck(args = "--as-cran", error_on = "warning")'
python3 scripts/check-design.py
```

Source lives in `R/`, tests and cucumber feature specs live in `tests/testthat/`,
and the design — specification, ADRs, evidence — lives in `design/`. Implement
only against `[ratified]` sections of `design/specs/ssrfr-v1.md`.

Do not commit `.fp/`, secrets, dependency folders, build outputs, or generated caches.
