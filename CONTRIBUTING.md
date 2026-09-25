# Contributing

Install dependencies:

```sh
Rscript -e 'pak::local_install_deps(dependencies = TRUE)'
```

Run verification:

```sh
Rscript scripts/verify.R
python3 scripts/check-design.py
```

Source lives in `R/`, tests and cucumber feature specs live in `tests/testthat/`,
and the design — specification, ADRs, evidence — lives in `design/`. Implement
only against `[ratified]` sections of `design/specs/ssrfr-v1.md`.

Do not commit `.fp/`, secrets, dependency folders, build outputs, or generated caches.
