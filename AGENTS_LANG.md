This is an R package built the way CRAN verifies it. Follow the tidyverse
[style guide](https://style.tidyverse.org) and
[design guide](https://design.tidyverse.org).

### Dev loop

Install the dev tools locally (`devtools`, `lintr`, `rcmdcheck`); they are not
package dependencies, so they are not in `DESCRIPTION`.

- Load for interactive work: `devtools::load_all()` (or `pkgload::load_all()`).
- Run tests: `testthat::test_local(reporter = "check")`; a single file with
  `testthat::test_local(filter = "corpus")` (matches `test-corpus.R`).
- Regenerate docs: `devtools::document()` — rebuilds `man/` and `NAMESPACE` from
  the roxygen comments in `R/`.
- Verify gate: `Rscript scripts/verify.R`. The pre-push hook and CI run exactly
  that file; its header lists the stages.
- When no R REPL is available, run snippets with `Rscript -e "..."`.

### Formatting

Format R code with [Air](https://posit-dev.github.io/air/):

```bash
air format .
```

Air is a fast, R-free formatter configured in `air.toml` (80 columns, 2-space
indent — the tidyverse style this package targets). The `air-format` pre-commit
hook runs it on every commit and bootstraps its own binary, so you do not need a
global install.

Air owns **layout**; `lintr` owns **logic and best-practice** lints — the two do
not overlap. Do not reformat code unrelated to your change: keep the diff to the
lines you actually touched.

### The linter set

`.lintr` is intentionally aligned with the linter set `goodpractice::gp()` runs
(`goodpractice:::linters_to_lint()`), so the lint gate surfaces the same
findings as the goodpractice report reviewers run. Regenerate the list after a
goodpractice upgrade, comparing against `names(goodpractice:::linters_to_lint())`.

**Keep `.lintr` free of `#` comments.** It is parsed with `read.dcf()`, which
only learned to skip comment lines in R 4.6. On R 4.5 and older, which CI runs,
a single comment makes `lint_package()` abort with `Invalid DCF format`, so the
rationale lives here instead. Keep it ASCII too: a non-ASCII byte in `.lintr`
comes back `bytes`-encoded on older R and makes any config error surface as a
confusing `sprintf()` failure instead of the real message.

Documented deviations from the goodpractice set:

- `object_name_linter` / `object_usage_linter`: not part of the goodpractice set
  and deliberately NOT added. The cucumber DSL (`when`/`then`/`context`) and the
  testthat helpers read as undefined globals to `object_usage_linter`.
- `expect_identical_linter`: off. `expect_equal()`'s numeric tolerance and
  string-encoding normalization are routinely relied on.
- `implicit_assignment_linter`: off. Tests use the standard
  `expect_warning(res <- f(), "msg")` idiom.
- `library_require_linter`: off. `tests/testthat.R`, the cucumber steps and
  vignette setup chunks legitimately call `library()`.
- `undesirable_operator_linter`: configured to keep flagging `<<-`/`->>` but
  allow `:::`, which tests use to reach internal functions.
- `case_folding_linter`: an addition. It bans `tolower()`, `toupper()` and
  `casefold()`, which follow `LC_CTYPE`: a Turkish or Azeri locale maps `I` to
  a dotless `ı`. Use `ascii_lower()` (`R/policy.R`), or `chartr()` over `a-z`
  where it is out of reach, as in the webfakes apps, which run in another
  process. Tests are not exempt: lintr 3.4 turns a directory key in
  `exclusions` into a whole-file exclusion for every linter.

`strings_as_factors_linter` is off, as in goodpractice, which dropped it in 1.2.0
(ropensci-review-tools/goodpractice#321). The R >= 4.0 floor already defaults
`stringsAsFactors = FALSE`.

### Code style

- `DESCRIPTION` sets the floor at R 4.0.0, so neither the base pipe `|>` nor
  the `\(x)` lambda (both R 4.1) is available; write `function(x)` and nest
  calls until the floor moves.
- `snake_case` for functions and arguments; explicit `pkg::fn()` prefixes.
- Layout is automated by Air (see [Formatting](#formatting)).

### Tests

- testthat edition 3. `R/foo.R` is tested by `tests/testthat/test-foo.R`.
- Keep all code inside `test_that()` blocks; shared setup lives in `helper-*.R` /
  `setup-*.R`.
- Prefer specific expectations over `expect_true()` / `expect_false()`.
- Use `expect_snapshot()` for printed output and `expect_snapshot(error = TRUE)`
  for errors.
- Behavior specs are Cucumber `.feature` files under `tests/testthat/`, with
  steps in `setup-steps.R` run via `test-cucumber.R`; `R CMD check` exercises
  them, so there is no separate BDD step.
- A skipped test, or one with no expectation, fails the gate
  (`ssrfr-v1.md` §7.2).
- New code requires tests.
- A proof under load, such as a timing fix, uses `scripts/load-test.sh`. It runs
  the test files that start processes N times in one container capped below
  the Docker VM's CPU count, under a load it generates inside that container,
  and counts the failures by class; its header lists the options. 1x and 2x
  are too light to reproduce the webfakes start timeout; 16x does
  (`design/evidence/2026-10-02-load-test-results.txt`). Never start
  load processes (`yes`, busy loops, parallel test runs) on the host by hand:
  other sessions share the machine. Commit the summary under `design/evidence/`
  with the command line at its top.

### Documentation

- Roxygen2 with markdown (`Roxygen: list(markdown = TRUE)`). `man/` and
  `NAMESPACE` are **generated — never edit them by hand**; edit the roxygen
  comments in `R/` and re-run `devtools::document()`.
- Every exported function needs a title, a `@param` per argument, `@return`, and
  runnable `@examples`. Internal helpers stay unexported and undocumented.
- Wrap roxygen comments at 80 columns. Add new help topics to `_pkgdown.yml`
  once it lists them; do not hand-edit the generated site in `site/`.

### New functions

Ship each new user-facing function with: runnable examples, tests, full argument
docs, `snake_case` arguments with sensible defaults, and argument validation.
Where a `...` separates required from optional arguments, guard it against
unexpected (e.g. misspelled) arguments.

### NEWS

Add a `NEWS.md` bullet for every user-facing change — one line, no wrapping,
with the issue number in parentheses. Internal-only refactors go under an
`## Internal` heading or are omitted. The verify gate's `news-version` stage
checks that the top `NEWS.md` heading is `(development version)` or the
`DESCRIPTION` `Version`, so bump both together.

### A red gate on an untouched tree

Toolchain drift makes the verify gate go red on a tree nobody changed, and it
looks exactly like a defect in the change being made. `scripts/check-toolchain.R`
runs ahead of the expensive step and names it in one line: roxygen2's installed
version against this package's `Config/roxygen2/version`, and any installed
package built under a newer R than the one running (SEOR-tcytizic).

If that check passes and the gate is still red on a tree you have not touched,
say so and keep the evidence rather than assuming your change caused it.
