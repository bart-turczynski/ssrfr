#!/bin/sh
# scripts/gates.sh -- the cheap gates scripts/verify.R does not run, folded
# into one CI job (`gates` in .gitlab-ci.yml), in seor's scripts/gates.sh
# shape: README drift and spelling. lint and news-version are stages of
# scripts/verify.R; citation-version keeps its own python image.
#
# Every gate runs whatever an earlier one did, then ONE verdict line names
# every failure, and only then does the script exit nonzero (seor ADR 0005).
# It installs nothing: the `gates` job does that first. Run it from the
# package root.

failed=""

run_gate() {
  name="$1"
  shift
  echo "== gate: $name"
  if "$@"; then
    echo "-- $name: PASS"
  else
    echo "-- $name: FAIL"
    failed="$failed $name"
  fi
}

# README.md is knit from README.Rmd, so a hand-edit to the markdown is lost on
# the next render. Rendered with rmarkdown directly, as pagerankr does: the Rmd
# evaluates no package code, so nothing needs installing first. pandoc's
# markdown writer reflows text between versions, so the job pins the pandoc
# that knit README.md. Blank-line-only differences don't count, and the test
# is on the diff's output, since git 2.43 still exits 1 on a blank-only diff
# under --ignore-blank-lines (seor SEOR-oaqnafzs, SEOR-kaqtnovh).
gate_readme() {
  Rscript -e 'rmarkdown::render("README.Rmd", output_options = list(html_preview = FALSE), quiet = TRUE)' || return 1
  readme_diff=$(git diff --ignore-blank-lines -- README.md)
  if [ -n "$readme_diff" ]; then
    printf '%s\n' "$readme_diff"
    echo "README.md is out of sync with README.Rmd. Knit README.Rmd and commit the result."
    return 1
  fi
}

# The same script as the pre-push `spelling` hook (SEOR-mtbzfroz).
gate_spelling() {
  Rscript scripts/check-spelling.R
}

run_gate readme gate_readme
run_gate spelling gate_spelling

if [ -n "$failed" ]; then
  echo "VERDICT: FAIL --$failed"
  exit 1
fi
echo "VERDICT: PASS -- readme, spelling"
