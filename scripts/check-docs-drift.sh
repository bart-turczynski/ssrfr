#!/usr/bin/env bash
# scripts/check-docs-drift.sh -- the docs-drift pre-push hook: man/, NAMESPACE
# and DESCRIPTION in the commit being pushed against a fresh roxygen2 run
# (SEOR-nwfmerhu). Ported from run_docs_drift() in pslr's tools/verify.sh.
#
# It checks the pushed commit, ${PRE_COMMIT_TO_REF:-HEAD} (pre-commit sets
# PRE_COMMIT_TO_REF for a push), never the working tree: roxygenise() writes
# into the directory it is given, so the R check runs against a throwaway
# `git archive` export of that commit. It is the checkout's copy of
# scripts/check-docs-drift.R that runs, not the exported commit's, so a branch
# that predates the script is still checked rather than failing with "cannot
# open file".
#
# The export lives in a subshell that removes it on every exit, an interrupt
# included: INT, TERM and HUP become an ordinary exit, which runs the EXIT
# trap. Exit 3 means the export could not be made; 128 and above, an
# interrupt. Any other failure of the R check is reported without claiming
# drift for certain: roxygen2 skew, a missing pin or a package that fails to
# load exit 1 just as drift does, and the output above says which.
#
# bash, not sh, for pipefail: without it the pipeline's status is tar's, and a
# failed git archive (a bad ref) would go unnoticed.
#
# Usage (from the package root): bash scripts/check-docs-drift.sh

set -uo pipefail

ref="${PRE_COMMIT_TO_REF:-HEAD}"
echo "== docs-drift: generated docs in sync at ${ref}"

status=0
(
  if ! docsdir="$(mktemp -d "${TMPDIR:-/tmp}/ssrfr-docs-drift.XXXXXX")"; then
    echo "docs-drift: could not create a temporary directory for the docs export" >&2
    exit 3
  fi
  trap 'rm -rf "$docsdir"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  if ! git archive "$ref" | tar -x -C "$docsdir"; then
    echo "docs-drift: could not export ${ref} with git archive" >&2
    exit 3
  fi
  Rscript scripts/check-docs-drift.R "$docsdir"
) || status=$?

if [ "$status" -eq 3 ] || [ "$status" -ge 128 ]; then
  exit "$status"
elif [ "$status" -ne 0 ]; then
  echo "docs-drift: FAIL -- the generated docs at ${ref} are out of date (or the check could not run; see the output above). If they are stale, run devtools::document() and commit the result." >&2
  exit 1
fi
echo "-- docs-drift: PASS -- man/, NAMESPACE and DESCRIPTION match the roxygen comments in R/"
