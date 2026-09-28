#!/usr/bin/env Rscript
# check-spelling v1
#
# Spell-check the package: DESCRIPTION, man/, vignettes, README and NEWS.
#
#   Rscript scripts/check-spelling.R
#
# R CMD check skips its DESCRIPTION spelling check on a machine with no English
# aspell or hunspell dictionary, so a typo first shows up in win-builder's
# incoming NOTE (SEOR-mtbzfroz). `spelling` bundles its own hunspell
# dictionaries, so this check runs the same everywhere. The language is
# DESCRIPTION's `Language: en-US`; genuine terms go in inst/WORDLIST, a typo is
# fixed at its source (the roxygen comment in R/ for man/).
#
# Exit 1, listing each word and where it was found, on any flagged word.

bad <- spelling::spell_check_package()
if (nrow(bad)) {
  print(bad)
  quit(status = 1L)
}
cat("no spelling errors\n")
