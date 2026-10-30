#!/usr/bin/env Rscript
# check-locale-legs v1
#
# The positive locale assertion: proves that tests/testthat/test-locale.R ran
# its hostile-locale legs rather than skipping them quietly.
#
#   Rscript scripts/check-locale-legs.R
#
# test-locale.R (REQ-094) runs the package's decisions in a fresh R process
# for each Turkish, Azeri and Lithuanian locale the machine accepts, through
# callr, and runs none when the locales or callr are missing; that would
# still pass. So this asserts what the test needs: callr in the run library
# the check used, every hostile locale below usable by R, and tr_TR.UTF-8
# folding "I" to a dotless i (U+0131). It also asserts that the check it
# follows ran the tests at all.
#
# A `locale_assertions` entry of .fleet-ci.yml: the fleet-ci local gate runs
# it after each locale leg's check (full tier), and CI's `t2-locale` after
# each of its legs, with FLEET_RCHECK_DIR naming the leg's .Rcheck directory.
# The locales come from .fleet-ci.yml's `locales`; the list below must name
# no locale missing there. The test's Latin-5 legs (tr_TR.ISO8859-9,
# tr_TR.iso88599) are not here: fleet-ci cannot build them yet
# (.fleet-ci.yml's `locales` says why). The run library is R_LIBS in the
# local gate and FLEET_RUN_LIB in CI. Exit 1, naming every failure, on any.

hostile_locales <- c(
  "tr_TR.UTF-8",
  "az_AZ.UTF-8",
  "lt_LT.UTF-8"
)

problems <- character()

# R CMD check writes testthat.Rout, or testthat.Rout.fail when a test failed
# (the check then fails on its own).
rcheck <- Sys.getenv("FLEET_RCHECK_DIR")
rout <- file.path(rcheck, "tests", c("testthat.Rout", "testthat.Rout.fail"))
if (!nzchar(rcheck) || !any(file.exists(rout))) {
  problems <- c(
    problems,
    paste0(
      "no test output at '",
      rout[[1L]],
      "' (or .fail): the check this follows ran no tests ",
      "(FLEET_RCHECK_DIR='",
      rcheck,
      "')"
    )
  )
}

libs <- c(
  strsplit(Sys.getenv("R_LIBS"), .Platform$path.sep, fixed = TRUE)[[1L]],
  Sys.getenv("FLEET_RUN_LIB")
)
libs <- unique(libs[nzchar(libs) & dir.exists(libs)])
if (!nzchar(system.file(package = "callr", lib.loc = libs))) {
  problems <- c(
    problems,
    paste0(
      "callr is not in the run library (",
      if (length(libs)) paste(libs, collapse = ", ") else "none found",
      "), so test-locale.R runs no hostile leg"
    )
  )
}

old <- Sys.getlocale("LC_CTYPE")
for (locale in hostile_locales) {
  if (!nzchar(suppressWarnings(Sys.setlocale("LC_CTYPE", locale)))) {
    problems <- c(
      problems,
      paste0("R cannot use locale ", locale, ", so test-locale.R skips it")
    )
  }
}
if (nzchar(suppressWarnings(Sys.setlocale("LC_CTYPE", "tr_TR.UTF-8")))) {
  if (!identical(tolower("I"), intToUtf8(0x131L))) {
    problems <- c(
      problems,
      "tr_TR.UTF-8 does not fold \"I\" to a dotless i (U+0131)"
    )
  }
}
invisible(Sys.setlocale("LC_CTYPE", old))

if (length(problems)) {
  cat("check-locale-legs: FAIL\n", paste0("  - ", problems, "\n"), sep = "")
  quit(status = 1L)
}
cat(
  "check-locale-legs: callr present; usable: ",
  paste(hostile_locales, collapse = ", "),
  "; tr_TR.UTF-8 folds I to a dotless i\n",
  sep = ""
)
