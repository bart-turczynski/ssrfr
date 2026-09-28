#!/usr/bin/env Rscript
# verify v1
#
# The verify gate. The pre-push `verify` hook and the CI `verify` job both run
# this file, so the local gate and CI run one chain and cannot drift apart.
#
#   Rscript scripts/verify.R
#
# Stages, in order:
#
#   lint          lintr::lint_package() finds nothing.
#   news-version  the top NEWS.md heading is "(development version)" or the
#                 DESCRIPTION Version.
#   tests         testthat with NOT_CRAN=true. A skipped test fails the stage,
#                 and testthat reports a test with no expectation as skipped,
#                 so that fails it too (ssrfr-v1.md §7.2).
#   check         R CMD check --as-cran with NOT_CRAN=false, as CRAN runs it.
#                 An ERROR, a WARNING or a NOTE not in `allowed_notes` fails
#                 the stage; an allowed NOTE's first line is printed with its
#                 reason. CRAN incoming feasibility stays ON: it is what
#                 finds dead URL/BugReports links (seor ADR 0004), so do not
#                 switch it off to turn the gate green.
#
# Every stage runs even after an earlier one fails, and one VERDICT line names
# all failures, so one run says everything five separate runs would (seor ADR
# 0005). Exit 1 on any failure.
#
# A red gate on a tree nobody changed is usually the machine: run
# `Rscript scripts/check-toolchain.R` first (AGENTS_LANG.md).

package_root <- function() {
  args <- commandArgs(trailingOnly = FALSE)
  self <- sub("^--file=", "", grep("^--file=", args, value = TRUE))
  if (length(self) != 1L) {
    return(normalizePath(".", mustWork = TRUE))
  }
  normalizePath(file.path(dirname(self), ".."), mustWork = TRUE)
}

# Runs one stage. A stage returns TRUE to pass, FALSE (after printing why) to
# fail; an error inside it is a failure, not an abort of the whole gate.
run_stage <- function(name, fun) {
  cat("\n== verify: ", name, " ==\n", sep = "")
  ok <- tryCatch(isTRUE(fun()), error = function(e) {
    cat("error: ", conditionMessage(e), "\n", sep = "")
    FALSE
  })
  cat("== ", name, ": ", if (ok) "pass" else "FAIL", " ==\n", sep = "")
  ok
}

# Sets an environment variable for the duration of `code`, then restores it.
with_env <- function(name, value, code) {
  old <- Sys.getenv(name, unset = NA_character_)
  do.call(Sys.setenv, stats::setNames(list(value), name))
  on.exit(
    if (is.na(old)) {
      Sys.unsetenv(name)
    } else {
      do.call(Sys.setenv, stats::setNames(list(old), name))
    },
    add = TRUE
  )
  force(code)
}

stage_lint <- function(root) {
  lints <- lintr::lint_package(root)
  if (length(lints)) {
    print(lints)
    return(FALSE)
  }
  cat("no lints\n")
  TRUE
}

stage_news_version <- function(root) {
  version <- read.dcf(file.path(root, "DESCRIPTION"), fields = "Version")[[1L]]
  news <- readLines(
    file.path(root, "NEWS.md"),
    warn = FALSE,
    encoding = "UTF-8"
  )
  top <- grep("^# ", news, value = TRUE)[1L]
  heading <- sub("^#[[:space:]]+(ssrfr[[:space:]]+)?", "", top)
  cat("DESCRIPTION Version: '", version, "'\n", sep = "")
  cat("Top NEWS heading:    '", heading, "'\n", sep = "")
  if (heading %in% c("(development version)", version)) {
    return(TRUE)
  }
  cat(
    "The top NEWS.md heading is neither '(development version)' nor the ",
    "DESCRIPTION Version. Update NEWS.md.\n",
    sep = ""
  )
  FALSE
}

stage_tests <- function(root) {
  res <- with_env(
    "NOT_CRAN",
    "true",
    as.data.frame(testthat::test_local(
      root,
      reporter = "summary",
      stop_on_failure = FALSE
    ))
  )
  ok <- TRUE
  if (!nrow(res)) {
    cat("No tests ran. An empty suite is not a pass (ssrfr-v1.md §7.2).\n")
    ok <- FALSE
  }
  broken <- res[res$failed > 0L | res$error, c("file", "test")]
  if (nrow(broken)) {
    cat("Failed or erroring tests:\n")
    print(broken, row.names = FALSE)
    ok <- FALSE
  }
  skipped <- res[res$skipped, c("file", "test")]
  if (nrow(skipped)) {
    cat(
      "Skipped or expectation-free tests fail the gate (ssrfr-v1.md §7.2):\n"
    )
    print(skipped, row.names = FALSE)
    ok <- FALSE
  }
  cat(
    nrow(res),
    " tests: ",
    sum(res$passed),
    " expectations passed, ",
    sum(res$skipped),
    " skipped\n",
    sep = ""
  )
  ok
}

# The "HTML version of manual" lines that only say a tool the environment lacks
# kept R from checking something; wording from tools:::.check_packages and
# tools:::.find_tidy_cmd in R 4.4.3, 4.5.2 and 4.6.0. The command is
# $R_TIDYCMD, default "tidy". Up to 4.4 the Tidy line ends without a period and
# with no "Please obtain" paragraph, and its too-old wordings differ.
tidy_skipped <- paste0(
  "Skipping checking HTML validation: ",
  "(no command '[^']*' found",
  "|'[^']*' is too old: need version [0-9.]+, found [0-9.]+",
  "|'[^']*' doesn't look like recent enough HTML Tidy",
  "|'tidy' is Apple's too old build",
  "|'tidy' is not HTML Tidy)\\.?",
  "( Please obtain a recent version of HTML Tidy by downloading a binary ",
  "release or compiling the source code from ",
  "<https://www\\.html-tidy\\.org/>\\.)?"
)
v8_skipped <- "Skipping checking math rendering: package 'V8' unavailable"
html_skip_line <- paste0("(", tidy_skipped, "|", v8_skipped, ")")

# The R CMD check NOTEs the check stage lets through; any other NOTE fails it.
# `check` is the check's name as the NOTE's first line gives it, between
# "checking " and " ...". `body` is a regex the rest of the NOTE must match,
# whitespace collapsed to single spaces; NULL lets any text through. `reason`
# is printed next to each NOTE it lets through.
allowed_notes <- list(
  list(
    check = "CRAN incoming feasibility",
    body = NULL,
    reason = paste(
      "Maintainer, New submission and the .9000 version appear until a CRAN",
      "release, and URL checks vary with the network, so it is allowed whole:",
      "a flaky gate costs more than it saves. Read it before submitting."
    )
  ),
  list(
    check = "HTML version of manual",
    body = paste0("^", html_skip_line, "( ", html_skip_line, ")*$"),
    reason = paste(
      "HTML Tidy (5.0.0 or later) or V8 is missing, as in the CI image, so R",
      "skipped HTML validation or math rendering; no problem was reported."
    )
  ),
  list(
    check = "for future file timestamps",
    body = paste0(
      "^(unable to verify current time",
      "|Unable to verify current time\\. To disable remote verification, ",
      "set environment variable _R_CHECK_SYSTEM_CLOCK_ to a false value\\.)$"
    ),
    reason = "No time server was reachable, so R could not check the clock."
  )
)

# The `allowed_notes` entry that covers `note`, one element of rcmdcheck's
# `notes` (the "checking <name> ... NOTE" line, then the NOTE's text), or NULL.
# A NOTE the regexes cannot read, such as one with invalid UTF-8, is not
# covered.
note_entry <- function(note) {
  tryCatch(
    {
      lines <- strsplit(note, "\n", fixed = TRUE)[[1L]]
      check <- sub(
        "^checking (.*?) \\.\\.\\..*$",
        "\\1",
        lines[1L],
        perl = TRUE
      )
      body <- trimws(gsub(
        "[[:space:]]+",
        " ",
        paste(lines[-1L], collapse = " ")
      ))
      for (entry in allowed_notes) {
        body_ok <- is.null(entry$body) ||
          isTRUE(grepl(entry$body, body, perl = TRUE))
        if (identical(check, entry$check) && body_ok) {
          return(entry)
        }
      }
      NULL
    },
    error = function(e) NULL,
    warning = function(w) NULL
  )
}

note_allowed <- function(note) !is.null(note_entry(note))

stage_check <- function(root) {
  cat("R CMD check --as-cran, incoming=on\n")
  res <- rcmdcheck::rcmdcheck(
    root,
    args = "--as-cran",
    error_on = "never",
    env = c(callr::rcmd_safe_env(), NOT_CRAN = "false")
  )
  if (res$status != 0L) {
    cat(
      "R CMD check halted before finishing (exit status ",
      res$status,
      ")\n",
      sep = ""
    )
    return(FALSE)
  }
  entries <- lapply(res$notes, note_entry)
  allowed <- !vapply(entries, is.null, logical(1L))
  for (i in which(allowed)) {
    cat(
      "Allowed NOTE: ",
      strsplit(res$notes[[i]], "\n", fixed = TRUE)[[1L]][1L],
      " (reason: ",
      entries[[i]]$reason,
      ")\n",
      sep = ""
    )
  }
  if (!all(allowed)) {
    cat("NOTEs not in allowed_notes (scripts/verify.R):\n\n")
    cat(res$notes[!allowed], sep = "\n\n")
    cat("\n")
  }
  !length(res$errors) && !length(res$warnings) && all(allowed)
}

main <- function() {
  root <- package_root()
  stages <- list(
    "lint" = stage_lint,
    "news-version" = stage_news_version,
    "tests" = stage_tests,
    "check" = stage_check
  )
  passed <- vapply(
    names(stages),
    function(name) run_stage(name, function() stages[[name]](root)),
    logical(1L)
  )
  if (all(passed)) {
    cat(
      "\nVERDICT: PASS -- ",
      paste(names(stages), collapse = ", "),
      "\n",
      sep = ""
    )
    return(0L)
  }
  cat(
    "\nVERDICT: FAIL -- ",
    paste(names(stages)[!passed], collapse = ", "),
    "\n",
    sep = ""
  )
  1L
}

quit(status = main())
