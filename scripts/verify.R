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

# The one "HTML version of manual" line allowed: R skipped math rendering
# because the V8 package is not installed, which is neither a DESCRIPTION
# dependency nor dev tooling here. R prints it only once an Rd file has \eqn or
# \deqn, which none has yet. Wording from tools:::.check_packages in
# R 4.4.3, 4.5.2 and 4.6.0. The HTML Tidy skip ("Skipping checking HTML
# validation: ...") is NOT allowed, since CRAN validates what the check would
# have skipped. The CI image installs tidy (Ubuntu noble, 5.6.0); a machine
# without HTML Tidy 5.0.0 or later fails the gate. macOS's /usr/bin/tidy is too
# old: put Homebrew's `tidy-html5` ahead of it on PATH, or point $R_TIDYCMD at
# one.
v8_skipped <- "Skipping checking math rendering: package 'V8' unavailable"

# The R CMD check NOTEs the check stage lets through; any other NOTE fails it.
# `check` is the check's name as the NOTE's first line gives it, between
# "checking " and " ...". `body` is a regex the rest of the NOTE must match,
# whitespace collapsed to single spaces; NULL lets any text through. An entry
# may give `paragraphs` instead: regexes, one of which each paragraph of the
# NOTE (split at blank lines, line breaks kept, trailing spaces dropped) must
# match whole; a paragraph none matches fails the stage and is printed on its
# own. `reason` is printed next to each NOTE it lets through.
allowed_notes <- list(
  list(
    # Known paragraphs only; anything else R says here (a misspelling, a
    # Title-case remark, a BugReports remark, an HTTP status for a URL) fails
    # the gate. Wording from tools:::format.check_package_CRAN_incoming and
    # tools:::format.check_url_db in R 4.6.0. A URL paragraph passes only when
    # every URL in it is one of two kinds, with no other line in the
    # paragraph:
    # - DESCRIPTION's BugReports, exactly .../ssrfr/-/issues, answering 404.
    #   That is the fleet's BugReports split (SEOR-ocbtrrnl;
    #   scripts/check-bugreports.py holds it): R's incoming check wants a path
    #   ending in /issues, and GitLab serves that as 404 to a signed-out
    #   client since issues moved to /-/work_items. cran-comments.md explains
    #   it to CRAN.
    # - a URL that failed with Status "Error" and libcurl error 6 (could not
    #   resolve host) or 28 (timed out), in the serial check's "libcurl error
    #   code N:" form. Status 0 fails: R prints it with no message, so a
    #   network blip and a broken server look the same. A dead domain also
    #   fails to resolve and would pass, as it does offline; read the NOTE
    #   before a submission.
    check = "CRAN incoming feasibility",
    paragraphs = c(
      "Maintainer: .+",
      "New submission",
      "Version contains large components \\([0-9.]+\\.9[0-9]{3}\\)",
      paste0(
        "Found the following \\(possibly\\) invalid URLs?:",
        "(?:",
        "\n  URL: https://gitlab\\.com/bart-turczynski/ssrfr/-/issues",
        "\n    From: DESCRIPTION",
        "\n    Status: 404",
        "\n    Message: Not Found",
        "|",
        "\n  URL: \\S+(?: \\(moved to \\S+\\))?",
        "\n    From: \\S+(?:\n {10}\\S+)*",
        "\n    Status: Error",
        "\n    Message: libcurl error code (?:6|28):",
        "\n {6}\t?\\S.*",
        ")+"
      )
    ),
    reason = paste(
      "Only R's pre-first-release lines (Maintainer, New submission, a .9xxx",
      "version), the 404 on BugReports' /-/issues URL and URLs that timed",
      "out or did not resolve are allowed. BugReports keeps /-/issues because",
      "R's incoming check flags any other path, and GitLab serves it as 404",
      "to a signed-out client (SEOR-ocbtrrnl). Any other HTTP status, status",
      "0 or other libcurl error on a URL fails the gate."
    )
  ),
  list(
    check = "HTML version of manual",
    body = paste0("^", v8_skipped, "$"),
    reason = paste(
      "V8 is not installed, so R skipped math rendering; HTML validation ran",
      "and no problem was reported."
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

# Splits `note`, one element of rcmdcheck's `notes` (the "checking <name> ...
# NOTE" line, then the NOTE's text), into its check name and its text lines.
note_parts <- function(note) {
  lines <- strsplit(note, "\n", fixed = TRUE)[[1L]]
  list(
    check = sub("^checking (.*?) \\.\\.\\..*$", "\\1", lines[1L], perl = TRUE),
    text = lines[-1L]
  )
}

# The paragraphs of `text` that no regex in `patterns` matches whole. A
# paragraph is a run of non-blank lines, rejoined with "\n", each line's
# trailing whitespace dropped; `.` in a pattern does not cross a line break.
unmatched_paragraphs <- function(text, patterns) {
  text <- sub("[[:space:]]+$", "", text)
  keep <- nzchar(text)
  paras <- unname(vapply(
    split(text[keep], cumsum(!keep)[keep]),
    paste,
    "",
    collapse = "\n"
  ))
  matched <- vapply(
    paras,
    function(para) {
      any(vapply(
        patterns,
        function(re) grepl(paste0("\\A(?:", re, ")\\z"), para, perl = TRUE),
        logical(1L)
      ))
    },
    logical(1L)
  )
  paras[!matched]
}

# The `allowed_notes` entry that covers `note`, or NULL. A NOTE the regexes
# cannot read, such as one with invalid UTF-8, is not covered.
note_entry <- function(note) {
  tryCatch(
    {
      parts <- note_parts(note)
      body <- trimws(gsub(
        "[[:space:]]+",
        " ",
        paste(parts$text, collapse = " ")
      ))
      for (entry in allowed_notes) {
        body_ok <- if (is.null(entry$paragraphs)) {
          is.null(entry$body) || isTRUE(grepl(entry$body, body, perl = TRUE))
        } else {
          !length(unmatched_paragraphs(parts$text, entry$paragraphs))
        }
        if (identical(parts$check, entry$check) && body_ok) {
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

# What to print for a NOTE `allowed_notes` does not cover: when an entry for
# its check lists `paragraphs`, the "checking" line and only the paragraphs
# none of them matches; otherwise, or when that fails, the whole NOTE.
note_unexplained <- function(note) {
  tryCatch(
    {
      parts <- note_parts(note)
      for (entry in allowed_notes) {
        if (identical(parts$check, entry$check) && length(entry$paragraphs)) {
          return(paste(
            c(
              strsplit(note, "\n", fixed = TRUE)[[1L]][1L],
              "(only the paragraphs no allowed_notes entry allows)",
              unmatched_paragraphs(parts$text, entry$paragraphs)
            ),
            collapse = "\n"
          ))
        }
      }
      note
    },
    error = function(e) note,
    warning = function(w) note
  )
}

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
    cat(
      vapply(res$notes[!allowed], note_unexplained, "", USE.NAMES = FALSE),
      sep = "\n\n"
    )
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
