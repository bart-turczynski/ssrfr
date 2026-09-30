# Writes the published conformance results of ssrfr-v1.md §7: the corpus run
# and the dependency versions of §7 component 4 (§4.3). Run it from the
# repository root:
#   Rscript scripts/conformance-results.R [output]
# The default output is design/evidence/<YYYY-MM-DD>-conformance-results.txt,
# dated today; commit it as r-binding.md §9 (Conformance results) says.
#
# The corpus is tests/testthat/test-corpus.R with its helpers, run exactly as
# testthat::test_local(filter = "corpus") runs it, so every verdict comes from
# the test file and none is re-derived here. NOT_CRAN is set because this is
# the run that declares conformance, where nothing may skip (§7.2).
#
# The file is written whatever the outcome, and the script exits 1 when any
# test fails, errors, skips or makes no assertion (§7.2), when a corpus file
# does not match its manifest, or when a component 4 field cannot be read.

args <- commandArgs(trailingOnly = TRUE)
out_path <- if (length(args) > 0L) {
  args[[1L]]
} else {
  file.path(
    "design",
    "evidence",
    paste0(format(Sys.Date()), "-conformance-results.txt")
  )
}

if (
  !file.exists("DESCRIPTION") ||
    !identical(unname(read.dcf("DESCRIPTION", "Package")[1L, 1L]), "ssrfr")
) {
  stop("run this from the ssrfr repository root")
}

corpus_dir <- file.path("tests", "testthat", "fixtures")
corpus_files <- c(
  "verdict-vectors.tsv",
  "parse-vectors.tsv",
  "requirements.tsv"
)

read_tsv <- function(file) {
  utils::read.delim(
    file.path(corpus_dir, file),
    quote = "",
    comment.char = "",
    na.strings = character(),
    colClasses = "character",
    encoding = "UTF-8",
    check.names = FALSE
  )
}

# --- Environment and component 4 ---------------------------------------------

git_out <- function(git_args) {
  out <- tryCatch(
    suppressWarnings(system2("git", git_args, stdout = TRUE, stderr = FALSE)),
    error = function(e) character()
  )
  if (!is.null(attr(out, "status"))) character() else out
}

sha <- git_out(c("rev-parse", "HEAD"))
decisive <- c("R", "tests", "inst", "DESCRIPTION", "NAMESPACE")
changed <- git_out(c("status", "--porcelain", "--", decisive))
commit <- if (length(sha) == 0L) {
  "unavailable (not a git checkout)"
} else if (length(changed) == 0L) {
  sha
} else {
  paste(sha, "with uncommitted changes to", toString(substring(changed, 4L)))
}

# A field is read when its reader returns one non-empty string.
read_field <- function(reader) {
  tryCatch(
    {
      value <- reader()
      stopifnot(
        is.character(value),
        length(value) == 1L,
        !is.na(value),
        nzchar(value)
      )
      c(value = value, error = "")
    },
    error = function(e) c(value = "", error = conditionMessage(e))
  )
}

pkg_version <- function(pkg) {
  function() format(utils::packageVersion(pkg))
}

component4 <- list(
  "raddr" = pkg_version("raddr"),
  "raddr addr_registry_version()" = function() {
    raddr::addr_registry_version()
  },
  "raddr addr_address_space_version()" = function() {
    raddr::addr_address_space_version()
  },
  "raddr addr_registry_snapshot()" = function() {
    raddr::addr_registry_snapshot()
  },
  "rurl" = pkg_version("rurl"),
  "curl (R package)" = pkg_version("curl"),
  "libcurl" = function() curl::curl_version()$version,
  # As curl reports it: the active backend outside parentheses, any other
  # backend the build carries inside them.
  "libcurl TLS backend" = function() curl::curl_version()$ssl_version
)
fields <- lapply(component4, read_field)
unreadable <- names(fields)[vapply(
  fields,
  function(f) nzchar(f[["error"]]),
  logical(1)
)]

# --- Manifest (§7.2) ---------------------------------------------------------

manifest <- read_tsv("corpus-manifest.tsv")
manifest_ok <- vapply(
  corpus_files,
  function(f) {
    i <- match(f, manifest$file)
    !is.na(i) &&
      identical(
        unname(tools::md5sum(file.path(corpus_dir, f))),
        manifest$md5[i]
      ) &&
      identical(nrow(read_tsv(f)), as.integer(manifest$rows[i]))
  },
  logical(1)
)

# --- The corpus run ----------------------------------------------------------

Sys.setenv(NOT_CRAN = "true")
started <- proc.time()[["elapsed"]]
run <- testthat::test_local(
  filter = "^corpus$",
  reporter = testthat::ListReporter$new(),
  stop_on_failure = FALSE,
  stop_on_warning = FALSE
)
elapsed <- proc.time()[["elapsed"]] - started

kinds <- c("success", "failure", "error", "skip", "warning")
# Code that fails outside test_that(), such as the manifest guard in
# test-corpus.R, is reported under no test name.
test_name <- function(t) {
  if (is.null(t$test) || is.na(t$test)) "(outside test_that())" else t$test
}
tests <- do.call(
  rbind,
  lapply(run, function(t) {
    kind <- vapply(
      t$results,
      function(r) {
        hit <- kinds[vapply(
          kinds,
          function(k) inherits(r, paste0("expectation_", k)),
          logical(1)
        )]
        if (length(hit) > 0L) hit[[1L]] else "other"
      },
      character(1)
    )
    counts <- vapply(kinds, function(k) sum(kind == k), integer(1))
    outcome <- if (counts[["failure"]] + counts[["error"]] > 0L) {
      "FAIL"
    } else if (counts[["skip"]] > 0L) {
      "SKIP"
    } else if (counts[["success"]] == 0L) {
      "EMPTY"
    } else {
      "PASS"
    }
    data.frame(
      test = test_name(t),
      outcome = outcome,
      t(counts),
      stringsAsFactors = FALSE
    )
  })
)

# The first line of every failing or erroring expectation's message; the
# corpus tests label each one with the row id it evaluated.
failures <- unlist(lapply(run, function(t) {
  bad <- Filter(
    function(r) {
      inherits(r, "expectation_failure") || inherits(r, "expectation_error")
    },
    t$results
  )
  vapply(
    bad,
    function(r) {
      msg <- strsplit(conditionMessage(r), "\n", fixed = TRUE)[[1L]]
      paste0(test_name(t), ": ", c(msg, "")[[1L]])
    },
    character(1)
  )
}))
if (is.null(failures)) {
  failures <- character()
}
failed_ids <- unique(unlist(regmatches(
  failures,
  gregexpr("\\b[VP][0-9]{4}\\b", failures)
)))
# Every row was evaluated only when no test errored or skipped part of it.
rows_decided <- !is.null(tests) &&
  sum(tests$error) + sum(tests$skip) == 0L

passed <- !is.null(tests) &&
  all(tests$outcome == "PASS") &&
  all(manifest_ok) &&
  length(unreadable) == 0L

# --- The results file --------------------------------------------------------

status_class <- function(status) {
  sub(":.*$", "", status)
}

vector_lines <- function(file) {
  rows <- read_tsv(file)
  class <- status_class(rows$status)
  lines <- sprintf(
    "  rows %d: active %d, pending %d, superseded %d",
    nrow(rows),
    sum(class == "active"),
    sum(class == "pending"),
    sum(class == "superseded")
  )
  # An active row passes when it meets its expectation; a pending row holds
  # when it still does not (test-corpus.R).
  held <- c(active = "pass", pending = "still pending")
  for (st in names(held)) {
    ids <- rows$id[class == st]
    bad <- intersect(ids, failed_ids)
    ok <- if (rows_decided) {
      as.character(length(ids) - length(bad))
    } else {
      "not established (a test errored or skipped)"
    }
    lines <- c(
      lines,
      sprintf(
        "  %s rows: %s %s, fail %d%s",
        st,
        held[[st]],
        ok,
        length(bad),
        if (length(bad) > 0L) paste0(" (", toString(bad), ")") else ""
      )
    )
  }
  lines
}

requirement_lines <- function() {
  rows <- read_tsv("requirements.tsv")
  by_class <- table(rows$class)
  c(
    sprintf("  rows %d, no status column; by class:", nrow(rows)),
    sprintf("    %s %d", names(by_class), as.integer(by_class)),
    "  decided by the file-level tests below"
  )
}

field_lines <- vapply(
  names(fields),
  function(n) {
    f <- fields[[n]]
    value <- if (nzchar(f[["error"]])) {
      paste("UNREADABLE:", f[["error"]])
    } else {
      f[["value"]]
    }
    sprintf("  %-36s %s", paste0(n, ":"), value)
  },
  character(1)
)

test_lines <- if (is.null(tests)) {
  "  none ran"
} else {
  sprintf(
    "  %-5s %3d pass %2d fail %2d error %2d skip  %s",
    tests$outcome,
    tests$success,
    tests$failure,
    tests$error,
    tests$skip,
    tests$test
  )
}

backend <- Sys.getenv("CURL_SSL_BACKEND", unset = "")

results <- c(
  "# ssrfr conformance results (ssrfr-v1.md §7)",
  "# Generated by Rscript scripts/conformance-results.R; never hand-edited.",
  "",
  paste("result:", if (passed) "PASS" else "FAIL"),
  "",
  "## Run",
  paste("  ssrfr:", read.dcf("DESCRIPTION", "Version")[1L, 1L]),
  paste("  commit:", commit),
  paste("  date:", format(Sys.Date())),
  paste("  R:", R.version.string),
  paste("  platform:", R.version$platform),
  paste("  OS:", utils::sessionInfo()$running),
  paste("  CURL_SSL_BACKEND:", if (nzchar(backend)) backend else "unset"),
  "",
  "## Dependency pinning (§7 component 4, §4.3)",
  field_lines,
  "",
  "## Manifest (§7.2)",
  sprintf(
    "  %-20s %s",
    corpus_files,
    ifelse(manifest_ok, "matches", "DOES NOT MATCH")
  ),
  "",
  "## verdict-vectors.tsv (§7 component 1)",
  vector_lines("verdict-vectors.tsv"),
  "",
  "## parse-vectors.tsv (§7 component 2)",
  vector_lines("parse-vectors.tsv"),
  "",
  "## requirements.tsv (§7 component 3)",
  requirement_lines(),
  "",
  "## Tests in test-corpus.R (skipped or empty counts as not passed, §7.2)",
  test_lines
)
if (length(failures) > 0L) {
  results <- c(results, "", "## Failures", paste(" ", failures))
}

dir.create(dirname(out_path), recursive = TRUE, showWarnings = FALSE)
con <- file(out_path, "w", encoding = "UTF-8")
writeLines(results, con)
close(con)

writeLines(results)
message(sprintf("wrote %s; corpus run took %.0f s", out_path, elapsed))
if (!passed) {
  quit(status = 1L)
}
