# The in-container half of scripts/load-test.sh. Never run it on the host:
# load-test.sh starts it inside the capped container, under the load it
# generates there.
#
#   Rscript load-test-run.R run <out-prefix> <filter-regex>
#   Rscript load-test-run.R summarize <out-dir>
#   Rscript load-test-run.R selftest
#
# `run` runs the test files whose names match the filter once, against the
# installed package (as R CMD check does), from the working directory's
# tests/testthat, and writes <out-prefix>.tsv: one row per failing
# expectation, classified, plus a `run` row with the totals. The timing
# events the injected helper (load-test-helper.R) records go to
# <out-prefix>.events, named by SSRFR_LOAD_TEST_EVENTS.
#
# `summarize` reads every run in <out-dir> and prints, per cell (load level
# and start timeout), the runs that failed in each class out of the runs.
#
# `selftest` feeds the classifier one known message per class and stops
# unless each lands in its class.

# The failure classes, in priority order:
# - start-timeout: a webfakes app process did not start in time, through
#   callr's session start wait or webfakes' own (helper-transport.R,
#   app_start_timeout(); SSRF-xounanjz).
# - raw-server: a test whose local_server_process() readiness wait ran out
#   (the injected helper records it, and the failure names the wait), or a
#   failure that names a refused connection (SSRF-ptkasofy).
# - other: everything else.
start_timeout_pattern <- paste(
  "Could not start R session",
  "webfakes app subprocess did not start",
  sep = "|"
)
connect_pattern <- paste(
  "readiness wait ran out",
  "connect-failed",
  "Couldn't connect",
  "Could not connect",
  "Connection refused",
  "Failed to connect",
  sep = "|"
)

classify <- function(message, readiness_timed_out) {
  if (grepl(start_timeout_pattern, message)) {
    "start-timeout"
  } else if (readiness_timed_out || grepl(connect_pattern, message)) {
    "raw-server"
  } else {
    "other"
  }
}

classes <- c("start-timeout", "raw-server", "other")

one_line <- function(x) {
  x <- gsub("[\t\r\n]+", " ", x)
  if (nchar(x) > 300L) paste0(substr(x, 1L, 300L), "...") else x
}

read_events <- function(path) {
  cols <- c("kind", "seconds", "status", "test")
  if (!file.exists(path) || !file.size(path)) {
    return(stats::setNames(
      data.frame(character(), numeric(), character(), character()),
      cols
    ))
  }
  ev <- utils::read.delim(
    path,
    header = FALSE,
    col.names = cols,
    quote = "",
    stringsAsFactors = FALSE
  )
  ev$seconds <- as.numeric(ev$seconds)
  ev
}

run_once <- function(prefix, filter) {
  events <- paste0(prefix, ".events")
  Sys.setenv(SSRFR_LOAD_TEST_EVENTS = events)
  file.create(events)
  t0 <- Sys.time()
  res <- tryCatch(
    testthat::test_dir(
      "tests/testthat",
      filter = filter,
      package = "ssrfr",
      load_package = "installed",
      reporter = "summary",
      stop_on_failure = FALSE,
      stop_on_warning = FALSE
    ),
    error = identity
  )
  elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  ev <- read_events(events)
  not_ready <- ev$test[ev$kind == "raw-ready" & ev$status == "timeout"]
  rows <- list()
  n_tests <- 0L
  n_skipped <- 0L
  if (inherits(res, "error")) {
    rows[[1L]] <- c(
      "failure",
      "(runner)",
      "(test_dir)",
      "other",
      one_line(conditionMessage(res))
    )
  } else {
    for (t in res) {
      n_tests <- n_tests + 1L
      for (e in t$results) {
        if (inherits(e, "expectation_skip")) {
          n_skipped <- n_skipped + 1L
        }
        if (inherits(e, c("expectation_failure", "expectation_error"))) {
          msg <- conditionMessage(e)
          rows[[length(rows) + 1L]] <- c(
            "failure",
            t$file,
            one_line(t$test),
            classify(msg, t$test %in% not_ready),
            one_line(msg)
          )
        }
      }
    }
  }
  summary_row <- c(
    "run",
    sprintf("%.1f", elapsed),
    paste0("tests=", n_tests, " skipped=", n_skipped),
    if (inherits(res, "error")) "crashed" else "completed",
    paste0("failures=", length(rows))
  )
  out <- do.call(rbind, c(list(summary_row), rows))
  utils::write.table(
    out,
    paste0(prefix, ".tsv"),
    sep = "\t",
    quote = FALSE,
    row.names = FALSE,
    col.names = FALSE
  )
  cat(sprintf(
    "run: %.1f s, %d tests, %d failing expectations\n",
    elapsed,
    n_tests,
    length(rows)
  ))
  for (r in rows[seq_len(min(length(rows), 20L))]) {
    cat(
      "  [",
      r[[4L]],
      "] ",
      r[[2L]],
      ": ",
      r[[3L]],
      ": ",
      r[[5L]],
      "\n",
      sep = ""
    )
  }
}

# Run files are named <cell>.run<NN>.tsv, where <cell> is
# load<L>x-timeout<T>.
summarize <- function(dir) {
  files <- sort(list.files(
    dir,
    pattern = "\\.run[0-9]+\\.tsv$",
    full.names = TRUE
  ))
  if (!length(files)) {
    cat("no runs in", dir, "\n")
    return(invisible())
  }
  cell <- sub("\\.run[0-9]+\\.tsv$", "", basename(files))
  cat(sprintf(
    "%-28s %5s %14s %14s %14s %8s  %s\n",
    "cell",
    "runs",
    "start-timeout",
    "raw-server",
    "other",
    "secs/run",
    "app starts (n, median s, max s, >3 s) | raw ready (n, max s, timeouts)"
  ))
  for (c in unique(cell)) {
    runs <- files[cell == c]
    hit <- stats::setNames(integer(3L), classes)
    fails <- stats::setNames(integer(3L), classes)
    secs <- numeric()
    ev <- NULL
    for (f in runs) {
      lines <- strsplit(readLines(f, warn = FALSE), "\t", fixed = TRUE)
      kinds <- vapply(lines, `[[`, "", 1L)
      run <- lines[[which(kinds == "run")[[1L]]]]
      secs <- c(secs, as.numeric(run[[2L]]))
      got <- vapply(lines[kinds == "failure"], `[[`, "", 4L)
      for (k in classes) {
        fails[[k]] <- fails[[k]] + sum(got == k)
        hit[[k]] <- hit[[k]] + any(got == k)
      }
      ev <- rbind(ev, read_events(sub("\\.tsv$", ".events", f)))
    }
    app <- ev$seconds[ev$kind == "app-start"]
    raw <- ev$seconds[ev$kind == "raw-ready"]
    cat(sprintf(
      "%-28s %5d %14s %14s %14s %8.0f  %s | %s\n",
      c,
      length(runs),
      sprintf("%d/%d (%d)", hit[[1L]], length(runs), fails[[1L]]),
      sprintf("%d/%d (%d)", hit[[2L]], length(runs), fails[[2L]]),
      sprintf("%d/%d (%d)", hit[[3L]], length(runs), fails[[3L]]),
      stats::median(secs),
      if (length(app)) {
        sprintf(
          "%d, %.2f, %.2f, %d",
          length(app),
          stats::median(app),
          max(app),
          sum(app > 3)
        )
      } else {
        "0"
      },
      if (length(raw)) {
        sprintf(
          "%d, %.2f, %d",
          length(raw),
          max(raw),
          sum(ev$kind == "raw-ready" & ev$status == "timeout")
        )
      } else {
        "0"
      }
    ))
  }
  cat(
    "\nA class column reads <runs with at least one failure of that class>/",
    "<runs> (<failing expectations of that class>).\n",
    sep = ""
  )
}

selftest <- function() {
  cases <- list(
    list("Could not start R session, timed out", FALSE, "start-timeout"),
    list("webfakes app subprocess did not start :(", FALSE, "start-timeout"),
    list("r$status (`actual`) not identical to 200L.", TRUE, "raw-server"),
    list("Failed to connect to 127.0.0.1 port 4000", FALSE, "raw-server"),
    list(
      "the raw server's readiness wait ran out after 20 s",
      FALSE,
      "raw-server"
    ),
    list("`out$cause` is \"connect-failed\"", FALSE, "raw-server"),
    list("r$status (`actual`) not identical to 200L.", FALSE, "other")
  )
  for (case in cases) {
    got <- classify(case[[1L]], case[[2L]])
    if (!identical(got, case[[3L]])) {
      stop("classifier: '", case[[1L]], "' -> ", got, ", want ", case[[3L]])
    }
  }
  cat("classifier selftest: ", length(cases), " cases ok\n", sep = "")
}

args <- commandArgs(trailingOnly = TRUE)
switch(
  args[[1L]],
  run = run_once(args[[2L]], args[[3L]]),
  summarize = summarize(args[[2L]]),
  selftest = selftest(),
  stop("unknown mode: ", args[[1L]])
)
