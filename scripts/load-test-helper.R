# Timing instrumentation for scripts/load-test.sh. The script copies this
# file into its container's copy of the tree as
# tests/testthat/helper-zzz-load-test.R, so it is sourced after
# helper-transport.R, into the same environment, and never lands in the
# repository's tests. It wraps the two process starters by name, so every
# helper that calls them (local_test_server(), local_raw_server(), ...) goes
# through the wrapper, and changes nothing they do: it records how long each
# start took, one tab-separated line per start, to SSRFR_LOAD_TEST_EVENTS.
#
#   app-start  <secs>  ok|error    <test>   local_app_server()'s start
#   raw-ready  <secs>  ok|timeout  <test>   local_server_process()
#
# local_server_process() waits up to 20 s for its server to listen and
# returns either way (SSRF-ptkasofy), so a start that took 20 s or more is a
# readiness timeout.

load_test_event <- function(kind, t0, status) {
  path <- Sys.getenv("SSRFR_LOAD_TEST_EVENTS")
  if (!nzchar(path)) {
    return(invisible())
  }
  test <- tryCatch(
    get("test_description", asNamespace("testthat"))(),
    error = function(e) NULL
  )
  if (!is.character(test) || length(test) != 1L) {
    test <- "?"
  }
  secs <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  cat(
    kind,
    "\t",
    sprintf("%.3f", secs),
    "\t",
    status,
    "\t",
    gsub("[\t\r\n]+", " ", test),
    "\n",
    sep = "",
    file = path,
    append = TRUE
  )
}

# webfakes starts the app process lazily, on the first get_port() or url(),
# through the object's own `start` method, which it looks up on the object
# each time; so the wrapper times that method.
load_test_app_server <- local_app_server
local_app_server <- function(app, opts, port = NULL, env = parent.frame()) {
  out <- load_test_app_server(app, opts = opts, port = port, env = env)
  start <- out$start
  out$start <- function() {
    t0 <- Sys.time()
    withCallingHandlers(
      start(),
      error = function(e) load_test_event("app-start", t0, "error")
    )
    load_test_event("app-start", t0, "ok")
    invisible(out)
  }
  out
}

load_test_server_process <- local_server_process
local_server_process <- function(serve, args = list(), env = parent.frame()) {
  t0 <- Sys.time()
  out <- load_test_server_process(serve, args = args, env = env)
  waited <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  load_test_event("raw-ready", t0, if (waited >= 20) "timeout" else "ok")
  out
}
