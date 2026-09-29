# Post-stop reads with and without an abort from the write callback, behind
# r-binding.md §7's callback rows (fp SSRF-itqfcyrw): how much a transfer
# reads and decodes after a stop, when the write callback only records it
# (ssrfr until 2026-09-29, the mechanism of 2026-09-26-post-stop-reads.R) and
# when it records it and then invokes R's `abort` restart.
#
# curl evaluates the write callback through R_tryEval() (curl 8.0.0,
# src/utils.c, data_callback()), so the restart's jump ends at that call and
# the callback returns 0: a short write, which libcurl fails as
# CURLE_WRITE_ERROR. The process runs with an options(error = ) hook that
# quits it with status 3, so a restart that escaped or a condition raised
# would end the run before its last line.
#
# Modes, each per `buffersize`:
#   record    the write callback records the stop at 100,000 decoded bytes
#             and returns; the loop cancels the transfer after the round
#   abort     the same stop, then invokeRestart("abort") in that callback
#   progress  the progress callback records a stop once 20,000 wire bytes
#             have arrived; the next write callback aborts
# For each: the wire bytes traced after the stop (CURLINFO_DATA_IN), the
# decoded bytes delivered after it, the class of the error the fail callback
# got, and the number of final (empty) deliveries.
#
#   Rscript --vanilla design/evidence/2026-09-29-abort-post-stop-reads.R
#
# Needs a free loopback port (SSRFR_PROBE_PORT, default 18181) and about
# 400 MB of memory for the server to build its body once. Captured output:
# 2026-09-29-abort-post-stop-reads.txt.

suppressMessages(library(curl))
options(error = function() {
  cat("error hook ran\n")
  quit("no", status = 3L)
})

port <- as.integer(Sys.getenv("SSRFR_PROBE_PORT", "18181"))
limit <- 1e5
wire_limit <- 2e4
sizes <- c(0L, 4096L, 1024L) # 0: libcurl's default buffer, 16 KiB
modes <- c("record", "abort", "progress")

server <- sprintf(
  'body <- memCompress(raw(4e8), "gzip")
  head <- charToRaw(paste0("HTTP/1.1 200 OK\\r\\nContent-Encoding: gzip\\r\\n",
    "Content-Type: application/octet-stream\\r\\nContent-Length: ",
    length(body), "\\r\\nConnection: close\\r\\n\\r\\n"))
  s <- serverSocket(%dL)
  invisible(file.create(%s))
  for (i in seq_len(%dL)) {
    con <- socketAccept(s, open = "r+b", blocking = TRUE)
    readBin(con, "raw", 65536L)
    try(writeBin(c(head, body), con), silent = TRUE)
    try(close(con), silent = TRUE)
  }
  close(s)',
  port,
  deparse(ready <- tempfile("ready")),
  length(sizes) * length(modes)
)
script <- tempfile(fileext = ".R")
writeLines(server, script)
system2(file.path(R.home("bin"), "Rscript"), c("--vanilla", script), wait = FALSE)
for (i in seq_len(600)) {
  if (file.exists(ready)) break
  Sys.sleep(0.1)
}
stopifnot(file.exists(ready))

probe <- function(mode, size) {
  seen <- new.env()
  seen$decoded <- 0
  seen$wire <- 0
  seen$stopped <- FALSE
  seen$wire_after <- 0
  seen$decoded_after <- 0
  seen$finals <- 0L
  seen$fail <- NULL
  pool <- new_pool(total_con = 1L, host_con = 1L, multiplex = FALSE)
  h <- new_handle(
    url = sprintf("http://127.0.0.1:%d/", port),
    accept_encoding = "gzip, deflate",
    forbid_reuse = 1L,
    http_version = 2L,
    verbose = TRUE,
    debugfunction = function(type, msg) {
      if (type == 3L) {
        if (seen$stopped) {
          seen$wire_after <- seen$wire_after + length(msg)
        }
        seen$wire <- seen$wire + length(msg)
      }
    },
    noprogress = 0L,
    xferinfofunction = function(down, up) {
      if (mode == "progress" && !seen$stopped && seen$wire > wire_limit) {
        seen$stopped <- TRUE
      }
      TRUE
    }
  )
  if (size > 0L) handle_setopt(h, buffersize = size)
  multi_add(
    h,
    data = function(x, final = FALSE) {
      if (final) {
        seen$finals <- seen$finals + 1L
        return(invisible())
      }
      if (seen$stopped) {
        seen$decoded_after <- seen$decoded_after + length(x)
        if (mode != "record") invokeRestart("abort")
        return(invisible())
      }
      seen$decoded <- seen$decoded + length(x)
      if (mode != "progress" && seen$decoded > limit) {
        seen$stopped <- TRUE
        if (mode == "abort") invokeRestart("abort")
      }
      invisible()
    },
    fail = function(msg) seen$fail <- msg,
    pool = pool
  )
  repeat {
    multi_run(timeout = 0, pool = pool)
    if (seen$stopped) {
      multi_cancel(h)
      break
    }
    if (!length(multi_list(pool))) break
    Sys.sleep(0.001)
  }
  sprintf(
    "%-8s buffersize %-7s wire after stop %9.0f | decoded after stop %11.0f | fail %-24s | finals %d",
    mode,
    if (size > 0L) size else "default",
    seen$wire_after,
    seen$decoded_after,
    if (is.null(seen$fail)) "none" else class(seen$fail)[[1L]],
    seen$finals
  )
}

v <- curl_version()
cat("curl", as.character(packageVersion("curl")), "| libcurl", v$version,
    "|", R.version$platform, "\n")
for (mode in modes) for (size in sizes) cat(probe(mode, size), "\n")
cat("reached the end; the error hook did not run\n")
