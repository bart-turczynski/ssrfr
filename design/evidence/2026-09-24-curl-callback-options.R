# Which libcurl callback options R's curl package can set, behind r-binding.md
# §6: the socket-open and pre-request hooks other ecosystems validate in are
# unreachable from R, and debugfunction is the only observer of the dialed
# address (fp SSRF-ssldkvmd).
#
# Ported from BRAINSTORM §3, research/00b §1, research/10 §5.1 and the
# 2026-07-31 field note on the R curl integration boundary (curl 7.1.0, source
# snapshot jeroen/curl@4092c366c27c8b64528b493be5e09fb6484a1172). July runs:
# R 4.6.0, curl 7.1.0, libcurl 8.14.1 (LibreSSL 3.3.6), macOS / Darwin 25.4.0.
#
# Run from the repository root with curl installed. No network access needed.
#   Rscript design/evidence/2026-09-24-curl-callback-options.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1, LibreSSL
# 3.3.6), macOS 26 (Darwin 25.6). Expected output is in the comment after each
# block; "July:" marks where an earlier result differed. A different answer on
# another platform or version is a finding, not a failure of this script.

library(curl)
cat("curl", as.character(packageVersion("curl")), "libcurl", curl_version()$version, "\n")

try_set <- function(name, value) {
  tryCatch({
    do.call(handle_setopt, c(list(new_handle()), setNames(list(value), name)))
    "accepted"
  }, error = function(e) conditionMessage(e))
}
f <- function(...) 0L

# 1. The hooks a validate-at-connect design needs, and their data pointers.
wanted <- c("prereqfunction", "prereqdata", "opensocketfunction", "opensocketdata",
            "sockoptfunction", "sockoptdata", "closesocketfunction",
            "resolver_start_function", "resolver_start_data")
tab <- curl_options()
res <- vapply(wanted, function(o) try_set(o, if (grepl("data$", o)) 1L else f),
              character(1))
data.frame(listed = wanted %in% names(tab), result = res)
# All nine are listed in curl_options(); every one is refused with
# "Option <name> (<id>) has unknown or unsupported type", e.g.
# prereqfunction (20312), prereqdata (10313), opensocketfunction (20163),
# opensocketdata (10164), sockoptfunction (20148). Unchanged from curl 7.1.0.

# 2. The callbacks R's curl does marshal. Settable is not the same as useful:
#    none of these runs before the connection with the peer address and a veto.
ok <- c("debugfunction", "xferinfofunction", "progressfunction", "headerfunction",
        "readfunction", "writefunction", "seekfunction", "ssl_ctx_function")
vapply(ok, function(o) try_set(o, function(...) 0L), character(1))
try_set("debugdata", 1L)
# Accepted: debugfunction, xferinfofunction, progressfunction, readfunction,
# seekfunction, ssl_ctx_function. Refused with "unknown or unsupported type":
# headerfunction (20079), writefunction (20011), debugdata (10095).
# July: research/00b §2 reported headerfunction, writefunction and debugdata
# as accepted. The 2026-07-31 reading of curl 7.1.0's src/handle.c lists only
# xferinfo/progress, read, debug, SSL-context and seek, which matches this run,
# so the July report was likely wrong rather than the package having changed.
# None of this affects r-binding.md §6, which relies on debugfunction only.

# 3. debugfunction fires and names the dialed address; handle_data() has no
#    peer IP (research/00b §1).
log <- character()
h <- new_handle(connecttimeout = 2, timeout = 3)
handle_setopt(h, verbose = TRUE, debugfunction = function(type, msg) {
  if (type == 0L) log <<- c(log, trimws(rawToChar(msg)))
  NULL
})
invisible(try(curl_fetch_memory("http://127.0.0.1:1/", handle = h), silent = TRUE))
grep("Trying", log, value = TRUE)
"primary_ip" %in% names(handle_data(h))
# "Trying 127.0.0.1:1..."; FALSE
