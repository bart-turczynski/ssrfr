# Search-domain probe behind ssrfr-v1.md §5.0 "Names resolve as absolute"
# (fp SSRF-rcwugkqo): with a DNS search list in force, a single-label name
# resolves through it, and the same name with a trailing root dot does not.
#
# Needs a resolver whose search list names a domain that answers for one
# name. 2026-09-25-linux-transport-matrix.sh builds that in Docker: a helper
# container with the network alias svc.corp.test on a private bridge network,
# and the probe container started with --dns-search corp.test. Elsewhere, set
# SSRFR_SEARCH_NAME and SSRFR_SEARCH_DOMAIN to a name and search domain the
# local resolver answers; without them the probe reports that it has no
# fixture and stops.
#   Rscript --vanilla design/evidence/2026-09-25-search-domain-probe.R
#
# Rows read like 2026-09-25-platform-transport-probes.R: "ok" when the
# observed outcome is the reference, "DIFFERS" otherwise. The reference is the
# property §5.0 assumes. Captured output: 2026-09-25-linux-transport-results.txt.

suppressMessages(library(curl))

name <- Sys.getenv("SSRFR_SEARCH_NAME", "svc")
dom <- Sys.getenv("SSRFR_SEARCH_DOMAIN", "corp.test")
fq <- paste0(name, ".", dom)
v <- curl_version()
cat("curl", as.character(packageVersion("curl")), "| libcurl", v$version, "\n")

look <- function(h) {
  r <- tryCatch(nslookup(h, ipv4_only = FALSE, multiple = TRUE, error = FALSE),
                error = function(e) NULL)
  if (length(r)) paste(sort(r), collapse = " ") else "no answer"
}
row <- function(label, ref, obs) {
  same <- identical(ref, obs)
  cat(sprintf("%-7s %-52s %s%s\n", if (same) "ok" else "DIFFERS", label, obs,
              if (same) "" else paste0("   [ref: ", ref, "]")))
}
dialed <- function(url) {
  log <- character()
  h <- new_handle(connecttimeout = 2, timeout = 3, verbose = TRUE,
                  debugfunction = function(type, msg) {
                    if (type == 0L) log <<- c(log, trimws(strsplit(rawToChar(msg), "\n")[[1]]))
                    NULL
                  })
  e <- tryCatch({ curl_fetch_memory(url, handle = h); "" },
                error = function(e) conditionMessage(e))
  d <- grep("^Trying ", log, value = TRUE)
  if (length(d)) sub(":[0-9]+\\.\\.\\.$", "", sub("^Trying ", "", d[1]))
  else if (grepl("resolve", e, ignore.case = TRUE)) "could not resolve"
  else paste("?", substr(e, 1, 40))
}

addr <- look(fq)
if (addr == "no answer") {
  cat("no fixture:", fq, "does not resolve here; set SSRFR_SEARCH_NAME and",
      "SSRFR_SEARCH_DOMAIN (see the header)\n")
  quit(save = "no")
}
cat("fixture:", fq, "->", addr, "\n")
row(sprintf("a nslookup(\"%s\") (control)", fq), addr, look(fq))
row(sprintf("b nslookup(\"%s.\")", fq), addr, look(paste0(fq, ".")))
row(sprintf("c nslookup(\"%s\"): search list applies", name), addr, look(name))
row(sprintf("d nslookup(\"%s.\"): absolute, no search", name), "no answer",
    look(paste0(name, ".")))
row(sprintf("e libcurl http://%s:1/ dials", name), addr, dialed(sprintf("http://%s:1/", name)))
row(sprintf("f libcurl http://%s.:1/ dials", name), "could not resolve",
    dialed(sprintf("http://%s.:1/", name)))
