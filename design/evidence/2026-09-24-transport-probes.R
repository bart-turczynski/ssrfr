# Transport probes behind r-binding.md §3-§6 and ssrfr-v1.md §14: settable
# options, protocol exposure, what libcurl dials, the pinning primitives, the
# proxy hijack and the debugfunction audit seam (fp SSRF-ssldkvmd).
#
# Ported from the July research notes (research/00b §1-§6, research/10 §4.2-§4.4,
# §5.1 and §5.1a), which were run on 2026-07-25 with R 4.6.0, curl 7.1.0,
# libcurl 8.14.1 (LibreSSL 3.3.6), macOS / Darwin 25.4.0. Block 4's code was
# elided in the July note and is reconstructed here. Block 12 (resolve vs
# connection reuse) is new: July had only a reading of libcurl's lib/url.c.
#
# Run from the repository root with curl and webfakes installed. No network
# access is needed: every target is loopback or an RFC 2606 .invalid name.
# Block 9 shells out to the curl command-line tool and is skipped without it.
#   Rscript design/evidence/2026-09-24-transport-probes.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1, LibreSSL
# 3.3.6), webfakes 1.5.0, curl CLI 8.20.0, macOS 26 (Darwin 25.6). Expected
# output is in the comment after each block; "July:" marks where the 2026-07-25
# result differed. A different answer on another platform or version is a
# finding, not a failure of this script.

suppressMessages({
  library(curl)
  library(webfakes)
})

cat("curl", as.character(packageVersion("curl")),
    "libcurl", curl_version()$version, curl_version()$ssl_version, "\n")

# Fetch `url` with a verbose handle and return the libcurl text trace (debug
# type 0) plus the error, if any. The trace names the address actually dialed.
trace_fetch <- function(url, ..., handle = NULL) {
  log <- character()
  h <- if (is.null(handle)) new_handle(connecttimeout = 2, timeout = 3) else handle
  handle_setopt(h, ..., verbose = TRUE, debugfunction = function(type, msg) {
    if (type == 0L) log <<- c(log, trimws(rawToChar(msg)))
    NULL
  })
  res <- tryCatch(curl_fetch_memory(url, handle = h),
                  error = function(e) conditionMessage(e))
  list(log = log, result = res)
}
dialed <- function(t) {
  hit <- grep("^(Trying|Could not resolve|Re-using|Connected to)", t$log, value = TRUE)
  if (length(hit)) hit else t$log[1]
}

# A loopback app that echoes the Host header it received. Port-pinned tests
# below pin .invalid names to it, so arrival proves the pin was used. Keep-alive
# is on so that block 12 can observe connection reuse.
app <- new_app()
app$get("/", function(req, res) res$send(paste("host:", req$get_header("Host"))))
app$get("/to", function(req, res) res$redirect(req$query$u, 302L))
srv <- local_app_process(app, opts = server_opts(enable_keep_alive = TRUE,
                                                 num_threads = 2))
port <- srv$get_port()

# 1. The debugfunction audit seam (research/00b §1). The trace names the
#    dialed address; handle_data() exposes no peer IP.
t <- trace_fetch("http://127.0.0.1:1/")
t$log
names(handle_data(new_handle()))
# "Trying 127.0.0.1:1..." / "connect to 127.0.0.1 port 1 from 127.0.0.1 port
# <n> failed: Connection refused" / "Failed to connect to 127.0.0.1 port 1
# after 0 ms: Could not connect to server" / "closing connection #0"
# handle_data(): url status_code type headers modified times scheme
# http_version method — no primary or peer IP.

# 2. Settable options (research/00b §2, research/10 §5.1). Each is set with a
#    harmless value; dns_servers needs a c-ares build and fails at setopt.
opts <- list(resolve = "a.invalid:80:127.0.0.1", connect_to = "a.invalid::127.0.0.1:",
             dns_cache_timeout = 0L, maxfilesize = 1000, maxfilesize_large = 1000,
             forbid_reuse = 1L, fresh_connect = 1L, maxage_conn = 1L,
             noproxy = "*", proxy = "", path_as_is = 1L, ipresolve = 1L,
             protocols_str = "http,https", redir_protocols_str = "http,https",
             unrestricted_auth = 0L, happy_eyeballs_timeout_ms = 200L,
             dns_shuffle_addresses = 0L, unix_socket_path = "",
             abstract_unix_socket = "", altsvc = "", hsts = "",
             followlocation = 0L, maxredirs = 5L, netrc = 0L,
             default_protocol = "https", dns_servers = "127.0.0.1:5353")
ok <- vapply(names(opts), function(o) {
  tryCatch({ do.call(handle_setopt, c(list(new_handle()), opts[o])); "ok" },
           error = function(e) conditionMessage(e))
}, character(1))
ok[ok != "ok"]
all(names(opts) %in% names(curl_options()))
length(curl_options())
# Only dns_servers fails: "Invalid or unsupported value when setting curl
# option 'dns_servers'". All names are in curl_options(). 308 options.
curl_version()$ares   # NULL: this build has no c-ares

# 3. All addresses the system resolver returns (r-binding.md §3).
nslookup("localhost", ipv4_only = FALSE, multiple = TRUE)
# "::1" "127.0.0.1"

# 4. Protocol exposure (research/00b §3, research/10 §4.1).
curl_version()$protocols
# dict file ftp ftps gopher gophers http https imap imaps ldap ldaps mqtt pop3
# pop3s rtsp smb smbs smtp smtps telnet tftp ws wss (24; no scp, sftp, rtmp)

# 5. First-hop reachability (research/10 §4.2). "Failed to connect" or a
#    timeout means libcurl accepted the scheme and attempted I/O.
first_hop <- c(file = "file:///etc/hosts", dict = "dict://127.0.0.1:1/",
               gopher = "gopher://127.0.0.1:1/", telnet = "telnet://127.0.0.1:1",
               ldap = "ldap://127.0.0.1:1/", imap = "imap://127.0.0.1:1/",
               pop3 = "pop3://127.0.0.1:1/", smtp = "smtp://127.0.0.1:1/",
               rtsp = "rtsp://127.0.0.1:1/", ws = "ws://127.0.0.1:1/",
               smb = "smb://127.0.0.1:1/", tftp = "tftp://127.0.0.1:1/x",
               scp = "scp://127.0.0.1:1/x", sftp = "sftp://127.0.0.1:1/x")
for (s in names(first_hop)) {
  r <- tryCatch({
    x <- curl_fetch_memory(first_hop[[s]],
                           handle = new_handle(connecttimeout = 2, timeout = 2))
    sprintf("status %d, %d bytes", x$status_code, length(x$content))
  }, error = function(e) conditionMessage(e))
  cat(sprintf("%-7s %s\n", s, r))
}
# file: status 0, 213 bytes (all of /etc/hosts). dict gopher telnet ldap imap
# pop3 smtp rtsp ws: "Could not connect to server ... Failed to connect to
# 127.0.0.1 port 1". smb: "URL using bad/illegal format or missing URL ...
# missing share in URL path for SMB" (scheme accepted, URL shape rejected).
# tftp: "Timeout was reached". scp, sftp: "Unsupported protocol" (not compiled
# in, not a policy control).

# 5a. The whole R stack reads the file (research/10 §4.2, r-binding.md §5).
f <- "file:///etc/hosts"
readers <- list(
  curl = function() length(curl_fetch_memory(f)$content),
  httr2 = function() length(httr2::resp_body_raw(httr2::req_perform(httr2::request(f)))),
  httr = function() length(httr::GET(f)$content),
  readLines = function() length(readLines(f, warn = FALSE)),
  download.file = function() {
    d <- tempfile(); on.exit(unlink(d))
    utils::download.file(f, d, method = "libcurl", quiet = TRUE); file.size(d)
  })
for (n in names(readers)) {
  r <- tryCatch(paste("READ", readers[[n]]()), error = function(e) conditionMessage(e))
  cat(sprintf("%-13s %s\n", n, r))
}
# curl, httr2, httr, download.file: READ 213 (bytes); readLines: READ 9
# (lines). Every reader returns the file.

# 6. Redirect-hop reachability (research/10 §4.3). With libcurl following, a
#    302 to anything but http, https, ftp, ftps is refused.
for (s in c("file:///etc/hosts", "gopher://127.0.0.1:1/", "dict://127.0.0.1:1/",
            "ftp://127.0.0.1:1/", "http://127.0.0.1:1/")) {
  r <- tryCatch({
    x <- curl_fetch_memory(srv$url("/to", query = list(u = s)),
                           handle = new_handle(followlocation = 1L, timeout = 3))
    paste("status", x$status_code)
  }, error = function(e) conditionMessage(e))
  cat(sprintf("%-22s %s\n", s, r))
}
# file, gopher, dict: 'Unsupported protocol: Protocol "<scheme>" disabled (in
# redirect)'. ftp, http: "Could not connect to server ... port 1" (the
# redirect was followed).

# 7. libcurl's URL parser on the IPv4 evasion class (research/10 §4.4).
ev <- c("http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/",
        "http://127.1/", "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://user@127.0.0.1:80@evil.com/", "http://127.0.0.1%09.evil.com/",
        "http://evil.com#@127.0.0.1/", "http://①②⑦.0.0.1/",
        "http://metadata.google.internal/")
for (u in ev) {
  cat(sprintf("%-38s %s\n", u,
              tryCatch(curl_parse_url(u)$host, error = function(e) "<parse error>")))
}
# 127.0.0.1 x4; [::ffff:127.0.0.1]; <parse error> x2; evil.com; the circled
# digits pass through unchanged; metadata.google.internal.

# 8. What libcurl dials for 0177.0.0.1: loopback (r-binding.md §2.5).
dialed(trace_fetch("http://0177.0.0.1:1/"))
# "Trying 127.0.0.1:1..."

# 9. The same through the curl CLI, as in July (BRAINSTORM §11).
if (nzchar(Sys.which("curl"))) {
  out <- suppressWarnings(system(
    "curl -s -v --connect-timeout 2 http://0177.0.0.1/ 2>&1", intern = TRUE))
  print(grep("Trying", out, value = TRUE))
}
# "*   Trying 127.0.0.1:80..."

# 10. Pinning primitives (research/00b §4-§6). All hosts are .invalid, so
#     "Could not resolve host" proves the pin was ignored.
pin <- function(url, ...) dialed(trace_fetch(url, ...))
#   resolve: several addresses in one entry, failed over in order.
pin("http://pin-test.invalid:1/", resolve = "pin-test.invalid:1:127.0.0.1,127.0.0.2")
# "Trying 127.0.0.1:1..." then "Trying 127.0.0.2:1..."
#   Port-key mismatch: both primitives silently fall back to real resolution.
pin("http://mismatch-test.invalid:1/", resolve = "mismatch-test.invalid:443:127.0.0.1")
pin("http://mismatch-test.invalid:1/", resolve = "mismatch-test.invalid:1:127.0.0.1")
pin("http://ct3.invalid:1/", connect_to = "ct3.invalid:443:127.0.0.1:443")
pin("http://ct3.invalid:1/", connect_to = "ct3.invalid:1:127.0.0.1:1")
# mismatch: "Could not resolve host: mismatch-test.invalid" (pin ignored);
# match: "Trying 127.0.0.1:1..."; connect_to the same pair.
#   connect_to: first matching entry wins, later entries ignored.
pin("http://ct6.invalid:1/", connect_to = c("ct6.invalid::127.0.0.1:",
                                             "ct6.invalid::127.0.0.2:"))
# "Trying 127.0.0.1:1..." only.
#   The empty-field forms.
pin("http://ct4.invalid:8080/", connect_to = "ct4.invalid::127.0.0.1:1")
pin("http://ct5.invalid:1/", connect_to = "ct5.invalid::127.0.0.1:")
# "Trying 127.0.0.1:1..." (empty request port matched :8080 and the port was
# rewritten); "Trying 127.0.0.1:1..." (address pinned, port preserved).
#   The pin carries the request to the app with Host intact.
r <- curl_fetch_memory(sprintf("http://pinned.example.invalid:%d/", port),
                       handle = new_handle(connect_to = "pinned.example.invalid::127.0.0.1:"))
rawToChar(r$content)
# "host: pinned.example.invalid:<port>"

# 11. Environment proxy hijack (research/10 §5.1a). A child R process with
#     http_proxy pointed at a dead loopback port; proxy = "" neutralizes it.
#     The target is pinned, so the proxy also bypasses the pin.
if (nzchar(Sys.which("Rscript"))) {
  child <- function(extra) {
    code <- sprintf(paste0(
      "h <- curl::new_handle(connect_to = 'pinned.example.invalid::127.0.0.1:',",
      " timeout = 3%s); r <- tryCatch(curl::curl_fetch_memory(",
      "'http://pinned.example.invalid:%d/', handle = h)$status_code,",
      " error = function(e) conditionMessage(e)); cat(r)"), extra, port)
    system2(file.path(R.home("bin"), "Rscript"), c("-e", shQuote(code)),
            env = "http_proxy=http://127.0.0.1:19999", stdout = TRUE, stderr = TRUE)
  }
  cat("ambient proxy: ", child(""), "\n")
  cat("proxy = \"\":    ", child(", proxy = ''"), "\n")
}
# ambient proxy: "Failed to connect to 127.0.0.1 port 19999 ..." (proxy used:
# the TCP peer is the proxy, not the pinned address; what the proxy is handed
# is in 2026-09-24-proxy-probes.R); proxy = "": 200. [July used http://example.com/ with no pin:
# the same failure, then status 200 fetched directly.]

# 12. resolve vs connection reuse (r-binding.md §4.1, research/08 surprising
#     finding 1). Two requests to the same name and port; the second carries a
#     pin to 192.0.2.1 (TEST-NET-1, never answers), on the same handle or on a
#     fresh one. A 200 from the app means a pooled connection was reused and
#     the new pin was never consulted. R's curl runs synchronous fetches on one
#     shared multi handle, so the pool outlives any single easy handle.
reuse <- function(opt, forbid = 0L, fresh_handle = FALSE) {
  host <- sprintf("reuse-%s-%d-%d.invalid", sub("_", "", opt), forbid, fresh_handle)
  u <- sprintf("http://%s:%d/", host, port)
  pin <- function(ip) {
    if (opt == "resolve") sprintf("%s:%d:%s", host, port, ip)
    else sprintf("%s::%s:", host, ip)
  }
  mk <- function(ip) {
    h <- new_handle(connecttimeout = 2, timeout = 3, forbid_reuse = forbid)
    handle_setopt(h, .list = setNames(list(pin(ip)), opt))
  }
  h <- mk("127.0.0.1")
  a <- trace_fetch(u, handle = h)
  if (fresh_handle) h <- mk("192.0.2.1")
  else handle_setopt(h, .list = setNames(list(pin("192.0.2.1")), opt))
  b <- trace_fetch(u, handle = h)
  cat(sprintf("%-10s forbid_reuse=%d fresh_handle=%-5s | first: %s | second: %s -> %s\n",
              opt, forbid, fresh_handle, dialed(a)[1], dialed(b)[1],
              if (is.character(b$result)) "error" else b$result$status_code))
}
reuse("resolve")
reuse("resolve", fresh_handle = TRUE)
reuse("resolve", forbid = 1L)
reuse("connect_to")
reuse("connect_to", fresh_handle = TRUE)
# resolve    forbid_reuse=0 fresh_handle=FALSE | second: "Re-using existing
#   http: connection with host reuse-resolve-0-0.invalid" -> 200
# resolve    forbid_reuse=0 fresh_handle=TRUE  | second: "Re-using existing
#   http: connection ..." -> 200 (a new handle does not help)
# resolve    forbid_reuse=1 fresh_handle=FALSE | second: "Trying
#   192.0.2.1:<port>..." -> error (timeout)
# connect_to forbid_reuse=0, either handle      | second: "Trying
#   192.0.2.1:<port>..." -> error (timeout)
# So a resolve pin is not consulted when a pooled connection matches;
# connect_to takes part in the reuse match; forbid_reuse closes the gap.
# July: not run; the claim rested on reading libcurl's lib/url.c.
