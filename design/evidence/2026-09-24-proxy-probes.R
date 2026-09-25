# Proxy probes behind INV-10 (ssrfr-v1.md §13) and the r-binding.md §7 proxy
# isolation rule: which proxy variables libcurl reads for each scheme, that
# proxy = "" with noproxy = "*" neutralizes all of them, and what a proxy is
# asked for when a connect_to pin is set (fp SSRF-aylqwknz).
#
# New on 2026-09-24; 2026-09-24-transport-probes.R block 11 covers http_proxy
# in a child process only. Here the variables are set in-process with
# Sys.setenv(), which also shows that libcurl reads them on every transfer.
#
# Run from the repository root with curl, webfakes and callr installed. No
# network access is needed: every target and proxy is loopback, and the pinned
# names are RFC 2606 .invalid names. Blocks 3 and 4 run the client in a callr
# child against a raw serverSocket() listener, and are skipped without callr.
#   Rscript --vanilla design/evidence/2026-09-24-proxy-probes.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1, LibreSSL
# 3.3.6), webfakes 1.5.0, callr 3.8.0, macOS 26 (Darwin 25.6). Expected output
# is in the comment after each block, with ports elided as <port>. A different
# answer on another platform or version is a finding, not a failure of this
# script.

suppressMessages({
  library(curl)
  library(webfakes)
})

cat("curl", as.character(packageVersion("curl")),
    "libcurl", curl_version()$version, curl_version()$ssl_version, "\n")

vars <- c("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY",
          "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY")
Sys.unsetenv(vars)

# One loopback app over HTTP and one over HTTPS, answering "direct". The HTTP
# target is pinned under a .invalid name. The HTTPS target is pinned under
# "localhost", the name webfakes' certificate carries, so that verification
# passes and only the proxy decides the outcome.
app <- new_app()
app$get("/", function(req, res) res$send("direct"))
http <- local_app_process(app)
https <- local_app_process(app, port = "0s")
ca <- system.file("cert", "localhost", "ca.crt", package = "webfakes")
target <- list(
  http = list(url = sprintf("http://pinned.example.invalid:%d/", http$get_port()),
              pin = "pinned.example.invalid::127.0.0.1:"),
  https = list(url = sprintf("https://localhost:%d/", https$get_port()),
               pin = "localhost::127.0.0.1:"))

# Fetch a pinned target with `var` set to `value` in this process. Returns the
# body or the first line of the error, plus the "Uses proxy env variable" line
# from libcurl's trace when there is one.
fetch <- function(scheme, var, value, neutral) {
  Sys.unsetenv(vars)
  if (!is.na(var)) do.call(Sys.setenv, setNames(list(value), var))
  on.exit(Sys.unsetenv(vars))
  log <- character()
  h <- new_handle(connect_to = target[[scheme]]$pin, cainfo = ca, timeout = 5,
                  forbid_reuse = 1L, verbose = TRUE,
                  debugfunction = function(type, msg) {
                    if (type == 0L) log <<- c(log, trimws(rawToChar(msg)))
                    NULL
                  })
  if (neutral) handle_setopt(h, proxy = "", noproxy = "*")
  r <- tryCatch(rawToChar(curl_fetch_memory(target[[scheme]]$url, handle = h)$content),
                error = function(e) sub("\n.*", "", conditionMessage(e)))
  used <- grep("^Uses proxy env variable", log, value = TRUE)
  if (length(used)) paste(r, "|", sub(" ==.*", "", used[1])) else r
}

# 1. Which variables libcurl reads, per scheme. Each variable in turn points at
#    a dead loopback port (http://127.0.0.1:1); "Could not connect" means the
#    fetch went to the proxy. Then the same with proxy = "" and noproxy = "*".
dead <- "http://127.0.0.1:1"
for (s in c("http", "https")) for (v in c(NA, vars[1:6])) {
  cat(sprintf("%-5s %-11s ambient: %s  neutral: %s\n", s,
              if (is.na(v)) "(none)" else v,
              fetch(s, v, dead, FALSE), fetch(s, v, dead, TRUE)))
}
# http  (none)      ambient: direct  neutral: direct
# http  http_proxy  ambient: Could not connect to server
#   [pinned.example.invalid]: | Uses proxy env variable http_proxy  neutral: direct
# http  HTTP_PROXY  ambient: direct  neutral: direct
# http  https_proxy ambient: direct  neutral: direct
# http  HTTPS_PROXY ambient: direct  neutral: direct
# http  all_proxy   ambient: Could not connect ... | ... all_proxy  neutral: direct
# http  ALL_PROXY   ambient: Could not connect ... | ... ALL_PROXY  neutral: direct
# https (none)      ambient: direct  neutral: direct
# https http_proxy  ambient: direct  neutral: direct
# https HTTP_PROXY  ambient: direct  neutral: direct
# https https_proxy ambient: Could not connect to server [localhost]: | Uses
#   proxy env variable https_proxy  neutral: direct
# https HTTPS_PROXY ambient: Could not connect ... | ... HTTPS_PROXY  neutral: direct
# https all_proxy   ambient: Could not connect ... | ... all_proxy  neutral: direct
# https ALL_PROXY   ambient: Could not connect ... | ... ALL_PROXY  neutral: direct
# So libcurl reads http_proxy in lowercase only, https_proxy in either case for
# https:// only, and all_proxy in either case for both; the neutralized handle
# is direct under every variable. Setting the variable in-process was enough:
# libcurl reads the environment per transfer, not at load time.

# 2. SOCKS values. ALL_PROXY and http_proxy set to a dead socks5h:// or
#    socks4:// proxy; the same neutralization applies.
for (v in c("ALL_PROXY", "http_proxy")) for (p in c("socks5h://127.0.0.1:1",
                                                     "socks4://127.0.0.1:1")) {
  cat(sprintf("%-10s = %-22s ambient: %s  neutral: %s\n", v, p,
              fetch("http", v, p, FALSE), fetch("http", v, p, TRUE)))
}
# ALL_PROXY  = socks5h://127.0.0.1:1  ambient: Could not connect to server
#   [pinned.example.invalid]: | Uses proxy env variable ALL_PROXY  neutral: direct
# ALL_PROXY  = socks4://127.0.0.1:1   the same
# http_proxy = socks5h://127.0.0.1:1  ambient: Could not connect ... | Uses proxy
#   env variable http_proxy  neutral: direct
# http_proxy = socks4://127.0.0.1:1   the same

# A raw loopback listener on a free port, standing in for the proxy, and a
# child R process that fetches a pinned target with a proxy variable pointed
# at it. The child's environment is callr's safe set plus that one variable.
free_port <- function() {
  for (p in sample(30000:60000, 50)) {
    s <- tryCatch(serverSocket(p), error = function(e) NULL)
    if (!is.null(s)) { close(s); return(p) }
  }
  stop("no free port")
}
# Poll for a pending connection: a single socketSelect() can return FALSE at
# once (2026-09-24-test-harness-probes.R block 6).
pending <- function(srv, secs) {
  t0 <- Sys.time()
  repeat {
    if (socketSelect(list(srv), timeout = 0.2)) return(TRUE)
    if (difftime(Sys.time(), t0, units = "secs") >= secs) return(FALSE)
  }
}
leak_to <- function(var, proxy_scheme, url, pin, read_request) {
  lp <- free_port()
  srv <- serverSocket(lp)
  on.exit(close(srv))
  env <- c(callr::rcmd_safe_env(), setNames(sprintf("%s://127.0.0.1:%d", proxy_scheme, lp), var))
  px <- callr::r_bg(function(url, pin, ca) {
    h <- curl::new_handle(connect_to = pin, cainfo = ca, timeout = 4)
    tryCatch(curl::curl_fetch_memory(url, handle = h)$status_code,
             error = function(e) gsub("\n", " ", conditionMessage(e)))
  }, args = list(url = url, pin = pin, ca = ca), env = env)
  on.exit(px$kill(), add = TRUE)
  if (!pending(srv, 6)) return("listener got nothing")
  con <- socketAccept(srv, blocking = TRUE, open = "r+b", timeout = 6)
  on.exit(close(con), add = TRUE)
  read_request(con)
}
has_callr <- requireNamespace("callr", quietly = TRUE)
if (!has_callr) cat("blocks 3-4 skipped: callr is not installed\n")

# 3. What an HTTP proxy is asked for under a connect_to pin: the first two
#    request lines it receives, for a pinned http:// and a pinned https://
#    target. The http:// request is to port 8080, which nothing serves.
http_lines <- function(con) readLines(con, n = 2L, warn = FALSE)
if (has_callr) {
  print(leak_to("http_proxy", "http", "http://pinned.example.invalid:8080/x",
                "pinned.example.invalid::127.0.0.1:", http_lines))
  print(leak_to("HTTPS_PROXY", "http", target$https$url, target$https$pin, http_lines))
}
# "CONNECT 127.0.0.1:8080 HTTP/1.1" "Host: 127.0.0.1:8080"
# "CONNECT 127.0.0.1:<port> HTTP/1.1" "Host: 127.0.0.1:<port>"
# Under a connect_to pin libcurl tunnels even a plain http:// request, and the
# tunnel target is the pinned address and port, not the hostname.


# 4. What a SOCKS5 proxy is asked for under the pin: the listener answers the
#    greeting with "no authentication" and decodes the CONNECT request's
#    address type (1 = IPv4, 3 = domain name), address and port.
socks_request <- function(con) {
  greet <- readBin(con, "raw", 2)
  readBin(con, "raw", as.integer(greet[2]))       # the offered methods
  writeBin(as.raw(c(5, 0)), con)
  flush(con)
  req <- readBin(con, "raw", 4)                   # VER CMD RSV ATYP
  atyp <- as.integer(req[4])
  dest <- switch(as.character(atyp),
    "1" = paste(as.integer(readBin(con, "raw", 4)), collapse = "."),
    "3" = rawToChar(readBin(con, "raw", as.integer(readBin(con, "raw", 1)))),
    "other")
  port <- sum(as.integer(readBin(con, "raw", 2)) * c(256L, 1L))
  sprintf("SOCKS5 CONNECT cmd %d atyp %d dest %s port %d", as.integer(req[2]),
          atyp, dest, port)
}
if (has_callr) for (s in c("socks5h", "socks5")) {
  cat(s, "->", leak_to("ALL_PROXY", s, "http://pinned.example.invalid:8080/",
                       "pinned.example.invalid::127.0.0.1:", socks_request), "\n")
}
# socks5h -> SOCKS5 CONNECT cmd 1 atyp 1 dest 127.0.0.1 port 8080
# socks5 -> SOCKS5 CONNECT cmd 1 atyp 1 dest 127.0.0.1 port 8080
# Both ask for the IPv4 literal of the pin; socks5h does not send the hostname.
# So no proxy type tested receives the hostname: a leak test must assert that
# nothing reaches the listener, not look for the name in what it receives.
