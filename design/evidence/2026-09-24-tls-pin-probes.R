# TLS under a pin, behind INV-9 (ssrfr-v1.md §13) and r-binding.md §7: a
# connect_to or resolve pin leaves SNI, certificate verification and Host bound
# to the URL's hostname, and pinning by rewriting the URL to the IP does not
# (fp SSRF-ssldkvmd).
#
# Ported from the July research notes: research/09 §4.4 (TLSA-TLSD, offline,
# run 2026-07-25 with R 4.6.0, curl 7.1.0, libcurl 8.14.1, LibreSSL 3.3.6,
# webfakes 1.5.0, macOS / Darwin 25.4.0) and research/08 §B.4 (the three
# pinning methods against a public host, run with the curl command-line tool
# 8.20.0 on OpenSSL 3.6.2). Block 3 re-runs the latter through R's curl.
#
# Run from the repository root with curl and webfakes installed. Blocks 1-2 are
# offline. Block 3 needs network access to example.com and is skipped without
# it; its address comes from the live DNS answer.
#   Rscript design/evidence/2026-09-24-tls-pin-probes.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1, LibreSSL
# 3.3.6), webfakes 1.5.0, macOS 26 (Darwin 25.6). Expected output is in the
# comment after each block; "July:" marks where the 2026-07-25 result
# differed. A different answer on another platform or version is a finding,
# not a failure of this script.

suppressMessages({
  library(curl)
  library(webfakes)
})

cat(
  "curl",
  as.character(packageVersion("curl")),
  "libcurl",
  curl_version()$version,
  curl_version()$ssl_version,
  "\n"
)

try_fetch <- function(url, ...) {
  h <- new_handle(connecttimeout = 5, timeout = 10, ...)
  tryCatch(
    {
      r <- curl_fetch_memory(url, handle = h)
      sprintf(
        "status %d %s",
        r$status_code,
        substr(rawToChar(r$content), 1, 40)
      )
    },
    error = function(e) gsub("\n", " ", conditionMessage(e))
  )
}

# 1. The certificate webfakes serves: CN=localhost with an IP SAN for
#    127.0.0.1. That SAN is why block 2's TLSD is a caveat, not a result.
ca <- system.file("cert", "localhost", "ca.crt", package = "webfakes")
crt <- system.file("cert", "localhost", "server.crt", package = "webfakes")
if (nzchar(Sys.which("openssl")) && nzchar(crt)) {
  print(system2(
    "openssl",
    c(
      "x509",
      "-in",
      shQuote(crt),
      "-noout",
      "-subject",
      "-ext",
      "subjectAltName"
    ),
    stdout = TRUE
  ))
}
# subject=C=ES, ST=Barcelona, L=Barcelona, O=webfakes.r-lib.org, CN=localhost
# X509v3 Subject Alternative Name:
#     IP Address:127.0.0.1, DNS:localhost, DNS:localhost.localdomain

# 2. TLSA-TLSD against a loopback HTTPS app ("0s" = any port, TLS).
app <- new_app()
app$get("/hit", function(req, res) {
  res$send(paste0("host=", req$get_header("Host")))
})
web <- local_app_process(app, port = "0s")
port <- web$get_port()
pin <- function(host) sprintf("%s::127.0.0.1:", host)
cat(
  "TLSA https://localhost, no pin:        ",
  try_fetch(sprintf("https://localhost:%d/hit", port), cainfo = ca),
  "\n"
)
cat(
  "TLSB https://pinned.example.invalid:   ",
  try_fetch(
    sprintf("https://pinned.example.invalid:%d/hit", port),
    cainfo = ca,
    connect_to = pin("pinned.example.invalid")
  ),
  "\n"
)
cat(
  "TLSC https://localhost, pinned:        ",
  try_fetch(
    sprintf("https://localhost:%d/hit", port),
    cainfo = ca,
    connect_to = pin("localhost")
  ),
  "\n"
)
cat(
  "TLSD https://127.0.0.1, no pin:        ",
  try_fetch(sprintf("https://127.0.0.1:%d/hit", port), cainfo = ca),
  "\n"
)
# TLSA: status 200 host=localhost:<port>
# TLSB: "SSL peer certificate or SSH remote key was not OK ... SSL: no
#       alternative certificate subject name matches target hostname
#       'pinned.example.invalid'" — the pin did not change the verified name.
# TLSC: status 200 host=localhost:<port> — pin and verification compose.
# TLSD: status 200 host=127.0.0.1:<port> — only because of the IP SAN.
# July used "HOST:PORT:127.0.0.1:PORT" pins; the empty-field form above gives
# the same results.

# 3. The three pinning methods against a public HTTPS host (research/08 §B.4,
#    INV-9). connect_to and resolve keep the hostname for SNI and
#    verification; rewriting the URL to the IP with a Host header does not.
ip <- tryCatch(nslookup("example.com", ipv4_only = TRUE), error = function(e) {
  NA
})
if (!is.na(ip)) {
  cat("address used:", ip, "\n")
  cat(
    "connect_to:          ",
    try_fetch(
      "https://example.com/",
      connect_to = sprintf("example.com:443:%s:443", ip)
    ),
    "\n"
  )
  cat(
    "resolve:             ",
    try_fetch(
      "https://example.com/",
      resolve = sprintf("example.com:443:%s", ip)
    ),
    "\n"
  )
  cat(
    "IP URL + Host header:",
    try_fetch(sprintf("https://%s/", ip), httpheader = "Host: example.com"),
    "\n"
  )
} else {
  cat("block 3 skipped: example.com did not resolve\n")
}
# 2026-09-24, address 172.66.147.243: connect_to status 200; resolve status
# 200; IP URL + Host header: "SSL connect error ... TLS connect error: ...
# sslv3 alert handshake failure" (the server gets the IP, not the name, as SNI).
# July, curl CLI 8.20.0 / OpenSSL 3.6.2, address 104.20.23.154: the same three
# outcomes; the last as "curl: (35) TLS connect error: ssl/tls alert handshake
# failure". Not run here: against a server that does not route on SNI, the
# third method would reach certificate verification and fail on the hostname
# (the IP) instead. Either way, pinning by URL rewrite works only with
# verification off.
