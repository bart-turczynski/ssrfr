# Handle-option probes behind r-binding.md §4.1, §4.2 and §5: what a new
# curl handle already carries (Accept-Encoding, the cookie engine, netrc),
# what handle_reset() restores, which encodings libcurl decodes, the shared
# DNS cache of R's multi handle, the empty-HOST connect_to form, ipresolve
# against a literal pin, and share.
#
# Run from the repository root with curl and webfakes installed. No network
# access is needed: every target is loopback or an RFC 2606 .invalid name.
#   Rscript --vanilla design/evidence/2026-09-24-handle-option-probes.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1, LibreSSL
# 3.3.6, zlib 1.2.12, no brotli or zstd), webfakes 1.5.0, macOS 26 (Darwin
# 25.6). Expected output is in the comment after each block. A different
# answer on another platform or version is a finding, not a failure of this
# script.

suppressMessages({
  library(curl)
  library(webfakes)
})
`%||%` <- function(a, b) if (is.null(a)) b else a

cat(
  "R",
  as.character(getRversion()),
  "curl",
  as.character(packageVersion("curl")),
  "libcurl",
  curl_version()$version,
  curl_version()$ssl_version,
  "\n"
)

app <- new_app()
app$get("/echo", function(req, res) {
  res$send(paste0(
    "ae=",
    req$get_header("Accept-Encoding") %||% "<none>",
    " cookie=",
    req$get_header("Cookie") %||% "<none>",
    " auth=",
    req$get_header("Authorization") %||% "<none>",
    " host=",
    req$get_header("Host")
  ))
})
app$get("/setcookie", function(req, res) {
  res$set_header("Set-Cookie", "sid=planted; Path=/")$send("set")
})
app$get("/auth", function(req, res) {
  a <- req$get_header("Authorization")
  if (is.null(a)) {
    res$set_status(401L)$set_header("WWW-Authenticate", 'Basic realm="x"')$send(
      "no"
    )
  } else {
    res$send(paste("auth=", a))
  }
})
app$get("/deflate", function(req, res) {
  res$set_header("Content-Encoding", "deflate")$set_header(
    "Content-Type",
    "text/plain"
  )$send(memCompress(charToRaw(strrep("A", 1000)), "gzip")) # zlib stream
})
app$get("/redir", function(req, res) res$redirect("/echo", 302L))
srv <- local_app_process(app, opts = server_opts(num_threads = 2))
port <- srv$get_port()
base <- paste0("http://127.0.0.1:", port)

try_fetch <- function(url, h) {
  tryCatch(curl_fetch_memory(url, handle = h), error = function(e) {
    conditionMessage(e)
  })
}
show <- function(label, r) {
  cat(sprintf(
    "%-52s %s\n",
    label,
    if (is.character(r)) {
      paste("ERROR:", sub("\n.*", "", r))
    } else {
      paste(r$status_code, rawToChar(r$content))
    }
  ))
}
quiet <- function(url, h) invisible(curl_fetch_memory(url, handle = h))

# 1. Request headers a new handle sends.
show("1  new_handle():", try_fetch(paste0(base, "/echo"), new_handle()))
# 200 ae=deflate, gzip cookie=<none> auth=<none> host=127.0.0.1:<port>

# 2. The cookie engine is on in every new handle. A Set-Cookie is replayed by
#    the same handle, not by a fresh one; cookiefile = NULL turns it off.
h <- new_handle()
quiet(paste0(base, "/setcookie"), h)
show("2a same handle after Set-Cookie:", try_fetch(paste0(base, "/echo"), h))
show("2b fresh handle:", try_fetch(paste0(base, "/echo"), new_handle()))
h <- new_handle()
handle_setopt(h, cookiefile = NULL)
quiet(paste0(base, "/setcookie"), h)
show("2c cookiefile = NULL, same handle:", try_fetch(paste0(base, "/echo"), h))
# 2a: cookie=sid=planted   2b: cookie=<none>   2c: cookie=<none>

# 3. netrc. With options(netrc = <file>) set before new_handle(), a netrc
#    `default` entry answers a 401 challenge from any host, inside one
#    transfer, with followlocation = 0 and unrestricted_auth = 0.
cat("3  getOption('netrc') at startup:", format(getOption("netrc")), "\n")
nf <- tempfile()
writeLines("default login ambient password s3cret", nf)
old <- options(netrc = nf)
h <- new_handle()
handle_setopt(h, followlocation = 0L, unrestricted_auth = 0L)
show("3a options(netrc), 401 Basic:", try_fetch(paste0(base, "/auth"), h))
h <- new_handle()
handle_setopt(h, netrc = 0L)
show("3b same, netrc = 0L:", try_fetch(paste0(base, "/auth"), h))
h <- new_handle()
handle_setopt(h, netrc = 0L)
handle_reset(h)
show("3c netrc = 0L, then handle_reset():", try_fetch(paste0(base, "/auth"), h))
options(old)
show("3d option unset:", try_fetch(paste0(base, "/auth"), new_handle()))
# 3 NULL | 3a 200 auth= Basic YW1iaWVudDpzM2NyZXQ= (ambient:s3cret)
# 3b 401 no | 3c 200 auth= Basic ... (reset re-read the option) | 3d 401 no

# 4. handle_reset() re-applies the package defaults: followlocation = 1.
h <- new_handle()
handle_setopt(h, followlocation = 0L)
show("4a followlocation = 0, /redir:", try_fetch(paste0(base, "/redir"), h))
handle_reset(h)
show("4b after handle_reset(), /redir:", try_fetch(paste0(base, "/redir"), h))
# 4a 302 ... | 4b 200 ae=deflate, gzip ... (the redirect was followed)

# 5. accept_encoding. The server always answers Content-Encoding: deflate
#    (1000 x "A"). Any non-NULL value decodes it, including "gzip" and
#    "identity"; only NULL delivers the compressed bytes.
enc <- function(label, ...) {
  h <- new_handle()
  handle_setopt(h, ...)
  r <- try_fetch(paste0(base, "/deflate"), h)
  cat(sprintf(
    "%-52s %s\n",
    label,
    if (is.character(r)) {
      paste("ERROR:", r)
    } else {
      paste(
        length(r$content),
        "bytes, decoded =",
        identical(r$content, charToRaw(strrep("A", 1000)))
      )
    }
  ))
}
enc("5a default:")
enc("5b accept_encoding = \"gzip\":", accept_encoding = "gzip")
enc("5c accept_encoding = \"identity\":", accept_encoding = "identity")
enc("5d accept_encoding = NULL:", accept_encoding = NULL)
h <- new_handle()
handle_setopt(h, accept_encoding = "identity")
show("5e header sent for \"identity\":", try_fetch(paste0(base, "/echo"), h))
# 5a-5c 1000 bytes, decoded = TRUE | 5d 17 bytes, decoded = FALSE
# 5e 200 ae=identity ...

# 6. resolve writes into the DNS cache of R's shared multi handle; connect_to
#    does not. Handle A pins; handle B is fresh, unpinned, dns_cache_timeout 0.
leak <- function(label, pin, host) {
  a <- new_handle(connecttimeout = 2, timeout = 3)
  handle_setopt(a, .list = pin)
  b <- new_handle(connecttimeout = 2, timeout = 3)
  handle_setopt(b, dns_cache_timeout = 0L)
  u <- sprintf("http://%s:%d/echo", host, port)
  show(paste(label, "A, pinned:"), try_fetch(u, a))
  show(paste(label, "B, fresh and unpinned:"), try_fetch(u, b))
}
leak(
  "6a resolve",
  list(resolve = sprintf("leak-r.invalid:%d:127.0.0.1", port)),
  "leak-r.invalid"
)
leak(
  "6b connect_to",
  list(connect_to = "leak-c.invalid::127.0.0.1:"),
  "leak-c.invalid"
)
op <- options(curl_interrupt = FALSE) # curl_easy_perform: a private multi
leak(
  "6c resolve, curl_interrupt = FALSE",
  list(resolve = sprintf("leak-p.invalid:%d:127.0.0.1", port)),
  "leak-p.invalid"
)
options(op)
# 6a A 200, B 200 (B reached 127.0.0.1 with no pin of its own)
# 6b A 200, B ERROR: Could not resolve hostname [leak-c.invalid]
# 6c A 200, B ERROR: Could not resolve hostname [leak-p.invalid]

# 7. An empty HOST field matches every host.
h <- new_handle(connecttimeout = 2, timeout = 3)
handle_setopt(h, connect_to = "::127.0.0.1:")
show(
  "7  connect_to = \"::127.0.0.1:\":",
  try_fetch(sprintf("http://any-host.invalid:%d/echo", port), h)
)
# 200 ... host=any-host.invalid:<port>

# 8. ipresolve does not override a literal connect_to target.
h <- new_handle(connecttimeout = 2, timeout = 3)
handle_setopt(h, connect_to = "fam.invalid::127.0.0.1:", ipresolve = 2L) # CURL_IPRESOLVE_V6
show(
  "8  IPv4 literal pin + ipresolve = V6:",
  try_fetch(sprintf("http://fam.invalid:%d/echo", port), h)
)
# 200 ... (the pin is used)

# 9. HTTP/3 and share.
r <- tryCatch(
  {
    handle_setopt(new_handle(), http_version = 30L)
    "accepted"
  },
  error = function(e) conditionMessage(e)
)
cat("9a http_version = 30L (HTTP/3):", r, "\n")
r <- tryCatch(
  {
    handle_setopt(new_handle(), share = 1L)
    "accepted"
  },
  error = function(e) conditionMessage(e)
)
cat("9b share = 1L:", r, "\n")
# 9a Invalid or unsupported value when setting curl option 'http_version'
# 9b Value for option share (10015) must be a string or raw vector.
