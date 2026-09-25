# Probes behind r-binding.md §7 (test layers) and its hard limits: pinning to a
# loopback app under a .invalid name, per-hop redirects, maxfilesize, timeouts,
# a raw base-R listener, mocking the resolver, and webfakes' refusal to bind ::1
# (fp SSRF-ssldkvmd).
#
# Ported from research/09 (§2.4, §2.6, §4.2-§4.6 and Appendix A: EXP1-EXP7,
# A.2, A.5-A.7), run on 2026-07-25 with R 4.6.0, curl 7.1.0, libcurl 8.14.1
# (LibreSSL 3.3.6), webfakes 1.5.0, testthat 3.3.2, macOS / Darwin 25.4.0. The
# July throwaway-package suite (A.1) and the TLS probe (A.4) are not here; A.4
# is in 2026-09-24-tls-pin-probes.R.
#
# Run from the repository root with curl, webfakes, testthat, callr and pkgload
# installed. No network access is needed.
#   Rscript design/evidence/2026-09-24-hermetic-test-probes.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1, LibreSSL
# 3.3.6), webfakes 1.5.0, testthat 3.3.2, callr 3.8.0, pkgload 1.5.3, macOS 26
# (Darwin 25.6). Expected output is in the comment after each block; "July:"
# marks where the 2026-07-25 result differed. A different answer on another
# platform or version is a finding, not a failure of this script.

suppressMessages({
  library(curl)
  library(webfakes)
})

err <- function(expr) {
  tryCatch(
    {
      force(expr)
      "no error"
    },
    error = function(e) gsub("\n", " ", conditionMessage(e))
  )
}

# A.2. Capability probe.
v <- curl_version()
cat(
  "libcurl",
  v$version,
  "ssl",
  v$ssl_version,
  "ipv6",
  v$ipv6,
  "http2",
  v$http2,
  "ares",
  if (is.null(v$ares)) "absent" else v$ares,
  "\n"
)
grep(
  "^(connect_to|resolve|dns_|doh_url|fresh_connect|happy_eyeballs|ipresolve|resolver_start)",
  names(curl_options()),
  value = TRUE
)
args(nslookup)
err(handle_setopt(new_handle(), connect_to = "v6.invalid:443:[::1]:443"))
err(handle_setopt(new_handle(), connect_to = "v6.invalid::[::1]:"))
err(handle_setopt(new_handle(), resolve = "a.invalid:80:127.0.0.1,127.0.0.2"))
err(handle_setopt(new_handle(), dns_servers = "127.0.0.1:5353"))
# libcurl 8.14.1 ssl LibreSSL/3.3.6 (SecureTransport) ipv6 TRUE http2 TRUE
# ares absent. connect_to, resolve, dns_cache_timeout, dns_servers, doh_url,
# resolver_start_function ... all listed. nslookup(host, ipv4_only = FALSE,
# multiple = FALSE, error = TRUE). Both IPv6 connect_to spellings and the
# multi-address resolve are accepted ("no error"); dns_servers: "Invalid or
# unsupported value when setting curl option 'dns_servers'". Accepted is not
# honoured: the bracketed IPv6 pin is still unverified end to end (A.7).

# The app used by EXP1-EXP7.
app <- new_app()
app$get("/echo", function(req, res) {
  res$send(paste0("host=", req$get_header("Host")))
})
app$get("/hop1", function(req, res) res$redirect("/hop2", 302L))
app$get("/hop2", function(req, res) {
  res$redirect("http://blocked.example:1/x", 302L)
})
app$get("/big", function(req, res) res$send(strrep("x", 200000)))
app$get("/chunked", function(req, res) {
  for (i in 1:50) {
    res$send_chunk(strrep("y", 5000))
  }
})
app$get("/slow", function(req, res) {
  if (is.null(res$locals$s)) {
    res$locals$s <- TRUE
    res$delay(2)
  } else {
    res$send("late")
  }
})
web <- local_app_process(app, opts = server_opts(num_threads = 2))
port <- web$get_port()
show <- function(u, ...) {
  tryCatch(
    {
      r <- curl_fetch_memory(u, handle = new_handle(...))
      sprintf(
        "status %d body %s url %s",
        r$status_code,
        rawToChar(r$content),
        r$url
      )
    },
    error = function(e) gsub("\n", " ", conditionMessage(e))
  )
}

# EXP1-EXP3. The pinning proof and its negative control: .invalid never
# resolves (RFC 2606), so arrival at the app proves the pin was used.
show(
  sprintf("http://pinned.example.invalid:%d/echo", port),
  connect_to = "pinned.example.invalid::127.0.0.1:"
)
show(
  sprintf("http://pinned2.example.invalid:%d/echo", port),
  resolve = sprintf("pinned2.example.invalid:%d:127.0.0.1", port)
)
show(sprintf("http://pinned.example.invalid:%d/echo", port), timeout_ms = 3000)
# EXP1: status 200 body host=pinned.example.invalid:<port>, url unchanged.
# EXP2: status 200 body host=pinned2.example.invalid:<port>.
# EXP3: "Could not resolve hostname [pinned.example.invalid]: Could not
#       resolve host: pinned.example.invalid".

# EXP4-EXP6. maxfilesize and timeouts.
show(web$url("/big"), maxfilesize = 1000)
show(web$url("/chunked"), maxfilesize = 1000)
t0 <- Sys.time()
show(web$url("/slow"), timeout_ms = 500)
round(as.numeric(Sys.time() - t0, units = "secs"), 1)
# EXP4: "Maximum file size exceeded" (refused up front from Content-Length).
# EXP5: "Maximum file size exceeded ... Exceeded the maximum allowed file size
#       (1000) with 1000 bytes" (refused mid-stream, uncompressed chunks).
# EXP6: "Timeout was reached ... Operation timed out after 503 milliseconds
#       with 0 bytes received", elapsed 0.5 s.
# maxfilesize counts wire bytes; a compressed body that inflates past the cap
# is not tested here (r-binding.md §5 "advisory").

# EXP7. With followlocation off, each hop and its Location are visible.
hop <- function(path) {
  r <- curl_fetch_memory(
    sprintf("http://127.0.0.1:%d%s", port, path),
    handle = new_handle(followlocation = 0L)
  )
  sprintf(
    "status %d Location %s",
    r$status_code,
    parse_headers_list(r$headers)[["location"]]
  )
}
hop("/hop1")
hop("/hop2")
# "status 302 Location /hop2"; "status 302 Location http://blocked.example:1/x"

# A.5. A raw base-R listener receives the pinned request. serverSocket() has
#      no host argument and cannot report an ephemeral port, so probe for one.
free_port <- function() {
  for (p in sample(30000:60000, 20)) {
    s <- tryCatch(serverSocket(p), error = function(e) NULL)
    if (!is.null(s)) {
      close(s)
      return(p)
    }
  }
  stop("no free port")
}
s0 <- serverSocket(0L)
summary(s0)$description
close(s0)
lp <- free_port()
srv <- serverSocket(lp)
px <- callr::r_bg(
  function(port) {
    rawToChar(
      curl::curl_fetch_memory(
        sprintf("http://pinned.example.invalid:%d/probe-path", port),
        handle = curl::new_handle(
          connect_to = "pinned.example.invalid::127.0.0.1:",
          timeout_ms = 4000
        )
      )$content
    )
  },
  args = list(port = lp)
)
if (socketSelect(list(srv), timeout = 6)) {
  con <- socketAccept(srv, blocking = TRUE, open = "r+b", timeout = 6)
  hdr <- character()
  repeat {
    l <- readLines(con, n = 1L, warn = FALSE)
    if (!length(l) || l == "") {
      break
    }
    hdr <- c(hdr, l)
  }
  writeChar(
    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nPINNED",
    con,
    eos = NULL
  )
  flush(con)
  close(con)
  px$wait(5000)
  print(hdr)
  cat("client got:", px$get_result(), "\n")
}
close(srv)
# summary(serverSocket(0))$description: "localhost" (no port introspection).
# "GET /probe-path HTTP/1.1" "Host: pinned.example.invalid:<port>"
# "User-Agent: R (4.6.0 aarch64-apple-darwin23 aarch64 darwin25.6.0)"
# "Accept: */*" "Accept-Encoding: deflate, gzip"; client got: PINNED.
# July: "User-Agent: curl/8.20.0" and no Accept-Encoding line; the July note
# does not record which client sent the request.

# A.6. Mocking the resolver. Four call styles in a throwaway package, and the
#      namespace mechanism underneath. Mocking curl's namespace works for
#      curl::nslookup() calls, not for an importFrom'd bare call; an internal
#      wrapper mocks cleanly with no public seam.
pkg <- file.path(tempfile(), "fakeguard")
dir.create(file.path(pkg, "R"), recursive = TRUE)
writeLines(
  c(
    "Package: fakeguard",
    "Version: 0.0.1",
    "Title: Probe",
    "Description: Probe.",
    "License: MIT",
    "Imports: curl"
  ),
  file.path(pkg, "DESCRIPTION")
)
writeLines(
  c(
    "importFrom(curl, nslookup)",
    "export(colon_call, bare_call, wrapped_call, inject_call)"
  ),
  file.path(pkg, "NAMESPACE")
)
writeLines(
  c(
    "colon_call <- function(h) curl::nslookup(h)",
    "bare_call <- function(h) nslookup(h)",
    "resolve_host <- function(h) curl::nslookup(h)",
    "wrapped_call <- function(h) resolve_host(h)",
    "inject_call <- function(h, .resolver = resolve_host) .resolver(h)"
  ),
  file.path(pkg, "R", "f.R")
)
suppressMessages(pkgload::load_all(pkg, quiet = TRUE, export_all = FALSE))
fake <- function(h) "203.0.113.5"
m <- function(expr) {
  tryCatch(expr, error = function(e) paste("real ran:", conditionMessage(e)))
}
c(
  colon = m(testthat::with_mocked_bindings(
    colon_call("x.invalid"),
    nslookup = fake,
    .package = "curl"
  )),
  bare = m(testthat::with_mocked_bindings(
    bare_call("x.invalid"),
    nslookup = fake,
    .package = "curl"
  )),
  wrapper = m(testthat::with_mocked_bindings(
    wrapped_call("x.invalid"),
    resolve_host = fake,
    .package = "fakeguard"
  )),
  inject = m(inject_call("x.invalid", .resolver = fake))
)
cns <- asNamespace("curl")
c(environmentIsLocked(cns), bindingIsLocked("nslookup", cns))
orig <- get("nslookup", envir = cns)
unlockBinding("nslookup", cns)
assign("nslookup", function(...) "MANUAL", envir = cns)
curl::nslookup("x.invalid")
assign("nslookup", orig, envir = cns)
lockBinding("nslookup", cns)
# colon 203.0.113.5; bare "real ran: Unable to resolve host: x.invalid";
# wrapper 203.0.113.5; inject 203.0.113.5. TRUE TRUE; "MANUAL".
# (Outside a test run .package must name the package; inside testthat it is
# detected, which is how r-binding.md §7's L1 uses it.)

# A.7. webfakes cannot bind ::1 (r-binding.md §4.4, §7).
#      Where a spec starts, ask whether anything answers on [::1].
v6_answers <- function(p) {
  r <- tryCatch(
    curl_fetch_memory(
      sprintf("http://[::1]:%d/echo", p),
      handle = new_handle(timeout = 2)
    )$status_code,
    error = function(e) "no"
  )
  paste("[::1] answers:", r)
}
for (spec in list(
  list(interfaces = "::1"),
  list(interfaces = "[::1]"),
  list(port = "[::1]:0"),
  list(interfaces = "[::1]", port = free_port())
)) {
  r <- tryCatch(
    {
      s <- local_app_process(app, opts = do.call(server_opts, spec))
      paste("started at", s$url(), "/", v6_answers(s$get_port()))
    },
    error = function(e) {
      sub(
        ".*(invalid port spec[^[]*\\[IP_ADDRESS:\\]PORT\\[s\\|r\\]).*",
        "\\1",
        gsub("\n", " ", conditionMessage(e))
      )
    }
  )
  cat(deparse(spec), "->", r, "\n")
}
# interfaces = "::1", interfaces = "[::1]", interfaces = "[::1]" + fixed port:
# "invalid port spec (entry 1). Expecting list of: [IP_ADDRESS:]PORT[s|r]".
# port = "[::1]:0": "started at http://127.0.0.1:<port>/ / [::1] answers: no"
# (the spec is accepted but the app binds IPv4 loopback only).
# July: port = "[::1]:0" failed with the invalid-port-spec error too. Either
# way no spec binds ::1, so the limit in r-binding.md §7 stands.
