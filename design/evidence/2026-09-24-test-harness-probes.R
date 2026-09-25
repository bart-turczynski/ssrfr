# Test-harness probes behind r-binding.md §4.4 (IPv6) and §7 (rules, harness
# notes, hard limits): an IPv6 pin to an httpuv server on ::1, SNI proven by a
# two-vhost TLS server, the resolve-time mocking rule and the namespace-walk
# tripwire, L0 doing no I/O, a listener that sees a bare TCP connect, protocol
# refusal under protocols_str, and how testthat and R CMD check report skips
# (fp SSRF-aylqwknz).
#
# New on 2026-09-24. Everything the blocks need (certificates, a throwaway
# package, a throwaway test directory) is generated in tempdir() at run time;
# no key material is committed.
#
# Run from the repository root with curl, testthat and callr installed. No
# network access is needed: servers bind loopback or listen on a free local
# port, and every hostname is an RFC 2606 .invalid name. Optional tools, each
# skipped with a printed note when missing: httpuv (block 1), the openssl
# command-line tool and processx (block 2), lsof (block 6), rcmdcheck
# (block 9, which runs four package checks; the whole script takes about 35 s
# with it, 5 s without).
#   Rscript --vanilla design/evidence/2026-09-24-test-harness-probes.R
#
# Recorded environment: R 4.6.0, curl 8.0.0 (bundled libcurl 8.14.1, LibreSSL
# 3.3.6), httpuv 1.6.17, testthat 3.3.2, callr 3.8.0, processx 3.9.0,
# rcmdcheck 1.4.0, openssl CLI 3.6.4 (Homebrew) and /usr/bin/openssl
# (LibreSSL 3.3.6), macOS 26 (Darwin 25.6). Expected output is in the comment
# after each block, with ports elided as <port> and temporary paths as <tmp>.
# A different answer on another platform or version is a finding, not a
# failure of this script.

suppressMessages({
  library(curl)
  library(testthat)
})
Sys.unsetenv("NOT_CRAN")

cat(
  "curl",
  as.character(packageVersion("curl")),
  "libcurl",
  curl_version()$version,
  curl_version()$ssl_version,
  "ipv6",
  curl_version()$ipv6,
  "\n"
)

has <- function(pkg) requireNamespace(pkg, quietly = TRUE)
free_port <- function() {
  for (p in sample(30000:60000, 50)) {
    s <- tryCatch(serverSocket(p), error = function(e) NULL)
    if (!is.null(s)) {
      close(s)
      return(p)
    }
  }
  stop("no free port")
}
# Wait up to `secs` for a pending connection on a serverSocket() listener.
# Polls, because a single socketSelect() call returned FALSE at once in this
# script (see block 6).
pending <- function(srv, secs) {
  t0 <- Sys.time()
  repeat {
    if (socketSelect(list(srv), timeout = 0.2)) {
      return(TRUE)
    }
    if (difftime(Sys.time(), t0, units = "secs") >= secs) return(FALSE)
  }
}
# Fetch with a verbose handle; return the result (or error) and the text trace.
trace_fetch <- function(url, ...) {
  log <- character()
  h <- new_handle(
    timeout = 5,
    forbid_reuse = 1L,
    verbose = TRUE,
    ...,
    debugfunction = function(type, msg) {
      if (type == 0L) {
        log <<- c(log, trimws(rawToChar(msg)))
      }
      NULL
    }
  )
  r <- tryCatch(curl_fetch_memory(url, handle = h), error = function(e) {
    gsub("\n", " ", conditionMessage(e))
  })
  list(result = r, log = log)
}
tmp <- tempfile("harness-")
dir.create(tmp)

# 1. IPv6 pin to httpuv on ::1 (r-binding.md §4.4; webfakes cannot bind ::1,
#    see 2026-09-24-hermetic-test-probes.R). The server runs in this process;
#    a callr child fetches through connect_to = "v6pin.invalid::[::1]:" and
#    then the bracketed literal directly.
srv <- NULL
if (!has("httpuv") || !has("callr")) {
  cat("block 1 skipped: httpuv or callr is not installed\n")
} else if (!isTRUE(curl_version()$ipv6)) {
  cat("block 1 skipped: this libcurl has no IPv6\n")
} else {
  v6port <- httpuv::randomPort()
  srv <- tryCatch(
    httpuv::startServer(
      "::1",
      v6port,
      list(call = function(req) {
        list(
          status = 200L,
          headers = list("Content-Type" = "text/plain"),
          body = paste0(
            "host=",
            req$HTTP_HOST,
            " remote_addr=",
            req$REMOTE_ADDR
          )
        )
      })
    ),
    error = function(e) NULL
  )
  if (is.null(srv)) cat("block 1 skipped: could not bind ::1\n")
}
if (!is.null(srv)) {
  px <- callr::r_bg(
    function(port) {
      log <- character()
      h <- curl::new_handle(
        connect_to = "v6pin.invalid::[::1]:",
        timeout = 5,
        verbose = TRUE,
        debugfunction = function(type, msg) {
          if (type == 0L) {
            log <<- c(log, trimws(rawToChar(msg)))
          }
          NULL
        }
      )
      get <- function(u, h) {
        tryCatch(
          rawToChar(curl::curl_fetch_memory(u, handle = h)$content),
          error = function(e) conditionMessage(e)
        )
      }
      c(
        pinned = get(sprintf("http://v6pin.invalid:%d/", port), h),
        grep("^(Trying|Connected)", log, value = TRUE),
        direct = get(
          sprintf("http://[::1]:%d/", port),
          curl::new_handle(timeout = 5)
        )
      )
    },
    args = list(port = v6port)
  )
  t0 <- Sys.time()
  while (px$is_alive() && difftime(Sys.time(), t0, units = "secs") < 15) {
    httpuv::service(100)
  }
  print(px$get_result())
  httpuv::stopServer(srv)
}
# pinned: "host=v6pin.invalid:<port> remote_addr="
# "Trying [::1]:<port>..." "Connected to ::1 (::1) port <port>"
# direct: "host=[::1]:<port> remote_addr="
# The pin reaches ::1 with the hostname intact in Host. httpuv leaves
# REMOTE_ADDR empty for this IPv6 peer, so a test cannot read the peer there.

# 2. Two-vhost SNI (INV-9, r-binding.md §7). A throwaway CA and certificates
#    for alpha.example.invalid and beta.example.invalid, DNS SANs only, are
#    generated in tempdir(). `openssl s_server -www` serves alpha by default
#    and beta to a ClientHello whose SNI is beta.example.invalid.
openssl <- Sys.which("openssl")
for (bin in unique(c(
  openssl,
  if (file.exists("/usr/bin/openssl")) "/usr/bin/openssl"
))) {
  if (!nzchar(bin)) {
    next
  }
  help <- suppressWarnings(system2(
    bin,
    c("s_server", "-help"),
    stdout = TRUE,
    stderr = TRUE
  ))
  cat(
    bin,
    "|",
    system2(bin, "version", stdout = TRUE),
    "| s_server has",
    vapply(
      c("-servername", "-cert2", "-key2"),
      function(o) any(grepl(paste0("^\\s*", o, "\\b"), help)),
      logical(1)
    ),
    "\n"
  )
}
if (!nzchar(openssl) || !has("processx")) {
  cat("block 2 skipped: the openssl command-line tool or processx is missing\n")
} else {
  pki <- file.path(tmp, "pki")
  dir.create(pki)
  f <- function(x) file.path(pki, x)
  ossl <- function(...) {
    out <- suppressWarnings(system2(
      openssl,
      c(...),
      stdout = TRUE,
      stderr = TRUE
    ))
    if (!is.null(attr(out, "status"))) stop(paste(out, collapse = "\n"))
  }
  writeLines(
    c(
      "[req]",
      "distinguished_name = dn",
      "prompt = no",
      "x509_extensions = v3_ca",
      "[dn]",
      "CN = probe-ca",
      "[v3_ca]",
      "basicConstraints = critical,CA:TRUE",
      "keyUsage = critical,keyCertSign,cRLSign",
      "subjectKeyIdentifier = hash"
    ),
    f("ca.cnf")
  )
  ossl(
    "req",
    "-x509",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-sha256",
    "-days",
    "2",
    "-config",
    f("ca.cnf"),
    "-keyout",
    f("ca.key"),
    "-out",
    f("ca.crt")
  )
  for (h in c("alpha", "beta")) {
    host <- paste0(h, ".example.invalid")
    writeLines(
      c(
        "[req]",
        "distinguished_name = dn",
        "prompt = no",
        "[dn]",
        paste("CN =", host)
      ),
      f(paste0(h, ".cnf"))
    )
    writeLines(paste0("subjectAltName = DNS:", host), f(paste0(h, ".ext")))
    ossl(
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-config",
      f(paste0(h, ".cnf")),
      "-keyout",
      f(paste0(h, ".key")),
      "-out",
      f(paste0(h, ".csr"))
    )
    ossl(
      "x509",
      "-req",
      "-sha256",
      "-days",
      "2",
      "-in",
      f(paste0(h, ".csr")),
      "-CA",
      f("ca.crt"),
      "-CAkey",
      f("ca.key"),
      "-CAcreateserial",
      "-extfile",
      f(paste0(h, ".ext")),
      "-out",
      f(paste0(h, ".crt"))
    )
  }
  tls_port <- free_port()
  serve <- function(two) {
    a <- c(
      "s_server",
      "-accept",
      tls_port,
      "-quiet",
      "-www",
      "-cert",
      f("alpha.crt"),
      "-key",
      f("alpha.key")
    )
    if (two) {
      a <- c(
        a,
        "-servername",
        "beta.example.invalid",
        "-cert2",
        f("beta.crt"),
        "-key2",
        f("beta.key")
      )
    }
    p <- processx::process$new(openssl, a, stdout = "|", stderr = "|")
    for (i in 1:50) {
      # wait until it listens
      up <- tryCatch(
        {
          curl_fetch_memory(
            sprintf("http://127.0.0.1:%d/", tls_port),
            handle = new_handle(connect_only = TRUE, timeout = 1)
          )
          TRUE
        },
        error = function(e) FALSE
      )
      if (up) {
        break
      }
      Sys.sleep(0.1)
    }
    p
  }
  sni <- function(url, ...) {
    t <- trace_fetch(url, cainfo = f("ca.crt"), ...)
    r <- if (is.character(t$result)) {
      t$result
    } else {
      sprintf("status %d", t$result$status_code)
    }
    paste(r, "|", paste(grep("^subject:", t$log, value = TRUE), collapse = " "))
  }
  pin <- function(host) sprintf("%s::127.0.0.1:", host)
  u <- function(host) sprintf("https://%s:%d/", host, tls_port)
  p <- serve(TRUE)
  cat(
    "A alpha pinned:          ",
    sni(u("alpha.example.invalid"), connect_to = pin("alpha.example.invalid")),
    "\n"
  )
  cat(
    "B beta pinned:           ",
    sni(u("beta.example.invalid"), connect_to = pin("beta.example.invalid")),
    "\n"
  )
  cat(
    "C IP URL + Host: beta:   ",
    sni(u("127.0.0.1"), httpheader = "Host: beta.example.invalid"),
    "\n"
  )
  invisible(p$kill())
  p <- serve(FALSE)
  cat(
    "D beta pinned, alpha only:",
    sni(u("beta.example.invalid"), connect_to = pin("beta.example.invalid")),
    "\n"
  )
  invisible(p$kill())
}
# /opt/homebrew/bin/openssl | OpenSSL 3.6.4 25 Aug 2026 (Library: OpenSSL 3.6.4
#   25 Aug 2026) | s_server has TRUE TRUE TRUE
# /usr/bin/openssl | LibreSSL 3.3.6 | s_server has TRUE TRUE TRUE
# A alpha pinned:           status 200 | subject: CN=alpha.example.invalid
# B beta pinned:            status 200 | subject: CN=beta.example.invalid
# C IP URL + Host: beta:    SSL peer certificate or SSH remote key was not OK
#   [127.0.0.1]: SSL: no alternative certificate subject name matches target
#   ipv4 address '127.0.0.1' | subject: CN=alpha.example.invalid
# D beta pinned, alpha only: SSL peer certificate or SSH remote key was not OK
#   [beta.example.invalid]: SSL: no alternative certificate subject name
#   matches target hostname 'beta.example.invalid' | subject:
#   CN=alpha.example.invalid
# B passes only because the pinned request carried beta in its SNI; D is the
# control. C: an IP literal sends no SNI, so it gets the default certificate.

# A throwaway package with the two I/O seams the §7 rules name: an internal
# resolver wrapper and an internal fetch. Installed into a library in tempdir.
pkg <- file.path(tmp, "probepkg")
dir.create(file.path(pkg, "R"), recursive = TRUE)
writeLines(
  c(
    "Package: probepkg",
    "Version: 0.0.1",
    "Title: Probe",
    "Description: Probe.",
    "License: MIT",
    "Imports: curl",
    "Encoding: UTF-8"
  ),
  file.path(pkg, "DESCRIPTION")
)
writeLines(
  "export(policy_early, lookup_early, lookup_late, classify_l0, fetch_guarded)",
  file.path(pkg, "NAMESPACE")
)
writeLines(
  c(
    "resolve_host <- function(host) curl::nslookup(host, multiple = TRUE)",
    "# early: the function value is captured when the policy is built",
    "policy_early <- function(resolver = resolve_host) list(resolver = resolver)",
    "lookup_early <- function(policy, host) policy$resolver(host)",
    "# late: the binding is looked up at the point of use",
    "lookup_late <- function(host) resolve_host(host)",
    "classify_l0 <- function(url) list(scheme = sub(':.*', '', url))",
    "perform_guarded <- function(url, h) curl::curl_fetch_memory(url, handle = h)",
    "fetch_guarded <- function(url) {",
    "  h <- curl::new_handle(connect_to = 'x::127.0.0.1:')",
    "  perform_guarded(url, h)",
    "}",
    "sneaky <- function(u) { inner <- function() curl::curl_fetch_disk(u, tempfile()); inner }"
  ),
  file.path(pkg, "R", "code.R")
)
lib <- file.path(tmp, "lib")
dir.create(lib)
inst <- system2(
  file.path(R.home("bin"), "R"),
  c("CMD", "INSTALL", "--no-test-load", "-l", shQuote(lib), shQuote(pkg)),
  stdout = TRUE,
  stderr = TRUE
)
library(probepkg, lib.loc = lib)

# 3. Look the resolver up at call time (r-binding.md §7). A policy object
#    built before local_mocked_bindings() captured the real resolver; one
#    built inside the mock, or a late lookup by name, gets the mock.
fake <- function(host) "203.0.113.5"
pol <- policy_early()
test_that("resolve-time rule", {
  local_mocked_bindings(resolve_host = fake, .package = "probepkg")
  cat(
    "\nearly, policy built before the mock:",
    tryCatch(lookup_early(pol, "x.invalid"), error = function(e) {
      paste("REAL RESOLVER RAN:", conditionMessage(e))
    }),
    "\nearly, policy built inside the mock:",
    lookup_early(policy_early(), "x.invalid"),
    "\nlate lookup:",
    lookup_late("x.invalid"),
    "\n"
  )
  succeed()
})
# early, policy built before the mock: REAL RESOLVER RAN: Unable to resolve
#   host: x.invalid
# early, policy built inside the mock: 203.0.113.5
# late lookup: 203.0.113.5
# Test passed with 1 success.

# 4. Tripwires (r-binding.md §7). handle_data() does not return the options
#    set on a handle, so a test cannot read the pin back from it. The
#    namespace walk over the installed package, base R only, flags each
#    closure whose body names a network entry point, nested closures included.
names(handle_data(new_handle(connect_to = "x.invalid::127.0.0.1:", proxy = "")))
ns <- asNamespace("probepkg")
fns <- Filter(is.function, mget(ls(ns, all.names = TRUE), envir = ns))
net <- c(
  "curl_fetch_memory",
  "curl_fetch_disk",
  "curl_fetch_stream",
  "curl_fetch_multi",
  "curl",
  "curl_download",
  "multi_add",
  "new_handle",
  "handle_setopt",
  "nslookup",
  "ie_get_proxy_for_url",
  "url",
  "download.file",
  "socketConnection"
)
walk <- function(names_of) {
  hits <- vapply(
    fns,
    function(f) paste(intersect(names_of(body(f)), net), collapse = ","),
    ""
  )
  hits[nzchar(hits)]
}
# Every symbol in the body, called or not.
walk(all.names)
# Only names in call position, with pkg::fun reduced to fun.
heads <- function(e) {
  if (is.pairlist(e) || is.list(e)) {
    return(unlist(lapply(e, heads)))
  }
  if (!is.call(e)) {
    return(character())
  }
  h <- e[[1]]
  nm <- if (is.name(h)) {
    as.character(h)
  } else if (is.call(h) && as.character(h[[1]]) %in% c("::", ":::")) {
    as.character(h[[3]])
  }
  c(nm, heads(as.list(e)[-1]))
}
walk(heads)
# "url" "status_code" "type" "headers" "modified" "times" "scheme"
# "http_version" "method" (no options)
# all.names: classify_l0 "url"; fetch_guarded "curl,new_handle,url";
#   perform_guarded "curl,curl_fetch_memory,url"; resolve_host "curl,nslookup";
#   sneaky "curl,curl_fetch_disk" (the nested closure).
# heads: fetch_guarded "new_handle"; perform_guarded "curl_fetch_memory";
#   resolve_host "nslookup"; sneaky "curl_fetch_disk".
# all.names() catches the nested closure but also matches plain symbols: every
# curl:: prefix hits "curl", and an argument named url hits base url(). The
# call-position walk, still base R, flags only real calls.

# 5. L0 does no I/O (ssrfr-v1.md §1). Both seams mocked to stop(): the L0
#    function passes, and the fetching path trips the mock.
test_that("L0 does no I/O", {
  local_mocked_bindings(
    resolve_host = function(...) stop("L0 resolved"),
    perform_guarded = function(...) stop("L0 fetched"),
    .package = "probepkg"
  )
  expect_no_error(classify_l0("http://x.invalid/"))
  expect_error(fetch_guarded("http://x.invalid/"), "L0 fetched")
})
# Test passed with 2 successes.

# 6. A refusal makes no connection (INV-11). A raw serverSocket() listener sees
#    a bare TCP connect before any byte arrives: socketSelect() is FALSE with
#    no client and TRUE after a child's connect_only fetch. lsof shows what the
#    listener binds.
lp <- free_port()
ls_srv <- serverSocket(lp)
cat(
  "no client, one select:",
  socketSelect(list(ls_srv), timeout = 1),
  "| polled for 1 s:",
  pending(ls_srv, 1),
  "\n"
)
if (nzchar(Sys.which("lsof"))) {
  cat(
    grep(
      "LISTEN",
      system2(
        "lsof",
        c("-nP", sprintf("-iTCP:%d", lp), "-sTCP:LISTEN"),
        stdout = TRUE
      ),
      value = TRUE
    ),
    "\n"
  )
} else {
  cat("lsof check skipped: lsof is not installed\n")
}
if (has("callr")) {
  px <- callr::r_bg(
    function(lp) {
      h <- curl::new_handle(
        connect_only = TRUE,
        connect_to = "honeypot.invalid::127.0.0.1:",
        timeout = 3
      )
      tryCatch(
        {
          curl::curl_fetch_memory(
            sprintf("http://honeypot.invalid:%d/", lp),
            handle = h
          )
          "connected"
        },
        error = function(e) conditionMessage(e)
      )
    },
    args = list(lp = lp)
  )
  t0 <- Sys.time()
  one <- socketSelect(list(ls_srv), timeout = 5)
  cat(sprintf(
    "bare TCP connect, one select: %s after %.2f s | polled for 5 s: %s\n",
    one,
    as.numeric(difftime(Sys.time(), t0, units = "secs")),
    pending(ls_srv, 5)
  ))
  px$wait()
  cat("client:", px$get_result(), "\n")
} else {
  cat("connect half skipped: callr is not installed\n")
}
close(ls_srv)
# no client, one select: FALSE | polled for 1 s: FALSE
# R <pid> <user> <fd>u IPv4 0x... 0t0 TCP *:<port> (LISTEN)   (every IPv4
#   interface, not only loopback)
# bare TCP connect, one select: FALSE after 0.00 s | polled for 5 s: TRUE
# client: connected
# The listener does see the bare connect, but a single socketSelect(timeout =
# 5) returned FALSE at once, before the child had connected, on every run of
# this whole script (also with block 2 skipped), while the same block run on
# its own gets TRUE from one select. The cause is not isolated. A no-connect
# assertion must therefore poll for its whole window: one FALSE select can be
# vacuous.

# 7. Protocols under protocols_str (r-binding.md §5, §7). Every compiled-in
#    scheme except http and https, fetched with protocols_str = "http,https".
p <- curl_version()$protocols
cat(length(p), "compiled in\n")
res <- vapply(
  setdiff(p, c("http", "https")),
  function(s) {
    h <- new_handle(protocols_str = "http,https", timeout = 3)
    tryCatch(
      {
        curl_fetch_memory(sprintf("%s://x.invalid/", s), handle = h)
        "FETCHED"
      },
      error = function(e) {
        gsub("\n", " ", sub(" \\[.*", "", conditionMessage(e)))
      }
    )
  },
  ""
)
print(table(res))
names(res)[res != "Unsupported protocol"]
# 24 compiled in
# "Unsupported protocol" 21; "URL using bad/illegal format or missing URL: URL
#   rejected: Bad file:// URL" 1
# "file": file://x.invalid/ fails libcurl's URL parse before protocols_str
# applies, so it proves nothing about protocols_str.

# 8. How testthat reports skips (r-binding.md §7, the skip rule). A throwaway
#    test directory: a pass, skip(), a test with no expectations, and
#    skip_on_cran(), run with NOT_CRAN unset and then set to "true".
tdir <- file.path(tmp, "tdir")
dir.create(tdir)
writeLines(
  c(
    'test_that("passes", expect_true(TRUE))',
    'test_that("skips", { skip("no webfakes"); expect_true(TRUE) })',
    'test_that("empty", { NULL })',
    'test_that("skip_on_cran", { skip_on_cran(); expect_true(TRUE) })'
  ),
  file.path(tdir, "test-a.R")
)
for (nc in c(NA, "true")) {
  if (is.na(nc)) {
    Sys.unsetenv("NOT_CRAN")
  } else {
    Sys.setenv(NOT_CRAN = nc)
  }
  r <- as.data.frame(test_dir(
    tdir,
    reporter = "silent",
    stop_on_failure = FALSE
  ))
  cat(sprintf(
    "NOT_CRAN=%-6s on_cran()=%-5s skipped: %s\n",
    if (is.na(nc)) "unset" else nc,
    testthat:::on_cran(),
    paste(r$test, r$skipped, sep = "=", collapse = " ")
  ))
}
Sys.unsetenv("NOT_CRAN")
# NOT_CRAN=unset  on_cran()=TRUE  skipped: passes=FALSE skips=TRUE empty=TRUE
#   skip_on_cran=TRUE
# NOT_CRAN=true   on_cran()=FALSE skipped: passes=FALSE skips=TRUE empty=TRUE
#   skip_on_cran=FALSE

# 9. R CMD check and skips (r-binding.md §7, harness notes). A throwaway
#    package with a skip_on_cran() test, a skip_if_not_installed("webfakes")
#    test and a test that reports .libPaths(). Checked four ways: the verify
#    hook's --as-cran call with NOT_CRAN unset, the same with NOT_CRAN=true,
#    and without --as-cran under _R_CHECK_DEPENDS_ONLY_=true, then with
#    _R_CHECK_NO_RECOMMENDED_=true as well. The CRAN-incoming remote checks
#    and the clock check are turned off to keep the run offline.
if (!has("rcmdcheck")) {
  cat("block 9 skipped: rcmdcheck is not installed\n")
} else {
  sp <- file.path(tmp, "skippkg")
  dir.create(file.path(sp, "R"), recursive = TRUE)
  dir.create(file.path(sp, "tests", "testthat"), recursive = TRUE)
  writeLines(
    c(
      "Package: skippkg",
      "Version: 0.0.1",
      "Title: Probe Skips",
      "Description: Probe skips under check.",
      "License: MIT",
      "Suggests: testthat (>= 3.0.0), webfakes",
      "Config/testthat/edition: 3",
      "Encoding: UTF-8",
      'Authors@R: person("A", "B", email = "a@b.invalid", role = c("aut", "cre"))'
    ),
    file.path(sp, "DESCRIPTION")
  )
  writeLines("", file.path(sp, "NAMESPACE"))
  writeLines("f <- function() 1", file.path(sp, "R", "f.R"))
  writeLines(
    'library(testthat); library(skippkg); test_check("skippkg")',
    file.path(sp, "tests", "testthat.R")
  )
  writeLines(
    'test_that("tls pin", { skip_on_cran(); expect_true(TRUE) })',
    file.path(sp, "tests", "testthat", "test-a.R")
  )
  writeLines(
    'test_that("L2 pin", { skip_if_not_installed("webfakes"); expect_true(TRUE) })',
    file.path(sp, "tests", "testthat", "test-b.R")
  )
  writeLines(
    c(
      'test_that("libpaths", {',
      '  message("LIBPATHS: ", paste(.libPaths(), collapse = " | "))',
      '  for (p in c("webfakes", "codetools")) message(toupper(p), ": ",',
      '    tryCatch(find.package(p), error = function(e) "ABSENT"))',
      '  succeed()',
      '})'
    ),
    file.path(sp, "tests", "testthat", "test-c.R")
  )
  offline <- c(
    "_R_CHECK_CRAN_INCOMING_REMOTE_" = "false",
    "_R_CHECK_SYSTEM_CLOCK_" = "false"
  )
  check <- function(label, args, env) {
    r <- tryCatch(
      rcmdcheck::rcmdcheck(
        sp,
        args = c(args, "--no-manual"),
        quiet = TRUE,
        error_on = "warning",
        env = c(offline, env),
        check_dir = file.path(tmp, "chk")
      ),
      error = function(e) e
    )
    if (inherits(r, "error")) {
      cat(label, "ERROR:", conditionMessage(r), "\n")
      return()
    }
    out <- strsplit(r$test_output[[1]], "\n")[[1]]
    tally <- grep("\\[ FAIL", out, value = TRUE)
    cat(sprintf(
      "%-38s passed=%-5s %s\n",
      label,
      length(r$errors) + length(r$warnings) == 0L,
      tail(tally, 1)
    ))
    lp <- grep("^(LIBPATHS|WEBFAKES|CODETOOLS):", out, value = TRUE)
    cat(
      paste0("    ", sub("/[^ ]*/RLIBS_[^ ]*", "<tmp>/RLIBS_<id>", lp)),
      sep = "\n"
    )
  }
  check("--as-cran, NOT_CRAN unset", "--as-cran", character())
  check("--as-cran, NOT_CRAN=true", "--as-cran", c(NOT_CRAN = "true"))
  check(
    "_R_CHECK_DEPENDS_ONLY_",
    character(),
    c("_R_CHECK_DEPENDS_ONLY_" = "true")
  )
  check(
    "_R_CHECK_DEPENDS_ONLY_ + NO_RECOMMENDED_",
    character(),
    c("_R_CHECK_DEPENDS_ONLY_" = "true", "_R_CHECK_NO_RECOMMENDED_" = "true")
  )
}
# --as-cran, NOT_CRAN unset               passed=TRUE  [ FAIL 0 | WARN 0 | SKIP 1 | PASS 2 ]
# --as-cran, NOT_CRAN=true                passed=TRUE  [ FAIL 0 | WARN 0 | SKIP 0 | PASS 3 ]
# _R_CHECK_DEPENDS_ONLY_                  passed=TRUE  [ FAIL 0 | WARN 0 | SKIP 1 | PASS 2 ]
# _R_CHECK_DEPENDS_ONLY_ + NO_RECOMMENDED_ passed=TRUE [ FAIL 0 | WARN 0 | SKIP 1 | PASS 2 ]
# and under each, the same three lines:
#     LIBPATHS: <tmp>/RLIBS_<id> | /Library/Frameworks/R.framework/Versions/4.6/Resources/library
#     WEBFAKES: /Library/Frameworks/R.framework/Versions/4.6/Resources/library/webfakes
#     CODETOOLS: /Library/Frameworks/R.framework/Versions/4.6/Resources/library/codetools
# The verify hook's call passes with the skip_on_cran() test skipped: a skip
# is not a warning. NOT_CRAN=true runs it. The skip in the last two rows is the
# same skip_on_cran() test. Neither _R_CHECK_ variable hides a package
# installed in .Library, which on this machine holds webfakes and codetools,
# so skip_if_not_installed("webfakes") never skipped here.
