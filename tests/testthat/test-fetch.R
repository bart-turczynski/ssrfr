# ssrf_fetch() end to end (ssrfr-v1.md §2.2, §2.5, §5.3, §6.6, §12 steps
# 9-12, §14, INV-5, INV-6, INV-9, INV-10, INV-12), and the behaviour tests of
# r-binding.md §7 that need a server. Every server is on loopback, every
# host a `.invalid` name the resolver mock maps to it, so a fetch that
# arrives proves the pin was used.

# --- the pin -----------------------------------------------------------------

test_that("the pin is load-bearing and Host is kept", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  seen <- mock_answers("127.0.0.1")
  r <- guarded_get(pinned_url(port), loopback_policy(port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(body_text(r), paste0("host=", pinned_host, ":", port))
  b <- attr(r, "binding")
  expect_identical(b$state$pin_used, "127.0.0.1")
  expect_identical(b$state$attempts, "127.0.0.1 connected")
  expect_identical(seen$queries, paste0(pinned_host, "."))
})

test_that("the pin holds on explicit, default and non-default ports", {
  mock_answers("127.0.0.1")
  cases <- list(
    list(url = paste0("http://", pinned_host, "/"), port = 80L),
    list(url = paste0("http://", pinned_host, ":80/"), port = 80L),
    list(url = paste0("https://", pinned_host, "/"), port = 443L),
    list(url = paste0("https://", pinned_host, ":443/"), port = 443L),
    list(url = paste0("http://", pinned_host, ":1/"), port = 1L)
  )
  for (case in cases) {
    local({
      trace <- local_trace_recorder()
      b <- ssrf_prepare_hop(case$url, loopback_policy(1), request = list())
      expect_identical(b$origin$port, case$port, label = case$url)
      ssrf_fetch(b)
      # Whatever answers there, the connection went to the pinned address on
      # the request's own port, and the pin check saw it.
      tries <- grep("^Trying ", trace$lines, value = TRUE)
      expect_identical(
        tries[[1L]],
        paste0("Trying 127.0.0.1:", case$port, "..."),
        label = case$url
      )
      expect_true(startsWith(b$state$attempts[[1L]], "127.0.0.1 "))
      expect_false(identical(b$state$outcome, "pin-mismatch"))
    })
  }
})

test_that("a changed second resolver answer is never used", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  seen <- mock_answers(function(q) {
    if (length(seen$queries) == 1L) "127.0.0.1" else "10.0.0.5"
  })
  b <- ssrf_prepare_hop(
    pinned_url(port),
    loopback_policy(port),
    request = list()
  )
  r <- ssrf_fetch(b)
  expect_identical(r$status, 200L)
  expect_length(seen$queries, 1L)
  # The flipped answer exists, and a new hop would meet it.
  r2 <- ssrf_prepare_hop(
    pinned_url(port),
    loopback_policy(port),
    request = list()
  )
  expect_identical(r2$code, "private")
})

test_that("a missing trace or another peer is pin-mismatch", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  transfer <- ssrfr:::dep_curl_transfer
  rewrite <- function(fn) {
    local_mocked_bindings(
      dep_curl_transfer = function(opts, data, debug, progress) {
        rewriting <- function(type, msg) {
          if (type == 0L) {
            msg <- charToRaw(fn(rawToChar(msg)))
          }
          debug(type, msg)
        }
        transfer(opts, data, rewriting, progress)
      },
      .env = parent.frame()
    )
  }
  cases <- list(
    absent = function(x) gsub("Trying ", "Dialing ", x, fixed = TRUE),
    `other-address` = function(x) {
      gsub("127.0.0.1", "10.0.0.7", x, fixed = TRUE)
    },
    garbled = function(x) sub("Trying [^ \n]*", "Trying ???", x)
  )
  for (check in names(cases)) {
    local({
      rewrite(cases[[check]])
      b <- ssrf_prepare_hop(
        pinned_url(port),
        loopback_policy(port),
        request = list()
      )
      r <- ssrf_fetch(b)
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "pin-mismatch", label = check)
      expect_identical(r$detail$check, check)
      # The response the server did send is discarded, not returned.
      expect_null(b$state$status)
    })
  }
})

# §2.5: the transport speaks HTTP/1.1 only (r-binding.md §5). Over HTTP/2
# libcurl sends a request again after the server refuses its stream
# (RST_STREAM REFUSED_STREAM). webfakes has no HTTP/2, so what shows the
# pin on the wire is the TLS handshake: h2 is never offered in ALPN.
test_that("HTTP/2 is never offered, even over TLS", {
  skip_if_no_webfakes()
  skip_if_not(isTRUE(curl::curl_version()$http2), "libcurl has no HTTP/2")
  tls <- local_test_server(tls = TRUE)
  port <- tls$get_port()
  local_trust_test_ca()
  mock_answers("127.0.0.1")
  trace <- local_trace_recorder()
  r <- guarded_get(
    pinned_url(port, scheme = "https", host = "alpha.example.invalid"),
    loopback_policy(port)
  )
  expect_identical(r$status, 200L)
  offers <- grep("ALPN", trace$lines, value = TRUE)
  expect_gt(length(offers), 0L)
  expect_false(any(grepl("h2", offers, fixed = TRUE)))
})

# --- the request plan (§2.3) --------------------------------------------------

# The request head a raw server received, split into lines.
request_head <- function(server) {
  bytes <- server$request()
  text <- rawToChar(bytes)
  head <- substr(text, 1L, regexpr("\r\n\r\n", text, fixed = TRUE) - 1L)
  strsplit(head, "\r\n", fixed = TRUE)[[1L]]
}

# §2.3: the plan the binding records is the plan the transport sends. libcurl
# adds Accept: */* to every request, a form Content-Type to every POST and
# Expect: 100-continue to a large body; none was in the plan, so none may
# reach the wire.
test_that("the transport sends no field the plan did not carry", {
  mock_answers("127.0.0.1")
  ok <- wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  )
  fields <- function(head) {
    tolower(sub(":.*$", "", head[-1L]))
  }
  empty <- local_raw_server(ok)
  r <- guarded_get(
    pinned_url(empty$port, "/p"),
    loopback_policy(empty$port),
    request = list(method = "POST")
  )
  expect_identical(r$status, 200L)
  head <- request_head(empty)
  expect_identical(head[[1L]], "POST /p HTTP/1.1")
  expect_setequal(
    fields(head),
    c("host", "user-agent", "accept-encoding", "content-length")
  )
  expect_true("Content-Length: 0" %in% head)

  # 1.5 MiB: over libcurl's threshold for Expect: 100-continue.
  body <- as.raw(rep(0x61, 1.5 * 2^20))
  big <- local_raw_server(ok)
  r <- guarded_get(
    pinned_url(big$port, "/p"),
    loopback_policy(big$port),
    request = list(method = "POST", body = body)
  )
  expect_identical(r$status, 200L)
  head <- request_head(big)
  expect_setequal(
    fields(head),
    c("host", "user-agent", "accept-encoding", "content-length")
  )
  sent <- big$request()
  expect_identical(tail(sent, length(body)), body)

  # A Content-Type the plan carries is sent once, as given.
  typed <- local_raw_server(ok)
  guarded_get(
    pinned_url(typed$port, "/p"),
    loopback_policy(typed$port),
    request = list(
      method = "POST",
      headers = c(`Content-Type` = "text/plain"),
      body = "x"
    )
  )
  head <- request_head(typed)
  expect_identical(
    grep("^Content-Type", head, value = TRUE),
    "Content-Type: text/plain"
  )
  expect_false(any(grepl("^Expect", head)))

  # An Accept the plan carries is sent once, as given.
  accepts <- local_raw_server(ok)
  guarded_get(
    pinned_url(accepts$port, "/a"),
    loopback_policy(accepts$port),
    request = list(headers = c(Accept = "application/json"))
  )
  head <- request_head(accepts)
  expect_identical(
    grep("^Accept:", head, value = TRUE),
    "Accept: application/json"
  )
})

# --- the response ------------------------------------------------------------

# Records every warning raised inside the transport's callbacks. libcurl
# runs them as top-level calls, where no handler of the caller's sees a
# warning: R prints it later, header bytes and all.
local_callback_warnings <- function(env = parent.frame()) {
  transfer <- ssrfr:::dep_curl_transfer
  seen <- new.env(parent = emptyenv())
  seen$warnings <- character()
  record <- function(f) {
    function(...) {
      withCallingHandlers(f(...), warning = function(w) {
        seen$warnings <- c(seen$warnings, conditionMessage(w))
        invokeRestart("muffleWarning")
      })
    }
  }
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug, ...) {
      transfer(opts, record(data), record(debug), ...)
    },
    .package = "ssrfr",
    .env = env
  )
  seen
}

# RFC 9110 §5.5: obs-text in a field value, here a Latin-1 filename, is a
# valid response, and no warning quotes the header block, Set-Cookie
# included (INV-12, §2.3).
test_that("a Latin-1 byte in a header value is a response, with no warning", {
  e9 <- as.raw(0xe9)
  web <- local_raw_server(c(
    wire(
      "HTTP/1.1 200 OK\r\n",
      "Content-Type: text/plain\r\n",
      "Set-Cookie: session=secret-cookie\r\n",
      "Content-Disposition: attachment; filename=\"caf"
    ),
    e9,
    wire(".txt\"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
  ))
  mock_answers("127.0.0.1")
  callbacks <- local_callback_warnings()
  r <- NULL
  expect_no_warning(
    r <- guarded_get(pinned_url(web$port), loopback_policy(web$port))
  )
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(body_text(r), "ok")
  expect_identical(
    charToRaw(unname(r$headers[["content-disposition"]])),
    c(wire("attachment; filename=\"caf"), e9, wire(".txt\""))
  )
  expect_identical(callbacks$warnings, character())
  expect_identical(format(r)[[3L]], "  type: text/plain")
})

# R's curl keeps a chunked body's trailer fields in the header bytes it
# returns. A trailer is not the header: its Location is neither a header
# field nor the redirect target the binding records (§2.3).
test_that("a trailer field never joins the header", {
  web <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Location\r\n",
    "Connection: close\r\n\r\n",
    "5\r\nhello\r\n0\r\nLocation: /trailer\r\nX-Trailer: t\r\n\r\n"
  ))
  mock_answers("127.0.0.1")
  r <- guarded_get(pinned_url(web$port), loopback_policy(web$port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(body_text(r), "hello")
  expect_named(r$headers, c("transfer-encoding", "trailer", "connection"))
  b <- attr(r, "binding")
  expect_identical(b$state$location_count, 0L)
  expect_null(b$state$location)
})

# The status libcurl reports and the status line of the header block ssrfr
# reads must be one response's; when they differ, neither is recorded
# (§2.3: the status is transport-observed).
test_that("a status that disagrees with the header block is a protocol error", {
  mock_answers("127.0.0.1")
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug, progress) {
      debug(0L, charToRaw("Trying 127.0.0.1:80...\n"))
      list(
        aborted = FALSE,
        error = NULL,
        status = 200L,
        headers = wire("HTTP/1.1 302 Found\r\nLocation: /x\r\n\r\n"),
        connect = 0.01
      )
    }
  )
  b <- ssrf_prepare_hop(
    paste0("http://", pinned_host, "/"),
    loopback_policy(),
    request = list()
  )
  r <- ssrf_fetch(b)
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "protocol-error")
  expect_identical(r$detail$check, "header")
  expect_null(b$state$status)
  expect_null(b$state$location)
})

# --- failover (§2.5, §6.6) ---------------------------------------------------

# Replaces the transport with a script: `outcomes` maps each address to how
# its attempt ends. Records the addresses in the order they were tried.
scripted_transfer <- function(outcomes, env = parent.frame()) {
  tried <- new.env(parent = emptyenv())
  tried$addresses <- character()
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug, progress) {
      key <- "multi.invalid::"
      target <- sub(":$", "", substring(opts$connect_to, nchar(key) + 1L))
      address <- gsub("[][]", "", target)
      tried$addresses <- c(tried$addresses, address)
      outcome <- outcomes[[address]]
      dialed <- if (outcome == "mismatch") "[fd00::66]" else target
      debug(0L, charToRaw(paste0("Trying ", dialed, ":80...\n")))
      base <- list(
        aborted = FALSE,
        error = NULL,
        status = 0L,
        headers = raw(),
        connect = 0
      )
      switch(
        outcome,
        refused = replace(base, "error", "curl_error_couldnt_connect"),
        timeout = replace(base, "error", "curl_error_operation_timedout"),
        mismatch = replace(base, "error", "curl_error_couldnt_connect"),
        tls = modifyList(
          base,
          list(error = "curl_error_peer_failed_verification", connect = 0.01)
        ),
        ok = {
          data(charToRaw("hello"))
          modifyList(
            base,
            list(
              status = 200L,
              connect = 0.01,
              headers = charToRaw(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
              )
            )
          )
        }
      )
    },
    .package = "ssrfr",
    .env = env
  )
  tried
}

failover_fetch <- function(outcomes) {
  addresses <- names(outcomes)
  local_mocked_bindings(dep_nslookup = function(query) addresses)
  policy <- ssrf_policy(allow_ranges = c("192.0.2.0/24", "2001:db8::/32"))
  b <- ssrf_prepare_hop("http://multi.invalid/", policy, request = list())
  list(result = ssrf_fetch(b), binding = b)
}

test_that("failover follows resolver order and stops at the first connection", {
  tried <- scripted_transfer(list(
    "192.0.2.3" = "refused",
    "2001:db8::1" = "timeout",
    "192.0.2.1" = "ok",
    "192.0.2.2" = "ok"
  ))
  out <- failover_fetch(list(
    "192.0.2.3" = 1,
    "2001:db8::1" = 1,
    "192.0.2.1" = 1,
    "192.0.2.2" = 1
  ))
  expect_identical(tried$addresses, c("192.0.2.3", "2001:db8::1", "192.0.2.1"))
  expect_s3_class(out$result, "ssrfr_response")
  expect_identical(body_text(out$result), "hello")
  expect_identical(out$binding$state$pin_used, "192.0.2.1")
  expect_identical(
    out$binding$state$attempts,
    c(
      "192.0.2.3 connect-failed",
      "2001:db8::1 connect-timeout",
      "192.0.2.1 connected"
    )
  )
})

test_that("exhausted failover is timeout only when every connect timed out", {
  run <- function(script) {
    local({
      tried <- scripted_transfer(script)
      out <- failover_fetch(lapply(script, function(x) 1))
      list(cause = out$result$cause, tried = tried$addresses, out = out$result)
    })
  }
  all_timeout <- run(list("192.0.2.1" = "timeout", "192.0.2.2" = "timeout"))
  expect_identical(all_timeout$cause, "timeout")
  expect_identical(all_timeout$tried, c("192.0.2.1", "192.0.2.2"))
  expect_identical(
    all_timeout$out$detail$attempts,
    c("192.0.2.1 connect-timeout", "192.0.2.2 connect-timeout")
  )
  mixed <- run(list("192.0.2.1" = "timeout", "192.0.2.2" = "refused"))
  expect_identical(mixed$cause, "connect-failed")
  mixed2 <- run(list("192.0.2.1" = "refused", "192.0.2.2" = "timeout"))
  expect_identical(mixed2$cause, "connect-failed")
  refused <- run(list("192.0.2.1" = "refused"))
  expect_identical(refused$cause, "connect-failed")
})

# §6.6: total_timeout elapsing during failover is `timeout`, naming the
# address last attempted; no further address is tried.
test_that("total_timeout ends failover as timeout", {
  tried <- new.env(parent = emptyenv())
  tried$addresses <- character()
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug, progress) {
      target <- sub("^multi[.]invalid::(.*):$", "\\1", opts$connect_to)
      tried$addresses <- c(tried$addresses, target)
      debug(0L, charToRaw(paste0("Trying ", target, ":80...\n")))
      Sys.sleep(0.6)
      list(
        aborted = FALSE,
        error = "curl_error_couldnt_connect",
        status = 0L,
        headers = raw(),
        connect = 0
      )
    }
  )
  addresses <- c("192.0.2.1", "192.0.2.2", "192.0.2.3")
  local_mocked_bindings(dep_nslookup = function(query) addresses)
  policy <- ssrf_policy(allow_ranges = "192.0.2.0/24", total_timeout = 1)
  b <- ssrf_prepare_hop("http://multi.invalid/", policy, request = list())
  r <- ssrf_fetch(b)
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$step, 10L)
  expect_identical(r$detail$limit, "total_timeout")
  expect_identical(r$address, "192.0.2.2")
  expect_identical(tried$addresses, c("192.0.2.1", "192.0.2.2"))
  expect_identical(
    r$detail$attempts,
    c("192.0.2.1 connect-failed", "192.0.2.2 connect-failed")
  )
})

test_that("pin-mismatch or an opened connection ends failover", {
  run <- function(script) {
    local({
      tried <- scripted_transfer(script)
      out <- failover_fetch(lapply(script, function(x) 1))
      list(cause = out$result$cause, tried = tried$addresses)
    })
  }
  first <- run(list("192.0.2.1" = "mismatch", "192.0.2.2" = "ok"))
  expect_identical(first$cause, "pin-mismatch")
  expect_identical(first$tried, "192.0.2.1")
  second <- run(list(
    "192.0.2.1" = "refused",
    "192.0.2.2" = "mismatch",
    "192.0.2.3" = "ok"
  ))
  expect_identical(second$cause, "pin-mismatch")
  expect_identical(second$tried, c("192.0.2.1", "192.0.2.2"))
  tls <- run(list("192.0.2.1" = "tls", "192.0.2.2" = "ok"))
  expect_identical(tls$cause, "tls-failed")
  expect_identical(tls$tried, "192.0.2.1")
})

test_that("failover reaches the listener after a dead address", {
  skip_if_no_webfakes()
  skip_if_not(isTRUE(curl::curl_version()$ipv6), "libcurl has no IPv6")
  web <- local_test_server()
  port <- web$get_port()
  mock_answers(c("::1", "127.0.0.1"))
  trace <- local_trace_recorder()
  r <- guarded_get(pinned_url(port), loopback_policy(port))
  expect_identical(r$status, 200L)
  b <- attr(r, "binding")
  expect_match(b$state$attempts[[1L]], "^::1 connect-(failed|timeout)$")
  expect_identical(b$state$attempts[[2L]], "127.0.0.1 connected")
  tries <- grep("^Trying ", trace$lines, value = TRUE)
  expect_length(tries, 2L)
  expect_match(tries[[1L]], paste0("^Trying \\[?::1\\]?:", port))
  expect_identical(tries[[2L]], paste0("Trying 127.0.0.1:", port, "..."))
})

# --- single use (§2.5) -------------------------------------------------------

test_that("a binding is spent on entry, even when the fetch fails", {
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    "http://spent.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  expect_true(b$state$fetchable)
  r <- ssrf_fetch(b)
  expect_identical(r$cause, "connect-failed")
  expect_false(b$state$fetchable)
  err <- expect_error(ssrf_fetch(b), class = "ssrfr_error_spent_binding")
  expect_s3_class(err, "ssrfr_error")
  # A copy is the same binding: spending one spends both.
  b2 <- ssrf_prepare_hop(
    "http://spent.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  alias <- b2
  ssrf_fetch(alias)
  expect_error(ssrf_fetch(b2), class = "ssrfr_error_spent_binding")
  # A transport that errors still leaves the binding spent.
  local({
    local_mocked_bindings(dep_curl_transfer = function(...) stop("boom"))
    b3 <- ssrf_prepare_hop(
      "http://spent.invalid:1/",
      loopback_policy(1),
      request = list()
    )
    r <- NULL
    expect_no_error(r <- ssrf_fetch(b3))
    expect_identical(r$cause, "pin-mismatch")
    expect_error(ssrf_fetch(b3), class = "ssrfr_error_spent_binding")
  })
  expect_error(ssrf_fetch(r), class = "ssrfr_error_invalid_argument")
  expect_error(ssrf_fetch("http://x/"), class = "ssrfr_error_invalid_argument")
})

# §2.5: no retries. libcurl's default auth, CURLAUTH_ANY, answers a 401
# challenge by sending the request again with the URL's credentials; the
# server here offers Digest and Basic and counts the requests it receives.
test_that("an auth challenge never makes the request a second time", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  r <- guarded_get(
    paste0("http://user:pass@", pinned_host, ":", port, "/auth"),
    loopback_policy(port, allow_userinfo = TRUE)
  )
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 401L)
  # One request, and it carried the credentials the URL named.
  # "dXNlcjpwYXNz" is base64 of "user:pass".
  expect_identical(body_text(r), "hits=1 auth=Basic dXNlcjpwYXNz")
})

test_that("a failing transport wrapper fails closed, never an R error", {
  modes <- list(
    stop = function(...) stop("dependency failed"),
    null = function(...) NULL,
    wrong_shape = function(...) list(unexpected = 42)
  )
  mock_answers("127.0.0.1")
  for (mode in names(modes)) {
    local({
      local_mocked_bindings(dep_curl_transfer = modes[[mode]])
      b <- ssrf_prepare_hop(
        "http://wrapper.invalid:1/",
        loopback_policy(1),
        request = list()
      )
      r <- NULL
      expect_no_error(r <- ssrf_fetch(b))
      expect_s3_class(r, "ssrfr_failure")
      expect_identical(r$cause, "pin-mismatch", label = mode)
    })
  }
})

# r-binding.md §7: an interrupt mid-transfer leaves the binding spent and no
# handle open. A raw server sends a header and one chunk, then waits; once
# the chunk is out, a second process interrupts this one. The server then
# reports whether the client closed the connection.
test_that("an interrupt leaves the binding spent and no handle open", {
  skip_if_not_installed("callr")
  skip_on_os("windows")
  port <- free_port()
  flag <- tempfile("chunk-sent-")
  ready <- tempfile("listening-")
  closed <- tempfile("closed-")
  server <- callr::r_bg(
    function(port, flag, ready, closed) {
      s <- serverSocket(port)
      on.exit(close(s))
      file.create(ready)
      con <- socketAccept(s, blocking = TRUE, open = "r+b", timeout = 30)
      on.exit(close(con), add = TRUE)
      repeat {
        l <- readLines(con, n = 1L, warn = FALSE)
        if (!length(l) || !nzchar(l)) break
      }
      writeBin(
        charToRaw(paste0(
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
          "5\r\nfirst\r\n"
        )),
        con
      )
      flush(con)
      file.create(flag)
      t0 <- Sys.time()
      repeat {
        x <- tryCatch(readBin(con, raw(), 1L), error = function(e) NULL)
        if (!length(x)) {
          file.create(closed)
          return("closed")
        }
        if (difftime(Sys.time(), t0, units = "secs") > 20) {
          return("still open")
        }
      }
    },
    args = list(port = port, flag = flag, ready = ready, closed = closed)
  )
  withr::defer(server$kill())
  interrupter <- callr::r_bg(
    function(pid, flag) {
      t0 <- Sys.time()
      while (!file.exists(flag)) {
        if (difftime(Sys.time(), t0, units = "secs") > 30) {
          return("no chunk")
        }
        Sys.sleep(0.05)
      }
      Sys.sleep(0.3)
      tools::pskill(pid, tools::SIGINT)
      "sent"
    },
    args = list(pid = Sys.getpid(), flag = flag)
  )
  withr::defer(interrupter$kill())
  # Wait for the server to listen before preparing the hop.
  t0 <- Sys.time()
  while (!file.exists(ready) && difftime(Sys.time(), t0, units = "secs") < 20) {
    Sys.sleep(0.05)
  }
  expect_true(file.exists(ready))
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    pinned_url(port),
    loopback_policy(port, total_timeout = 60),
    request = list()
  )
  got <- tryCatch(ssrf_fetch(b), interrupt = function(c) "interrupted")
  # The connection is closed at once, not whenever the garbage collector
  # finalizes an abandoned handle: poll before anything else allocates.
  t0 <- Sys.time()
  while (!file.exists(closed) && difftime(Sys.time(), t0, units = "secs") < 3) {
    Sys.sleep(0.05)
  }
  closed_at_once <- file.exists(closed)
  expect_identical(got, "interrupted")
  expect_true(closed_at_once)
  expect_false(b$state$fetchable)
  expect_error(ssrf_fetch(b), class = "ssrfr_error_spent_binding")
  server$wait(25000)
  expect_identical(server$get_result(), "closed")
})

# §2.5: a user's interrupt propagates even when it lands while ssrfr is
# ending the transfer itself. ssrfr stops this transfer at its header
# limit; curl raises that abort as an interrupt right after the transfer's
# final delivery, and the user's interrupt arrives during that delivery.
test_that("a user interrupt during ssrfr's own abort still propagates", {
  skip_on_os("windows")
  mock_answers("127.0.0.1")
  server <- local_raw_server(stream_forever(
    wire("HTTP/1.1 200 OK\r\n"),
    wire("X-Field: ", strrep("v", 50), "\r\n")
  ))
  transfer <- ssrfr:::dep_curl_transfer
  delivered <- new.env(parent = emptyenv())
  delivered$final <- FALSE
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug, progress) {
      interrupting <- function(x, final = FALSE) {
        if (final) {
          delivered$final <- TRUE
          tools::pskill(Sys.getpid(), tools::SIGINT)
          Sys.sleep(5)
        }
        data(x, final)
      }
      transfer(opts, interrupting, debug, progress)
    }
  )
  b <- ssrf_prepare_hop(
    pinned_url(server$port),
    loopback_policy(server$port, max_header_bytes = 1000, total_timeout = 20),
    request = list()
  )
  got <- tryCatch(ssrf_fetch(b), interrupt = function(c) "interrupted")
  expect_true(delivered$final)
  expect_identical(got, "interrupted")
  expect_false(b$state$fetchable)
  expect_null(b$state$status)
  expect_error(ssrf_fetch(b), class = "ssrfr_error_spent_binding")
})
