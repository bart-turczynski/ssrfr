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
      dep_curl_transfer = function(opts, data, debug) {
        transfer(opts, data, function(type, msg) {
          if (type == 0L) {
            msg <- charToRaw(fn(rawToChar(msg)))
          }
          debug(type, msg)
        })
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

# --- failover (§2.5, §6.6) ---------------------------------------------------

# Replaces the transport with a script: `outcomes` maps each address to how
# its attempt ends. Records the addresses in the order they were tried.
scripted_transfer <- function(outcomes, env = parent.frame()) {
  tried <- new.env(parent = emptyenv())
  tried$addresses <- character()
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug) {
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
