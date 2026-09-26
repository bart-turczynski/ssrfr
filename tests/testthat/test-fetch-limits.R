# ssrf_fetch()'s limits and its isolation from ambient configuration
# (ssrfr-v1.md §2.3, §5.3, §6.6, §14, INV-10; r-binding.md §5, §7). Servers
# are loopback webfakes apps reached through a pin, as in test-fetch.R.

test_that("total_timeout ends a slow response as timeout", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  t0 <- Sys.time()
  r <- guarded_get(
    pinned_url(port, "/slow"),
    loopback_policy(port, total_timeout = 1)
  )
  elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$limit, "total_timeout")
  expect_lt(elapsed, 4.5)
})

test_that("total_timeout is re-checked after decoding", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  transfer <- ssrfr:::dep_curl_transfer
  # A transfer that returns in time, followed by decoding that does not.
  local_mocked_bindings(
    dep_curl_transfer = function(opts, data, debug, progress) {
      out <- transfer(opts, data, debug, progress)
      Sys.sleep(1.3)
      out
    }
  )
  r <- guarded_get(pinned_url(port), loopback_policy(port, total_timeout = 1))
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "timeout")
  expect_identical(r$detail$step, 12L)
  expect_false(attr(r, "binding")$state$fetched)
})

test_that("the byte cap ends a chunked body as response-too-large", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  r <- guarded_get(
    pinned_url(port, "/chunked"),
    loopback_policy(port, max_response_size = 20000)
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$limit, "max_response_size")
  # Under the cap, the same body arrives whole.
  r <- guarded_get(
    pinned_url(port, "/chunked"),
    loopback_policy(port, max_response_size = 250000)
  )
  expect_length(r$body, 250000L)
})

test_that("a compression bomb is response-too-large from ssrfr's own counter", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  # 2,000,000 zero bytes, about 2 KB on the wire: under the cap as sent, over
  # it decoded. libcurl's maxfilesize counts the wire and lets it pass.
  r <- guarded_get(
    pinned_url(port, "/bomb"),
    loopback_policy(port, max_response_size = 100000)
  )
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$check, "decoded-bytes")
  expect_identical(r$detail$limit, "max_response_size")
  r <- guarded_get(
    pinned_url(port, "/bomb"),
    loopback_policy(port, max_response_size = 3e6)
  )
  expect_identical(r$status, 200L)
  expect_identical(r$body, raw(2e6))
  r <- guarded_get(pinned_url(port, "/deflate"), loopback_policy(port))
  expect_identical(body_text(r), strrep("deflated ", 1000))
})

# §5.3 counts decoded bytes. A declared Content-Length, or wire bytes that
# exceed the decoded body, never refuse a response whose decoded body is
# within the cap: libcurl's maxfilesize would refuse both.
test_that("only decoded bytes count against max_response_size", {
  mock_answers("127.0.0.1")
  policy <- function(port) loopback_policy(port, max_response_size = 1000)
  # A HEAD response declares the size of a body it does not carry.
  head <- local_raw_server(wire(
    "HTTP/1.1 200 OK\r\nContent-Length: 50000000\r\n",
    "Connection: close\r\n\r\n"
  ))
  r <- guarded_get(
    pinned_url(head$port),
    policy(head$port),
    request = list(method = "HEAD")
  )
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(r$body, raw())
  # 990 random bytes, deflated: over the cap on the wire, under it decoded.
  plain <- withr::with_seed(1L, as.raw(sample(0:255, 990L, replace = TRUE)))
  deflated <- memCompress(plain, "gzip")
  expect_gt(length(deflated), 1000L)
  packed <- local_raw_server(c(
    wire(
      "HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n",
      "Content-Length: ",
      length(deflated),
      "\r\nConnection: close\r\n\r\n"
    ),
    deflated
  ))
  r <- guarded_get(pinned_url(packed$port), policy(packed$port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$body, plain)
})

test_that("header bytes and header fields have limits of their own", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  fields <- guarded_get(
    pinned_url(port, "/many-headers"),
    loopback_policy(port, max_header_fields = 20)
  )
  expect_identical(fields$cause, "response-too-large")
  expect_identical(fields$detail$limit, "max_header_fields")
  bytes <- guarded_get(
    pinned_url(port, "/many-headers"),
    loopback_policy(port, max_header_bytes = 500)
  )
  expect_identical(bytes$cause, "response-too-large")
  expect_identical(bytes$detail$limit, "max_header_bytes")
  # The header arrives first, so its limit is the one that names the cause
  # even when the body would pass its own (§6.6).
  both <- guarded_get(
    pinned_url(port, "/many-headers?big=1"),
    loopback_policy(port, max_header_fields = 20, max_response_size = 1000)
  )
  expect_identical(both$cause, "response-too-large")
  expect_identical(both$detail$limit, "max_header_fields")
  ok <- guarded_get(pinned_url(port, "/many-headers"), loopback_policy(port))
  expect_identical(ok$status, 200L)
  expect_identical(unname(ok$headers[["x-field-50"]]), strrep("v", 40))
})

# §14: header bytes and field counts have limits of their own, which hold
# while the header arrives. A header that never ends, a run of 1xx blocks,
# or an endless header on a response to HEAD ends at its limit, well before
# total_timeout.
test_that("a header that never ends stops at its limit, not at the deadline", {
  mock_answers("127.0.0.1")
  field <- wire("X-Field: ", strrep("v", 50), "\r\n")
  cases <- list(
    bytes = list(
      prefix = wire("HTTP/1.1 200 OK\r\n"),
      chunk = field,
      limits = list(max_header_bytes = 1000),
      limit = "max_header_bytes"
    ),
    fields = list(
      prefix = wire("HTTP/1.1 200 OK\r\n"),
      chunk = wire("X: 1\r\n"),
      limits = list(max_header_fields = 20),
      limit = "max_header_fields"
    ),
    interim = list(
      prefix = raw(),
      chunk = wire("HTTP/1.1 102 Processing\r\n\r\n"),
      limits = list(max_header_bytes = 500),
      limit = "max_header_bytes"
    ),
    head = list(
      prefix = wire("HTTP/1.1 200 OK\r\n"),
      chunk = field,
      limits = list(max_header_bytes = 1000),
      limit = "max_header_bytes",
      request = list(method = "HEAD")
    )
  )
  for (name in names(cases)) {
    case <- cases[[name]]
    local({
      server <- local_raw_server(stream_forever(case$prefix, case$chunk))
      policy <- do.call(
        loopback_policy,
        c(list(server$port, total_timeout = 10), case$limits)
      )
      t0 <- Sys.time()
      r <- guarded_get(
        pinned_url(server$port),
        policy,
        request = if (is.null(case$request)) list() else case$request
      )
      elapsed <- as.numeric(difftime(Sys.time(), t0, units = "secs"))
      expect_identical(r$cause, "response-too-large", label = name)
      expect_identical(r$detail$check, "header", label = name)
      expect_identical(r$detail$limit, case$limit, label = name)
      expect_lt(elapsed, 4, label = name)
    })
  }
})

test_that("a redirect is returned with Location; two are a protocol error", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  r <- guarded_get(pinned_url(port, "/redirect"), loopback_policy(port))
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 302L)
  b <- attr(r, "binding")
  expect_identical(b$state$status, 302L)
  expect_identical(b$state$location, "/next?x=1")
  expect_identical(b$state$location_count, 1L)
  expect_true(b$state$fetched)

  r <- guarded_get(pinned_url(port, "/two-locations"), loopback_policy(port))
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "protocol-error")
  expect_identical(r$detail$check, "location")
  b <- attr(r, "binding")
  expect_identical(b$state$location_count, 2L)
  expect_null(b$state$location)
  expect_false(b$state$fetched)
})

# r-binding.md §7, Rules: each proxy variable, with an http:// and a
# socks5h:// value, set to a dead loopback port, for a pinned http:// and a
# pinned https:// fetch. A variable libcurl honoured would send the fetch to
# the dead port.
test_that("proxy variables have no effect", {
  skip_if_no_webfakes()
  skip_if_not_installed("withr")
  web <- local_test_server()
  tls <- local_test_server(tls = TRUE)
  port <- web$get_port()
  tport <- tls$get_port()
  local_trust_test_ca()
  mock_answers("127.0.0.1")
  dead <- free_port()
  policy <- loopback_policy(c(port, tport))
  secure_url <- pinned_url(
    tport,
    scheme = "https",
    host = "alpha.example.invalid"
  )
  vars <- c(
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY"
  )
  for (var in vars) {
    for (scheme in c("http", "socks5h")) {
      value <- paste0(scheme, "://127.0.0.1:", dead)
      local({
        withr::local_envvar(stats::setNames(value, var))
        plain <- guarded_get(pinned_url(port), policy)
        secure <- guarded_get(secure_url, policy)
        expect_identical(plain$status, 200L, label = paste(var, value, "http"))
        expect_identical(
          secure$status,
          200L,
          label = paste(var, value, "https")
        )
      })
    }
  }
})

# Under a connect_to pin a leaked proxy is sent CONNECT to the pinned
# address, so the test asserts that nothing at all reaches a listener
# standing in for the proxy (r-binding.md §7, Rules).
test_that("nothing reaches a listener standing in for the proxy", {
  skip_if_no_webfakes()
  skip_if_not_installed("withr")
  web <- local_test_server()
  tls <- local_test_server(tls = TRUE)
  port <- web$get_port()
  tport <- tls$get_port()
  local_trust_test_ca()
  mock_answers("127.0.0.1")
  proxy <- local_listener()
  value <- paste0("http://127.0.0.1:", proxy$port)
  withr::local_envvar(c(
    http_proxy = value,
    HTTPS_PROXY = value,
    https_proxy = value,
    ALL_PROXY = value
  ))
  policy <- loopback_policy(c(port, tport), total_timeout = 10)
  expect_identical(guarded_get(pinned_url(port), policy)$status, 200L)
  secure <- guarded_get(
    pinned_url(tport, scheme = "https", host = "alpha.example.invalid"),
    policy
  )
  expect_identical(secure$status, 200L)
  expect_false(connection_arrives(proxy$socket, 1))
})

test_that("Alt-Svc has no effect on a later fetch", {
  skip_if_no_webfakes()
  web <- local_test_server()
  port <- web$get_port()
  mock_answers("127.0.0.1")
  dead <- free_port()
  trace <- local_trace_recorder()
  url <- pinned_url(port, paste0("/alt-svc?dead=", dead))
  first <- guarded_get(url, loopback_policy(c(port, dead)))
  second <- guarded_get(url, loopback_policy(c(port, dead)))
  expect_identical(body_text(first), "hit 1")
  expect_identical(body_text(second), "hit 2")
  expect_match(unname(first$headers[["alt-svc"]]), as.character(dead))
  tries <- grep("^Trying ", trace$lines, value = TRUE)
  expect_identical(tries, rep(paste0("Trying 127.0.0.1:", port, "..."), 2L))
})

test_that("a connection is never reused, within a pin or across pins", {
  skip_if_no_webfakes()
  web <- local_test_server(keep_alive = TRUE)
  port <- web$get_port()
  answers <- "127.0.0.1"
  mock_answers(function(q) answers)
  trace <- local_trace_recorder()
  policy <- ssrf_policy(
    allow_ranges = c("127.0.0.0/8", "192.0.2.0/24"),
    allow_ports = port,
    connect_timeout = 1
  )
  # Each fetch opens its own connection, which the pin check sees.
  for (i in 1:2) {
    r <- guarded_get(pinned_url(port), policy)
    expect_identical(r$status, 200L)
  }
  expect_length(grep("^Trying ", trace$lines), 2L)
  expect_length(grep("Re-?using", trace$lines), 0L)
  # The same URL pinned to another address never reaches the first server.
  answers <- "192.0.2.1"
  r <- guarded_get(pinned_url(port), policy)
  expect_s3_class(r, "ssrfr_failure")
  expect_true(r$cause %in% c("timeout", "connect-failed"))
  expect_identical(
    tail(grep("^Trying ", trace$lines, value = TRUE), 1L),
    paste0("Trying 192.0.2.1:", port, "...")
  )
})

# §14, r-binding.md §7, Rules: the scheme allowlist is enforced at the
# transport too, for every scheme this libcurl was built with, and the guard
# refuses each of them first.
test_that("the transport refuses every scheme but http and https", {
  mock_answers("127.0.0.1")
  b <- ssrf_prepare_hop(
    "http://proto.invalid:1/",
    loopback_policy(1),
    request = list()
  )
  opts <- ssrfr:::transport_options(
    b,
    "127.0.0.1",
    5,
    ssrfr:::read_curl_capabilities()
  )
  file <- tempfile(fileext = ".txt")
  writeLines("secret", file)
  target <- function(scheme) {
    switch(
      scheme,
      file = paste0("file://", normalizePath(file, winslash = "/")),
      smb = ,
      smbs = paste0(scheme, "://127.0.0.1:1/share/x"),
      paste0(scheme, "://127.0.0.1:1/x")
    )
  }
  schemes <- setdiff(curl::curl_version()$protocols, c("http", "https"))
  expect_gt(length(schemes), 0L)
  for (scheme in schemes) {
    got <- ssrfr:::dep_curl_transfer(
      replace(opts, "url", target(scheme)),
      function(x, final = FALSE) invisible(),
      function(type, msg) NULL,
      function(down, up) TRUE
    )
    expect_identical(
      got$error,
      "curl_error_unsupported_protocol",
      label = scheme
    )
    guard <- ssrf_prepare_hop(target(scheme), ssrf_policy(), request = list())
    expect_true(guard$code %in% c("scheme", "parse"), label = scheme)
  }
})
