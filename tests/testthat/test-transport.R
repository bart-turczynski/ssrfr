# The pure parts of the transport (ssrfr-v1.md §14, INV-5, INV-6, INV-9,
# INV-10; r-binding.md §5-§7): the option-list builder every attempt's
# options come from, the one-place-dials tripwire, the trace matcher, and the
# reading of response headers. No test here opens a connection.

caps_modern <- list(
  version = numeric_version("8.14.1"),
  protocols_str = TRUE,
  zlib = TRUE
)
caps_old <- list(
  version = numeric_version("7.81.0"),
  protocols_str = FALSE,
  zlib = TRUE
)

# A binding for `url`, with the resolver answering `answers`.
binding_for <- function(url, answers = "93.184.216.34", policy = NULL) {
  local_mocked_bindings(dep_nslookup = function(query) answers)
  policy <- policy %||% ssrf_policy(allow_ports = c(80, 443, 8080))
  ssrf_prepare_hop(url, policy, request = list())
}

`%||%` <- function(x, y) if (is.null(x)) y else x

# r-binding.md §7, Rules: every handle carries the pin; TLS is never
# weakened; the "never set" options are absent. Each scheme, with explicit,
# default and non-default ports, a name and both address families, and both
# forms of the protocol restriction.
test_that("every handle carries the pin, TLS is never weakened, nothing never-set is set", {
  cases <- list(
    list(url = "http://pin.example/", answers = "93.184.216.34"),
    list(url = "http://pin.example:80/", answers = "93.184.216.34"),
    list(url = "http://pin.example:8080/", answers = "93.184.216.34"),
    list(url = "https://pin.example/", answers = "93.184.216.34"),
    list(url = "https://pin.example:443/", answers = "93.184.216.34"),
    list(url = "https://pin.example:8080/", answers = "93.184.216.34"),
    list(url = "https://PIN.Example./x", answers = "2606:4700:4700::1111"),
    list(url = "http://93.184.216.34:8080/", answers = NULL),
    list(url = "https://[2606:4700:4700::1111]/", answers = NULL)
  )
  for (case in cases) {
    b <- binding_for(case$url, case$answers)
    expect_s3_class(b, "ssrfr_binding")
    for (caps in list(caps_modern, caps_old, NULL)) {
      for (address in b$validated) {
        opts <- ssrfr:::transport_options(b, address, 10, caps)
        expect_identical(
          option_problems(opts, b$origin$host, address),
          character(),
          label = paste(case$url, address)
        )
        # The key is libcurl's own host, with no port field to mismatch.
        expect_true(startsWith(opts$connect_to, paste0(b$origin$host, "::")))
        expect_identical(opts$url, b$url)
      }
    }
  }
  # The restriction takes the string form from libcurl 7.85, else the bitmask.
  b <- binding_for("http://pin.example/")
  modern <- ssrfr:::transport_options(b, "93.184.216.34", 10, caps_modern)
  old <- ssrfr:::transport_options(b, "93.184.216.34", 10, caps_old)
  unknown <- ssrfr:::transport_options(b, "93.184.216.34", 10, NULL)
  expect_identical(modern$protocols_str, "http,https")
  expect_null(modern[["protocols"]])
  expect_identical(old[["protocols"]], 3L)
  expect_null(old$protocols_str)
  expect_identical(unknown[["protocols"]], 3L)
  # Accept-Encoding is always set, never NULL.
  expect_identical(modern$accept_encoding, "gzip, deflate")
  expect_identical(unknown$accept_encoding, "identity")
})

test_that("the option checker fires on a planted violation", {
  b <- binding_for("http://pin.example/")
  good <- ssrfr:::transport_options(b, "93.184.216.34", 10, caps_modern)
  expect_identical(
    option_problems(good, "pin.example", "93.184.216.34"),
    character()
  )
  planted <- list(
    missing_pin = within(good, rm(connect_to)),
    port_keyed = replace(good, "connect_to", "pin.example:80:93.184.216.34:80"),
    empty_host = replace(good, "connect_to", "::93.184.216.34:"),
    no_trailing_colon = replace(
      good,
      "connect_to",
      "pin.example::93.184.216.34"
    ),
    resolve = c(good, list(resolve = "pin.example:80:93.184.216.34")),
    verify_off = replace(good, "ssl_verifypeer", list(0L)),
    host_off = replace(good, "ssl_verifyhost", list(0L)),
    proxy = replace(good, "proxy", "http://proxy.example:3128"),
    noproxy_empty = replace(good, "noproxy", ""),
    reuse = replace(good, "forbid_reuse", list(0L)),
    follow = replace(good, "followlocation", list(1L)),
    netrc = replace(good, "netrc", list(1L)),
    cookie_engine = replace(good, "cookiefile", ""),
    protocols = within(good, rm(protocols_str, redir_protocols_str)),
    unix = c(good, list(unix_socket_path = "/var/run/docker.sock")),
    altsvc = c(good, list(altsvc = "altsvc.txt"))
  )
  for (name in names(planted)) {
    expect_gt(
      length(option_problems(planted[[name]], "pin.example", "93.184.216.34")),
      0L,
      label = name
    )
  }
})

test_that("limits and the request plan reach the options", {
  local_mocked_bindings(dep_nslookup = function(query) "93.184.216.34")
  policy <- ssrf_policy(
    connect_timeout = 2,
    total_timeout = 7,
    max_response_size = 12345,
    user_agent = "tester/1"
  )
  b <- ssrf_prepare_hop(
    "https://pin.example/",
    policy,
    request = list(
      method = "PATCH",
      headers = c(`X-A` = "1", `X-Empty` = ""),
      body = "payload"
    )
  )
  opts <- ssrfr:::transport_options(b, "93.184.216.34", 5, caps_modern)
  expect_identical(opts$connecttimeout_ms, 2000L)
  expect_identical(opts$timeout_ms, 5000L)
  expect_identical(opts$maxfilesize_large, 12345)
  expect_identical(opts$useragent, "tester/1")
  expect_identical(opts$customrequest, "PATCH")
  expect_identical(opts$postfields, charToRaw("payload"))
  expect_identical(opts$httpheader, c("X-A: 1", "X-Empty;", "Content-Type:"))
  # The connect timeout never exceeds what is left of the total.
  opts <- ssrfr:::transport_options(b, "93.184.216.34", 0.5, caps_modern)
  expect_identical(opts$connecttimeout_ms, 500L)

  methods <- list(
    GET = list(httpget = 1L),
    HEAD = list(nobody = 1L),
    POST = list(postfields = raw(), postfieldsize_large = 0),
    DELETE = list(customrequest = "DELETE")
  )
  for (m in names(methods)) {
    b <- ssrf_prepare_hop(
      "https://pin.example/",
      policy,
      request = list(method = m)
    )
    opts <- ssrfr:::transport_options(b, "93.184.216.34", 5, caps_modern)
    for (field in names(methods[[m]])) {
      expect_identical(opts[[field]], methods[[m]][[field]], label = m)
    }
  }
})

# r-binding.md §7, Rules: one place dials. Walk every closure in the
# installed namespace, nested closures included, for calls to a network entry
# point; only the resolver wrapper and the transport wrapper may make one.
test_that("one place dials", {
  ns <- asNamespace("ssrfr")
  callers <- network_callers(ns)
  expect_setequal(names(callers), c("dep_nslookup", "dep_curl_transfer"))
  expect_identical(callers[["dep_nslookup"]], "nslookup")
  expect_setequal(
    strsplit(callers[["dep_curl_transfer"]], ",")[[1L]],
    c("new_handle", "handle_setopt", "multi_add", "multi_run")
  )

  # Positive control: a planted closure, nested one level down, is found.
  planted <- new.env()
  planted$sneaky <- function(u) {
    inner <- function() curl::curl_fetch_memory(u)
    inner
  }
  planted$quiet <- function(u) paste0(u, "/")
  expect_identical(names(network_callers(planted)), "sneaky")
})

# r-binding.md §6-§7: the trace matcher fails safe. Synthetic traces: none,
# garbled, another address or port are mismatches; the pinned address is a
# match, an IPv6 address compared as a raddr value (INV-3).
test_that("the trace matcher fails safe", {
  check <- ssrfr:::pin_check
  expect_identical(check(character(), "127.0.0.1", 80L), "absent")
  expect_identical(
    check(
      c("Connecting to hostname: 127.0.0.1", "Connected to x"),
      "127.0.0.1",
      80L
    ),
    "absent"
  )
  expect_identical(
    check("Trying pinned.invalid:80...", "127.0.0.1", 80L),
    "garbled"
  )
  expect_identical(check("Trying 127.0.0.1...", "127.0.0.1", 80L), "garbled")
  expect_identical(
    check("Trying 127.0.0.1:80:81...", "127.0.0.1", 80L),
    "garbled"
  )
  expect_identical(check("Trying 999.0.0.1:80...", "127.0.0.1", 80L), "garbled")
  expect_identical(
    check("Trying 10.0.0.1:80...", "127.0.0.1", 80L),
    "other-address"
  )
  expect_identical(
    check("Trying 127.0.0.1:8080...", "127.0.0.1", 80L),
    "other-address"
  )
  expect_identical(
    check(
      c("Trying 127.0.0.1:80...", "Trying 10.0.0.1:80..."),
      "127.0.0.1",
      80L
    ),
    "other-address"
  )
  expect_identical(check("Trying 127.0.0.1:80...", "127.0.0.1", 80L), "match")
  # libcurl 8.x brackets an IPv6 address, 7.x does not; both are one value.
  for (line in c(
    "Trying [::1]:8080...",
    "Trying ::1:8080...",
    "Trying [0:0:0:0:0:0:0:1]:8080..."
  )) {
    expect_identical(check(line, "::1", 8080L), "match", label = line)
  }
  expect_identical(check("Trying [::2]:8080...", "::1", 8080L), "other-address")
  # A raddr failure is never a match (INV-11).
  local_mocked_bindings(dep_raddr_pton = function(...) stop("raddr"))
  expect_identical(check("Trying 127.0.0.1:80...", "127.0.0.1", 80L), "garbled")
})

test_that("response headers are read from the final block only", {
  raw <- charToRaw(paste0(
    "HTTP/1.1 100 Continue\r\n\r\n",
    "HTTP/1.1 302 Found\r\n",
    "Location: /a\r\n",
    "Content-Type: text/html; charset=utf-8\r\n",
    "X-Folded: one\r\n two\r\n",
    "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
  ))
  h <- ssrfr:::parse_response_headers(raw)
  expect_identical(
    names(h),
    c("location", "content-type", "x-folded", "set-cookie", "set-cookie")
  )
  expect_identical(unname(h[["x-folded"]]), "one two")
  expect_null(ssrfr:::parse_response_headers(charToRaw("garbage\r\n")))
  expect_null(
    ssrfr:::parse_response_headers(charToRaw("HTTP/1.1 200 OK\r\nno colon\r\n"))
  )
  expect_null(ssrfr:::parse_response_headers(as.raw(c(0x48, 0x00, 0x49))))
})

test_that("the displayed media type drops parameters and withholds junk", {
  show <- ssrfr:::display_media_type
  expect_identical(show("Text/HTML; charset=utf-8"), "text/html")
  expect_identical(show(character()), NA_character_)
  expect_identical(show("\033[31mred\033[0m/x"), "<withheld>")
  expect_identical(show("not a type"), "<withheld>")
})

test_that("libcurl's capabilities are read through guarded wrappers", {
  caps <- ssrfr:::read_curl_capabilities()
  expect_s3_class(caps$version, "numeric_version")
  expect_type(caps$protocols_str, "logical")
  for (wrapper in c("dep_curl_version", "dep_curl_options")) {
    for (failure in list(function() stop("x"), function() NULL, function() {
      42
    })) {
      local({
        do.call(local_mocked_bindings, stats::setNames(list(failure), wrapper))
        expect_null(ssrfr:::read_curl_capabilities(), label = wrapper)
      })
    }
  }
})
