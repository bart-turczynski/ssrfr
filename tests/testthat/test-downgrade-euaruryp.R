# The opt-in allow_downgrade policy field (ssrfr-v1.md §5.3, §12 step 3;
# SSRF-euaruryp): an https hop may redirect to http only when the policy
# says so, and every other check still applies.

test_that("allow_downgrade defaults to FALSE and takes only a flag", {
  expect_false(ssrf_policy()$allow_downgrade)
  expect_true(ssrf_policy(allow_downgrade = TRUE)$allow_downgrade)
  for (bad in list(NA, "yes", 1, c(TRUE, FALSE), NULL)) {
    expect_error(
      ssrf_policy(allow_downgrade = bad),
      class = "ssrfr_error_invalid_policy"
    )
  }
})

test_that("an https base to an http url is admitted only under the flag", {
  base <- "https://example.com/"
  expect_identical(
    ssrf_inspect_url("http://example.com/", base = base)$code,
    "downgrade"
  )
  open <- ssrf_policy(allow_downgrade = TRUE)
  expect_identical(
    ssrf_inspect_url("http://example.com/", open, base = base)$code,
    NA_character_
  )
  # A relative reference keeps the base's https: no downgrade either way.
  expect_identical(
    ssrf_inspect_url("/next", open, base = base)$code,
    NA_character_
  )
})

test_that("the flag lifts only the downgrade check of step 3", {
  base <- "https://example.com/"
  # Still refused: a scheme outside allow_schemes, then the later steps.
  tls_only <- ssrf_policy(allow_schemes = "https", allow_downgrade = TRUE)
  expect_identical(
    ssrf_inspect_url("http://example.com/", tls_only, base = base)$code,
    "scheme"
  )
  open <- ssrf_policy(allow_downgrade = TRUE)
  expect_identical(
    ssrf_inspect_url("http://u:p@example.com/", open, base = base)$code,
    "userinfo"
  )
  expect_identical(
    ssrf_inspect_url("http://example.com:8080/", open, base = base)$code,
    "port"
  )
  expect_identical(
    ssrf_inspect_url("http://127.0.0.1/", open, base = base)$code,
    "loopback"
  )
})

test_that("ssrf_prepare_hop() returns a binding for https to http under the flag", {
  skip_if_no_webfakes()
  mock_answers("127.0.0.1")
  tls <- local_redirect_server(tls = TRUE)
  tport <- tls$get_port()
  local_trust_test_ca()
  target <- paste0("http://legit.example:", tport, "/")
  request <- list(headers = c(`X-Corpus-Location` = target))

  closed <- loopback_policy(tport)
  b <- ssrf_prepare_hop(
    paste0("https://legit.example:", tport, "/"),
    closed,
    request = request
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  r <- ssrf_prepare_hop(b$state$location, closed, from = b)
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "downgrade")

  open <- loopback_policy(tport, allow_downgrade = TRUE)
  b <- ssrf_prepare_hop(
    paste0("https://legit.example:", tport, "/"),
    open,
    request = request
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  up <- ssrf_prepare_hop(b$state$location, open, from = b)
  expect_s3_class(up, "ssrfr_binding")
  expect_identical(up$origin$scheme, "http")

  # The flag is read from the redirect hop's own policy, not from `from`'s.
  r <- ssrf_prepare_hop(b$state$location, closed, from = b)
  expect_s3_class(r, "ssrfr_refusal")
  expect_identical(r$code, "downgrade")
  b <- ssrf_prepare_hop(
    paste0("https://legit.example:", tport, "/"),
    closed,
    request = request
  )
  expect_identical(ssrf_fetch(b)$status, 302L)
  up <- ssrf_prepare_hop(b$state$location, open, from = b)
  expect_s3_class(up, "ssrfr_binding")
})

test_that("a chain under the flag follows https to http and drops credentials", {
  skip_if_no_webfakes()
  mock_answers("127.0.0.1")
  plain <- local_redirect_server()
  hport <- plain$get_port()
  tls <- local_redirect_server(tls = TRUE)
  tport <- tls$get_port()
  local_trust_test_ca()
  to <- paste0("http://legit.example:", hport, "/echo")
  start <- paste0(
    "https://legit.example:",
    tport,
    "/r/302?to=",
    utils::URLencode(to, TRUE)
  )
  request <- list(
    headers = c(Authorization = "Bearer secret", `X-Trace` = "t1"),
    carry = "x-trace"
  )

  refused <- ssrf_fetch_chain(
    start,
    loopback_policy(c(tport, hport)),
    request = request
  )
  expect_s3_class(refused, "ssrfr_refusal")
  expect_identical(refused$code, "downgrade")

  r <- ssrf_fetch_chain(
    start,
    loopback_policy(c(tport, hport), allow_downgrade = TRUE),
    request = request
  )
  expect_identical(r$status, 200L)
  fields <- strsplit(r$headers[["x-echo-fields"]], ",", fixed = TRUE)[[1L]]
  expect_false("authorization" %in% fields)
  # A field nominated in `carry` crosses, now in plaintext (§5.3).
  expect_true("x-trace" %in% fields)
})
