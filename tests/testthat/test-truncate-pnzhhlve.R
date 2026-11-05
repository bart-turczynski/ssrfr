# A 2xx body over max_response_size (ssrfr-v1.md §5.3, §6.6; SSRF-pnzhhlve).
# By default the hop fails whole as response-too-large and returns no body.
# Under the policy's truncate_body, a 2xx body is returned cut at the limit,
# marked truncated, with the decoded bytes reached; any other status still
# fails whole.

# The decoded body every server here sends: 300,000 bytes of a repeating
# line, so a prefix is checkable byte for byte and gzip packs it small.
truncate_plain <- function() {
  rep_len(charToRaw("User-agent: *\nDisallow: /private/\n"), 300000L)
}

# `x` in the gzip format (RFC 1952), written by gzfile(); memCompress()
# writes the zlib format, which is HTTP's `deflate`.
truncate_gzip <- function(x) {
  path <- tempfile("truncate-", fileext = ".gz")
  on.exit(unlink(path))
  con <- gzfile(path, "wb")
  writeBin(x, con)
  close(con)
  readBin(path, raw(), file.size(path))
}

# A raw server's response: `head`, then `body` in 16 KiB writes, until they
# are sent or the client goes away.
truncate_respond <- function(head, body) {
  respond <- function(con) {
    writeBin(HEAD, con)
    bytes <- BODY
    at <- 0L
    while (at < length(bytes)) {
      n <- min(16384L, length(bytes) - at)
      sent <- tryCatch(
        {
          writeBin(bytes[at + seq_len(n)], con)
          flush(con)
          TRUE
        },
        error = function(e) FALSE
      )
      if (!sent) {
        break
      }
      at <- at + n
    }
  }
  body(respond) <- do.call(
    substitute,
    list(body(respond), list(HEAD = head, BODY = body))
  )
  respond
}

# Fetches a `status` response whose decoded body is `plain`, sent as
# `encoding` ("identity" or "gzip"), under `...` policy fields.
truncate_fetch <- function(
  encoding,
  ...,
  status = "200 OK",
  plain = truncate_plain(),
  env = parent.frame()
) {
  sent <- if (encoding == "gzip") truncate_gzip(plain) else plain
  head <- wire(
    "HTTP/1.1 ",
    status,
    "\r\nContent-Type: text/plain\r\n",
    if (encoding == "gzip") "Content-Encoding: gzip\r\n",
    "Content-Length: ",
    length(sent),
    "\r\nConnection: close\r\n\r\n"
  )
  server <- local_raw_server(truncate_respond(head, sent), env = env)
  policy <- loopback_policy(server$port, ...)
  r <- guarded_get(pinned_url(server$port), policy)
  list(result = r, binding = attr(r, "binding"), plain = plain)
}

# The refusal a body over the limit gets, whole, with no body (§6.6).
expect_body_refused <- function(got, status = 200L) {
  r <- got$result
  expect_s3_class(r, "ssrfr_failure")
  expect_identical(r$cause, "response-too-large")
  expect_identical(r$detail$check, "decoded-bytes")
  expect_identical(r$detail$limit, "max_response_size")
  expect_identical(r$detail$status, status)
  expect_gt(r$detail$observed_bytes, 100000)
  expect_null(r$body)
  expect_false(got$binding$state$fetched)
}

test_that("by default an identity 2xx body over the limit refuses whole", {
  mock_answers("127.0.0.1")
  expect_body_refused(truncate_fetch("identity", max_response_size = 100000))
})

test_that("by default a gzip 2xx body over the limit refuses whole", {
  mock_answers("127.0.0.1")
  expect_body_refused(truncate_fetch("gzip", max_response_size = 100000))
})

# A 2xx body cut at the limit: its first 100,000 decoded bytes, marked
# truncated, with the bytes reached past the limit but short of the whole.
expect_body_truncated <- function(got) {
  r <- got$result
  expect_s3_class(r, "ssrfr_response")
  expect_identical(r$status, 200L)
  expect_identical(r$body, got$plain[seq_len(100000L)])
  expect_true(r$truncated)
  expect_type(r$observed_bytes, "double")
  expect_gt(r$observed_bytes, 100000)
  expect_lte(r$observed_bytes, length(got$plain))
  expect_true(got$binding$state$fetched)
  expect_identical(got$binding$state$status, 200L)
}

test_that("truncate_body keeps an identity 2xx body's first bytes", {
  mock_answers("127.0.0.1")
  expect_body_truncated(truncate_fetch(
    "identity",
    max_response_size = 100000,
    truncate_body = TRUE
  ))
})

test_that("truncate_body keeps a gzip 2xx body's first decoded bytes", {
  mock_answers("127.0.0.1")
  got <- truncate_fetch(
    "gzip",
    max_response_size = 100000,
    truncate_body = TRUE
  )
  expect_body_truncated(got)
  # The limit counts decoded bytes: the whole body is small on the wire.
  expect_lt(length(truncate_gzip(got$plain)), 100000L)
})

test_that("truncate_body marks a body within the limit not truncated", {
  mock_answers("127.0.0.1")
  for (encoding in c("identity", "gzip")) {
    got <- truncate_fetch(
      encoding,
      max_response_size = 300000,
      truncate_body = TRUE
    )
    r <- got$result
    expect_s3_class(r, "ssrfr_response")
    expect_identical(r$body, got$plain)
    expect_false(r$truncated)
    expect_identical(r$observed_bytes, 300000)
  }
})

test_that("a response under the default policy carries no truncation fields", {
  mock_answers("127.0.0.1")
  got <- truncate_fetch("identity", max_response_size = 300000)
  expect_named(got$result, c("status", "headers", "body"))
})

test_that("truncate_body still refuses a non-2xx body over the limit", {
  mock_answers("127.0.0.1")
  expect_body_refused(
    truncate_fetch(
      "identity",
      max_response_size = 100000,
      truncate_body = TRUE,
      status = "404 Not Found"
    ),
    status = 404L
  )
})

test_that("truncate_body cuts at a byte, inside a UTF-8 character", {
  mock_answers("127.0.0.1")
  # U+017C, two bytes in UTF-8: an odd limit splits one.
  plain <- rep_len(as.raw(c(0xc5, 0xbc)), 300000L)
  got <- truncate_fetch(
    "identity",
    max_response_size = 100001,
    truncate_body = TRUE,
    plain = plain
  )
  r <- got$result
  expect_true(r$truncated)
  expect_length(r$body, 100001L)
  expect_identical(r$body[[100001L]], as.raw(0xc5))
})

test_that("truncate_body must be TRUE or FALSE", {
  for (bad in list(NA, "yes", c(TRUE, FALSE), 1)) {
    expect_error(
      ssrf_policy(truncate_body = bad),
      class = "ssrfr_error_invalid_policy"
    )
  }
  expect_true(ssrf_policy(truncate_body = TRUE)$truncate_body)
})
