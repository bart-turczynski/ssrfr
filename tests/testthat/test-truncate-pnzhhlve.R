# A 2xx body over max_response_size (ssrfr-v1.md §5.3, §6.6; SSRF-pnzhhlve).
# By default the hop fails whole as response-too-large and returns no body.

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

# Fetches a `status` response whose decoded body is truncate_plain(), sent
# as `encoding` ("identity" or "gzip"), under `...` policy fields.
truncate_fetch <- function(
  encoding,
  ...,
  status = "200 OK",
  env = parent.frame()
) {
  plain <- truncate_plain()
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
