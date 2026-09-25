# ssrf_fetch() (ssrfr-v1.md §2.2, §2.5, §12 steps 9-12, §14): consumes a
# binding, connects only to its validated addresses through a `connect_to`
# pin, checks the pin held, and reads the whole response within the limits.
#
# Failover (§2.5): the validated addresses are tried in resolver order, and
# the next is tried only after an attempt that ended before a connection was
# established. `pin-mismatch` ends the fetch at once. When every address has
# been tried, the cause is `timeout` if every attempt's connect timed out and
# `connect-failed` otherwise (§6.6). There are no retries: the request is sent
# at most once.

# Causes of an attempt that established a connection, by curl error class.
# Every TLS failure is `tls-failed`; a class not listed is `protocol-error`.
# A size limit is never libcurl's: ssrfr's own callbacks count the header
# and the decoded body, and record the limit they reached.
curl_error_causes <- c(
  curl_error_operation_timedout = "timeout",
  curl_error_peer_failed_verification = "tls-failed",
  curl_error_use_ssl_failed = "tls-failed"
)

connected_cause <- function(error) {
  if (startsWith(error, "curl_error_ssl_")) {
    return("tls-failed")
  }
  cause <- curl_error_causes[error]
  if (is.na(cause)) "protocol-error" else unname(cause)
}

#' Fetch through a guarded binding
#'
#' Makes the request a binding from [ssrf_prepare_hop()] describes, connecting
#' only to an address that binding validated. The name is never resolved
#' again: the connection is pinned to the validated address while TLS, the
#' `Host` header and certificate verification stay bound to the hostname.
#' Certificate verification is never weakened, no proxy is used whatever the
#' environment says, redirects are not followed, and the connection is closed
#' when the fetch returns.
#'
#' A binding is single-use. `ssrf_fetch()` spends it on entry, so a second
#' call with the same binding is an error of class
#' `ssrfr_error_spent_binding`, even when the first was interrupted. The
#' spent binding stays readable: its `state` records the response status,
#' the `Location` field, the address the connection was pinned to and each
#' address tried.
#'
#' When a name resolved to several addresses, they are tried in the order
#' the resolver returned them, moving on only when a connection could not be
#' established; a request is never sent twice. After connecting, `ssrfr`
#' confirms from libcurl's trace that the connection went to the pinned
#' address; if it cannot, the fetch fails as `"pin-mismatch"` without trying
#' another address.
#'
#' The whole response is read before `ssrf_fetch()` returns, within the
#' policy's limits: `max_response_size` counts the body's bytes after any
#' `gzip` or `deflate` decoding, as they arrive, so a compressed body cannot
#' exceed it; `max_header_bytes` and `max_header_fields` bound the header;
#' `connect_timeout` bounds each connection attempt and `total_timeout` the
#' time spent in `ssrfr` for the chain, decoding included.
#'
#' A redirect is returned, not followed: its status and `Location` are in the
#' response. `ssrfr` guards only requests made through a binding. R's own
#' `download.file()`, `url()`, `readLines()` on a URL, direct `curl` calls,
#' and the packages that read URLs through them, such as
#' `jsonlite::fromJSON(url)`, `data.table::fread(url)` and
#' `xml2::read_xml(url)`, stay unguarded, as does the `curl` command-line
#' tool.
#'
#' @section Testing against a local server:
#' A loopback server is a refused destination, so a test that fetches one
#' through the guard reopens loopback in its own policy, with
#' `ssrf_policy(allow_ranges = "127.0.0.0/8", allow_ports = <port>)`. `ssrfr`
#' has no test mode and no switch that turns the guard off; keep such a
#' policy out of production code.
#'
#' @param binding A binding from [ssrf_prepare_hop()] that has not been
#'   fetched.
#'
#' @return Either a response, class `ssrfr_response`, or an operational
#'   failure, class `ssrfr_failure`.
#'
#'   A response is a plain list that owns no handle, connection or file:
#'   `status` (the HTTP status code), `headers` (the final response's header
#'   fields, a character vector named by lowercase field name) and `body` (the
#'   decoded body, a raw vector; `rawToChar(response$body)` reads text). Its
#'   `print()` and `format()` show only the status, the media type and the
#'   body size, never the body or another header value.
#'
#'   A failure carries `cause`, from `ssrf_vocabulary("causes")`:
#'   `"connect-failed"`, `"timeout"`, `"tls-failed"`, `"pin-mismatch"`,
#'   `"response-too-large"` or `"protocol-error"`. Its `detail` lists each
#'   address tried and how the attempt ended, and names the limit that was
#'   reached.
#'
#' @seealso [ssrf_prepare_hop()], which makes the binding;
#'   [ssrf_public_reason()] before a failure reaches an untrusted party.
#'
#' @examples
#' binding <- ssrf_prepare_hop(
#'   "https://93.184.216.34/",
#'   ssrf_policy(),
#'   request = list()
#' )
#' \dontrun{
#' response <- ssrf_fetch(binding)
#' response
#' response$status
#' rawToChar(response$body)
#'
#' # A binding is spent on first use.
#' try(ssrf_fetch(binding))
#' binding$state$status
#' }
#'
#' # In a test, reach a local server by reopening loopback in the policy:
#' test_policy <- ssrf_policy(allow_ranges = "127.0.0.0/8", allow_ports = 8080)
#' ssrf_prepare_hop("http://127.0.0.1:8080/", test_policy, request = list())
#'
#' @export
ssrf_fetch <- function(binding) {
  if (!inherits(binding, "ssrfr_binding")) {
    abort_ssrfr(
      "invalid_argument",
      "`binding` must be a binding returned by ssrf_prepare_hop().",
      fn = "ssrf_fetch"
    )
  }
  if (!isTRUE(binding$state$fetchable)) {
    abort_ssrfr(
      "spent_binding",
      "This binding was already fetched; prepare the hop again.",
      fn = "ssrf_fetch"
    )
  }
  # §2.5: fetchability is spent on entry, before anything can fail.
  set_state(binding, fetchable = FALSE)
  started <- now()
  on.exit(
    set_state(
      binding,
      elapsed = binding$budget$elapsed + elapsed_since(started)
    ),
    add = TRUE
  )
  result <- guarded_transfer(binding, started)
  set_state(
    binding,
    outcome = if (inherits(result, "ssrfr_response")) {
      "response"
    } else {
      result$cause
    }
  )
  result
}

# Steps 9-12 over the validated addresses, in resolver order.
guarded_transfer <- function(binding, started) {
  budget <- binding$budget$total_timeout - binding$budget$elapsed
  remaining <- function() budget - elapsed_since(started)
  capabilities <- session_curl_capabilities()
  endings <- character()
  for (address in binding$validated) {
    attempt <- attempt_address(binding, address, remaining, capabilities)
    endings <- c(endings, paste(address, attempt$ending))
    set_state(binding, attempts = endings)
    if (attempt$ending == "pin-mismatch") {
      return(fetch_failure(
        binding,
        "pin-mismatch",
        address,
        endings,
        step = 11L,
        check = attempt$check
      ))
    }
    if (attempt$ending %in% c("connect-failed", "connect-timeout")) {
      if (remaining() <= 0) {
        return(total_timeout_failure(binding, address, endings, step = 10L))
      }
      next
    }
    set_state(binding, pin_used = address)
    if (!is.null(attempt$cause)) {
      return(fetch_failure(
        binding,
        attempt$cause,
        address,
        endings,
        step = attempt$step,
        check = attempt$check,
        limit = attempt$limit
      ))
    }
    # §5.3: elapsed time is re-checked after decoding, which the transport's
    # own timer does not preempt.
    if (remaining() <= 0) {
      return(total_timeout_failure(binding, address, endings, step = 12L))
    }
    # The binding records a successful response only now (§2.3).
    set_state(binding, fetched = TRUE)
    return(attempt$response)
  }
  timed_out <- all(endsWith(endings, " connect-timeout"))
  fetch_failure(
    binding,
    if (timed_out) "timeout" else "connect-failed",
    NA_character_,
    endings,
    step = 10L,
    check = "failover-exhausted"
  )
}

# §6.6: total_timeout elapsing is `timeout` wherever it happens; `address`
# is the one last attempted.
total_timeout_failure <- function(binding, address, endings, step) {
  fetch_failure(
    binding,
    "timeout",
    address,
    endings,
    step = step,
    check = "total",
    limit = "total_timeout"
  )
}

fetch_failure <- function(binding, cause, address, endings, step, ...) {
  detail <- c(list(step = as.integer(step)), Filter(Negate(is.null), list(...)))
  if (length(endings)) {
    detail$attempts <- endings
  }
  new_ssrf_failure(
    cause,
    binding$hop,
    host = binding$origin$host,
    address = address,
    url = binding$url,
    detail = detail
  )
}

# One connection attempt at `address`. Returns a list: `ending`, how the
# attempt ended ("pin-mismatch", "connect-failed", "connect-timeout", or
# "connected"); for a connected attempt either `cause` (with `step`, `check`
# and `limit`) or `response`; for a pin mismatch, `check`.
attempt_address <- function(binding, address, remaining, capabilities) {
  policy <- binding$policy
  opts <- transport_options(binding, address, remaining(), capabilities)
  seen <- new.env(parent = emptyenv())
  seen$trace <- character()
  seen$header_bytes <- 0
  seen$header_fields <- 0L
  seen$body <- list()
  seen$bytes <- 0
  seen$abort <- NULL
  abort <- function(cause, check, limit) {
    seen$abort <- list(cause = cause, check = check, limit = limit)
    stop(errorCondition("transfer aborted", class = "ssrfr_transfer_abort"))
  }
  # Every text match here is byte by byte: a header line may carry obs-text,
  # and a failed translation would warn with the line's bytes (INV-12).
  debug <- function(type, msg) {
    if (type == 0L) {
      text <- tryCatch(rawToChar(msg), error = function(e) "")
      lines <- strsplit(text, "\n", fixed = TRUE, useBytes = TRUE)[[1L]]
      lines <- gsub("^[ \t\r]+|[ \t\r]+$", "", lines, useBytes = TRUE)
      seen$trace <- c(
        seen$trace,
        grep("^(Trying|Connected to) ", lines, value = TRUE, useBytes = TRUE)
      )
    } else if (type == 1L) {
      seen$header_bytes <- seen$header_bytes + length(msg)
      line <- rawToChar(msg[msg != as.raw(0L)])
      if (!grepl("^(HTTP/|\r?\n?$)", line, useBytes = TRUE)) {
        seen$header_fields <- seen$header_fields + 1L
      }
    }
    NULL
  }
  data <- function(x, final = FALSE) {
    if (!length(x)) {
      return(invisible())
    }
    over <- header_limit(seen, policy)
    if (!is.null(over)) {
      abort("response-too-large", "header", over)
    }
    if (remaining() <= 0) {
      abort("timeout", "total", "total_timeout")
    }
    # §5.3: decoded bytes, counted on each delivery; the delivery that passes
    # the limit is not kept.
    if (seen$bytes + length(x) > policy$max_response_size) {
      abort("response-too-large", "decoded-bytes", "max_response_size")
    }
    seen$bytes <- seen$bytes + length(x)
    seen$body[[length(seen$body) + 1L]] <- x
    invisible()
  }
  # §14: the header limits hold while the header arrives, not only once a
  # body does. libcurl calls this after each read, header lines included,
  # so a header that never ends, a run of 1xx blocks, or an endless header
  # on a response with no body stops at its limit, not at total_timeout.
  # Returning FALSE ends the transfer.
  progress <- function(down, up) {
    if (is.null(seen$abort)) {
      over <- header_limit(seen, policy)
      if (!is.null(over)) {
        seen$abort <- list(
          cause = "response-too-large",
          check = "header",
          limit = over
        )
      }
    }
    is.null(seen$abort)
  }

  transfer <- read_transfer(opts, data, debug, progress)
  if (is.null(transfer)) {
    return(list(ending = "pin-mismatch", check = "no-transfer"))
  }
  # INV-5: the detector runs on every attempt, whatever its outcome. Absent or
  # unreadable evidence is a mismatch (§6.6).
  pin <- pin_check(seen$trace, address, binding$origin$port)
  if (pin != "match") {
    return(list(ending = "pin-mismatch", check = pin))
  }
  connected <- transfer$connect > 0 ||
    any(startsWith(seen$trace, "Connected to "))
  if (is.null(seen$abort) && !is.null(transfer$error) && !connected) {
    timed_out <- transfer$error == "curl_error_operation_timedout"
    return(list(
      ending = if (timed_out) "connect-timeout" else "connect-failed"
    ))
  }
  ended <- function(cause, step, check, limit = NULL) {
    list(
      ending = "connected",
      cause = cause,
      step = step,
      check = check,
      limit = limit
    )
  }
  # A limit a callback reached ends the transfer. curl reports it either by
  # re-raising the callback's condition or as a write error, so the record
  # the callback left decides.
  if (!is.null(seen$abort)) {
    a <- seen$abort
    return(ended(a$cause, 12L, a$check, a$limit))
  }
  if (transfer$aborted) {
    return(ended("protocol-error", 12L, "aborted"))
  }
  # The header is complete before libcurl ends a transfer on its own limits,
  # so a header limit it passed was the first limit reached (§6.6).
  over <- header_limit(seen, policy)
  if (!is.null(over)) {
    return(ended("response-too-large", 12L, "header", over))
  }
  if (!is.null(transfer$error)) {
    cause <- connected_cause(transfer$error)
    limit <- if (cause == "timeout") "total_timeout"
    step <- if (cause == "tls-failed") 10L else 12L
    return(ended(cause, step, "transport", limit))
  }
  headers <- parse_response_headers(transfer$headers)
  if (is.null(headers)) {
    return(ended("protocol-error", 12L, "header"))
  }
  locations <- unname(headers[names(headers) == "location"])
  set_state(
    binding,
    status = as.integer(transfer$status),
    location_count = length(locations),
    location = if (length(locations) == 1L) locations else NULL
  )
  # §2.3, §6.6: more than one Location field line.
  if (length(locations) > 1L) {
    return(ended("protocol-error", 12L, "location"))
  }
  list(
    ending = "connected",
    response = new_ssrf_response(
      transfer$status,
      headers,
      if (length(seen$body)) do.call(c, seen$body) else raw()
    )
  )
}

# The header limit the response has passed (§5.3), or NULL.
header_limit <- function(seen, policy) {
  if (seen$header_bytes > policy$max_header_bytes) {
    return("max_header_bytes")
  }
  if (seen$header_fields > policy$max_header_fields) {
    return("max_header_fields")
  }
  NULL
}

new_ssrf_response <- function(status, headers, body) {
  structure(
    list(status = as.integer(status), headers = headers, body = body),
    class = "ssrfr_response"
  )
}

#' @export
format.ssrfr_response <- function(x, ...) {
  type <- display_media_type(unname(x$headers[
    names(x$headers) == "content-type"
  ]))
  c(
    "<ssrfr_response>",
    paste0("  status: ", x$status),
    paste0("  type: ", if (is.na(type)) "none" else type),
    paste0("  body: ", length(x$body), " bytes (read it with $body)")
  )
}

#' @export
print.ssrfr_response <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}
