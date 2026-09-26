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
#' environment says, redirects are not followed, and the request goes over
#' HTTP/1.1 on a new connection that is closed when the fetch returns.
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
#' exceed it; `max_header_bytes` and `max_header_fields` bound the header,
#' including any interim `1xx` responses and the trailer fields of a chunked
#' body, as it arrives;
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
#'   fields, a character vector named by lowercase field name, without the
#'   trailer fields of a chunked body; a value that is not valid UTF-8 is
#'   kept byte for byte and marked `"bytes"`) and `body` (the decoded
#'   body, a raw vector; `rawToChar(response$body)` reads text). Its
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
  # §6.6: no attempt is made once total_timeout is spent, the first
  # included; the check after a failed attempt below covers each later one.
  if (remaining() <= 0) {
    return(total_timeout_failure(binding, NA_character_, endings, step = 10L))
  }
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
        check = attempt$check,
        callback = attempt$callback
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
        limit = attempt$limit,
        callback = attempt$callback
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
  seen$body_started <- FALSE
  seen$body_since_progress <- FALSE
  seen$abort <- NULL
  # Records the limit reached and answers FALSE, which ends the transfer:
  # the transport wrapper cancels it within the round (R/dependencies.R).
  abort <- function(cause, check, limit) {
    seen$abort <- list(cause = cause, check = check, limit = limit)
    FALSE
  }
  # Every text match here is byte by byte: a trace line may carry obs-text,
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
    }
    NULL
  }
  # Answers TRUE to go on. The header is complete when the first body byte
  # arrives, so a header over its limits ends the transfer there, before any
  # body byte is counted (§6.6). `received` is the transport wrapper's
  # header buffer reader.
  data <- function(x, received) {
    if (!length(x)) {
      return(TRUE)
    }
    seen$body_since_progress <- TRUE
    if (!seen$body_started) {
      seen$body_started <- TRUE
      measure_header(seen, received())
      over <- header_limit(seen, policy)
      if (!is.null(over)) {
        return(abort("response-too-large", "header", over))
      }
    }
    if (remaining() <= 0) {
      return(abort("timeout", "total", "total_timeout"))
    }
    # §5.3: decoded bytes, counted on each delivery; the delivery that passes
    # the limit is not kept.
    if (seen$bytes + length(x) > policy$max_response_size) {
      return(abort("response-too-large", "decoded-bytes", "max_response_size"))
    }
    seen$bytes <- seen$bytes + length(x)
    seen$body[[length(seen$body) + 1L]] <- x
    TRUE
  }
  # §14: the header limits hold while the header arrives, not only once a
  # body does. libcurl calls this after each read and whenever it waits, so
  # a header that never ends, a run of 1xx blocks, or an endless header on
  # a response with no body stops at its limit, not at total_timeout. A
  # chunked body's trailer lines count against the same limits as they
  # arrive. Both are measured from one source, libcurl's header buffer
  # (`received()`), never from the trace, which a build may not write for
  # every read. The buffer grows only while no body byte is delivered: before
  # the body, and after it as trailers. So it is read only on a call that no
  # delivery preceded, which keeps a body in flight from paying for it, and
  # scanned only when it has grown, so an idle wait pays for no scan and
  # each scan costs at most the header limit plus one read. Answers TRUE to
  # go on.
  progress <- function(down, up, received) {
    if (!is.null(seen$abort)) {
      return(FALSE)
    }
    if (!seen$body_since_progress) {
      measure_header(seen, received())
      over <- header_limit(seen, policy)
      if (!is.null(over)) {
        return(abort("response-too-large", "header", over))
      }
    }
    seen$body_since_progress <- FALSE
    TRUE
  }

  transfer <- read_transfer(opts, data, debug, progress)
  if (is.null(transfer)) {
    return(list(ending = "pin-mismatch", check = "no-transfer"))
  }
  # The callbacks that raised an error, which the wrapper caught (a defect,
  # never a limit), in the order they first failed.
  failed <- transfer$failed
  # INV-5: the detector runs on every attempt, whatever its outcome. Absent or
  # unreadable evidence is a mismatch (§6.6), and so is a trace whose
  # callback failed: evidence it may have missed cannot confirm the pin. A
  # trace naming another address, or one that cannot be read, is the pin's
  # own finding and names no other callback. A trace with no `Trying` line
  # beside a failed progress callback, the one callback that runs before
  # libcurl dials, is the one that failure cut short, and names it, even when
  # the trace callback failed after it.
  pin <- pin_check(seen$trace, address, binding$origin$port)
  traced <- !"debug" %in% failed
  if (pin == "match" && !traced) {
    pin <- "trace-error"
  }
  if (pin != "match") {
    callback <- if (pin == "absent" && "progress" %in% failed) {
      "progress"
    } else if (!traced) {
      "debug"
    }
    return(list(ending = "pin-mismatch", check = pin, callback = callback))
  }
  connected <- transfer$connect > 0 ||
    any(startsWith(seen$trace, "Connected to "))
  # A transfer a callback stopped leaves a record, read below: the limit
  # reached (`seen$abort`) or the callback's failure (`failed`).
  stopped <- transfer$aborted
  if (!stopped && !is.null(transfer$error) && !connected) {
    timed_out <- transfer$error == "curl_error_operation_timedout"
    return(list(
      ending = if (timed_out) "connect-timeout" else "connect-failed"
    ))
  }
  ended <- function(cause, step, check, limit = NULL, callback = NULL) {
    list(
      ending = "connected",
      cause = cause,
      step = step,
      check = check,
      limit = limit,
      callback = callback
    )
  }
  # A limit a callback reached ends the transfer, which the wrapper cancels;
  # the record the callback left decides.
  if (!is.null(seen$abort)) {
    a <- seen$abort
    return(ended(a$cause, 12L, a$check, a$limit))
  }
  # A callback that failed ends the transfer too, and fails closed. No cause
  # names a defect of ssrfr's own (§6.6); the closest is `protocol-error`,
  # and the check says what happened. The condition itself is not kept: its
  # message may quote response bytes (INV-12).
  if (length(failed)) {
    return(ended(
      "protocol-error",
      12L,
      "callback-error",
      callback = failed[[1L]]
    ))
  }
  # INV-11: a transfer the wrapper reports stopped, with neither record, is
  # never a response, however whole its header looks.
  if (stopped) {
    return(ended("protocol-error", 12L, "aborted"))
  }
  # The header is complete before libcurl ends a transfer on its own limits,
  # so a header limit it passed was the first limit reached (§6.6). The
  # buffer is measured once more here, before any response is recorded, for
  # trailer lines that arrived after the last progress call.
  measure_header(seen, transfer$headers)
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
  # The status libcurl reports and the header block ssrfr reads must be the
  # same response's: the status is transport-observed (§2.3), and a
  # disagreement records neither. The parse reads the segments the measure
  # above took of these same bytes, never segmenting them again.
  segments <- if (identical(seen$segmented, transfer$headers)) seen$segments
  parsed <- parse_response_headers(transfer$headers, segments)
  if (is.null(parsed) || parsed$status != transfer$status) {
    return(ended("protocol-error", 12L, "header"))
  }
  headers <- parsed$headers
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

# The header limit the response has passed (§5.3), or NULL. A chunked
# body's trailer fields count against the same limits as the header.
header_limit <- function(seen, policy) {
  if (seen$header_bytes > policy$max_header_bytes) {
    return("max_header_bytes")
  }
  if (seen$header_fields > policy$max_header_fields) {
    return("max_header_fields")
  }
  NULL
}

# Records the size of `buffer`, libcurl's header buffer so far: every byte,
# and as fields every line but an empty one and the status line that opens
# a header block: every other header line, and every trailer line that is
# not empty. The lines are read as header_segments() (R/transport.R) reads
# them for the parse, by the block before each: a block cut short is still a
# header block, and every line after a complete final block is a trailer
# line, so a count taken while the buffer arrives and one taken once it is
# whole agree. The buffer only grows, so a buffer of the length last
# measured is not scanned again.
measure_header <- function(seen, buffer) {
  if (!is.raw(buffer) || identical(seen$measured, length(buffer))) {
    return(invisible())
  }
  seen$measured <- length(buffer)
  seen$header_bytes <- length(buffer)
  segments <- header_segments(buffer)
  seen$header_fields <- sum(nzchar(segments$lines)) -
    length(segments$blocks$start)
  # Kept for the parse of a completed transfer, with the bytes they read.
  seen$segmented <- buffer
  seen$segments <- segments
  invisible()
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
