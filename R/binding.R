# L2, the guarded hop (ssrfr-v1.md §1, §2): ssrf_prepare_hop() runs steps
# 1-8 of the request lifecycle (§12) and returns a refusal, an operational
# failure, or a binding; ssrf_fetch() (R/fetch.R) consumes the binding. Only
# this layer is a defense (S2).
#
# A binding (§2.3) holds the security identity (the origin without userinfo,
# the policy by value, the hop context, the validated address set and the
# selected pin, the TLS settings bound to the hostname) and the request data
# (the wire URL without fragment, the sanitized plan). It is an environment
# with locked bindings: opacity is ergonomic, not enforceable (§2.4). Its
# `state` records what fetching it did: fetchability, spent on entry to
# ssrf_fetch() (§2.5), and the transport-observed facts (status, Location,
# the pin used, each attempt).

# Seconds elapsed since `start`, a value of proc.time()[["elapsed"]].
elapsed_since <- function(start) {
  proc.time()[["elapsed"]] - start
}

now <- function() {
  proc.time()[["elapsed"]]
}

#' Prepare one guarded hop
#'
#' Decides whether a URL may be fetched under a policy and, when it may,
#' returns the exact connection it may use. This is the first half of the
#' guarded fetch, the only part of `ssrfr` that is a defense against
#' server-side request forgery; [ssrf_fetch()] is the second.
#'
#' The URL is parsed as the transport will parse it, checked for its scheme,
#' embedded credentials, port, host spelling and hostname rules, then, for a
#' name, resolved exactly once, with a trailing root dot so no DNS search
#' domain applies. Every address it resolves to is classified with the
#' addresses embedded in it, and one refused address refuses the whole set.
#' A URL that passes becomes a binding pinned to those validated addresses:
#' [ssrf_fetch()] connects only to them, never resolving the name again, so a
#' name cannot be rebound between the check and the connection.
#'
#' The request plan is part of the decision. It is a list of up to four
#' fields, each optional:
#' \describe{
#'   \item{`method`}{The request method, `"GET"` by default. Any HTTP token is
#'     accepted; the application decides which methods an untrusted party
#'     may choose.}
#'   \item{`headers`}{Header fields to send, as a named character vector or a
#'     named list of strings. Names must be HTTP tokens and values carry no
#'     CR or LF. Fields the transport owns (`Host`, `Connection`,
#'     `Proxy-Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`,
#'     `Trailer`, `Upgrade`, `Content-Length`, `Accept-Encoding`, `Expect`
#'     and `User-Agent`, which the policy sets) are refused, and so are the
#'     metadata-service request markers of `ssrf_vocabulary("metadata_headers")`
#'     unless the policy's `allow_ranges` names a provider endpoint exactly.}
#'   \item{`body`}{The request body: a raw vector or a single string, sent as
#'     its UTF-8 bytes. `NULL` (the default) sends none.}
#'   \item{`carry`}{Names of fields in `headers` the application asserts
#'     carry no credential, so a redirect to another origin may keep them.
#'     Every other field and the body are treated as secret.
#'     `Authorization`, `Proxy-Authorization` and `Cookie` can never be
#'     nominated.}
#' }
#' `list()` is a plain `GET`. A plan that breaks one of these rules is an
#' error of class `ssrfr_error_invalid_request`, raised before anything is
#' parsed or resolved.
#'
#' Only the first hop of a redirect chain is supported so far: `from` must be
#' `NULL`.
#'
#' The binding is single-use: [ssrf_fetch()] spends it on entry. It prints
#' without userinfo, header values or the body, and holds the policy by value,
#' so a later change to the policy object does not reach it.
#'
#' @param url The URL, a single absolute URL string.
#' @param policy The policy to decide under, from [ssrf_policy()].
#' @param request The request plan for a first hop, a list as described
#'   above; `list()` for a plain `GET`. Exactly one of `request` and `from`
#'   is required.
#' @param from The binding of the previous hop, for a redirect. Not yet
#'   supported: it must be `NULL`.
#'
#' @return One of three values, told apart by class:
#'   \describe{
#'     \item{`ssrfr_binding`}{The hop may proceed: pass it to [ssrf_fetch()].
#'       Its fields can be read with `$`: `hop`, `url` (the URL the fetch
#'       requests, without fragment), `origin` (`scheme`, `host`, `port`),
#'       `validated` (the addresses a connection may use, in resolver
#'       order), `pin` (the first of them), `request` (the sanitized plan),
#'       `policy`, `tls` and `state`, the facts [ssrf_fetch()] records.}
#'     \item{`ssrfr_refusal`}{The policy refuses the hop; `code` is a reason
#'       code from `ssrf_vocabulary("reason_codes")`.}
#'     \item{`ssrfr_failure`}{The hop failed on the wire before a connection:
#'       `cause` is `"unresolvable"` when resolution failed, or `"timeout"`
#'       when resolution used up the policy's `total_timeout`.}
#'   }
#'   A refusal and a failure name the host, address and hop for the
#'   operator; project them with [ssrf_public_reason()] before an untrusted
#'   party sees them.
#'
#' @seealso [ssrf_fetch()] to fetch through a binding; [ssrf_policy()] for the
#'   rules; [ssrf_inspect_url()] to lint a URL or policy without fetching.
#'
#' @examples
#' policy <- ssrf_policy()
#'
#' # Refused before any network I/O.
#' ssrf_prepare_hop("http://127.0.0.1/admin", policy, request = list())
#' ssrf_prepare_hop("http://0177.0.0.1/", policy, request = list())$code
#'
#' # An address host needs no resolution: this binding is pinned to it.
#' binding <- ssrf_prepare_hop(
#'   "https://93.184.216.34/data?page=2",
#'   policy,
#'   request = list(headers = c(Authorization = "Bearer secret"))
#' )
#' binding
#'
#' # A request plan that breaks a header rule is an error.
#' try(ssrf_prepare_hop(
#'   "https://example.com/",
#'   policy,
#'   request = list(headers = c(Host = "internal.example"))
#' ))
#'
#' @export
ssrf_prepare_hop <- function(url, policy, request = NULL, from = NULL) {
  started <- now()
  bad <- function(message) {
    abort_ssrfr("invalid_argument", message, fn = "ssrf_prepare_hop")
  }
  if (!is_string(url)) {
    bad("`url` must be a single string.")
  }
  if (missing(policy) || !inherits(policy, "ssrfr_policy")) {
    bad("`policy` must be a policy built by ssrf_policy().")
  }
  if (!is.null(request) && !is.null(from)) {
    bad("Pass `request` on a first hop or `from` on a redirect hop, not both.")
  }
  if (!is.null(from)) {
    bad(paste0(
      "Redirect hops are not yet supported: `from` must be NULL, and the ",
      "first hop passes `request`."
    ))
  }
  if (is.null(request)) {
    bad(paste0(
      "A first hop needs `request`, its request plan; `list()` is a plain ",
      "GET."
    ))
  }
  plan <- check_request(request, policy)
  prepare_first_hop(enc2utf8(url), policy, plan, started)
}

# Steps 1-8 for a first hop whose request plan is valid. Returns a refusal, a
# failure or a binding.
prepare_first_hop <- function(url, policy, plan, started) {
  hop_index <- 1L
  hop <- parse_hop(url, policy)
  if (is.null(hop$finding)) {
    hop$finding <- host_policy(hop, policy)
  }
  validated <- character()
  if (is.null(hop$finding) && hop$host_kind %in% c("ipv4", "ipv6")) {
    gates <- address_gates(hop$address, policy)
    hop$finding <- gates$finding
    if (is.null(hop$finding)) {
      # The pin target is the literal's canonical text (r-binding.md §2.6).
      canonical <- canonical_address(hop$address)
      if (!is_string(canonical)) {
        hop$finding <- new_finding(
          "malformed-address",
          8L,
          address = hop$address,
          gate = "1b",
          tier = 1L
        )
      }
      validated <- canonical
    }
    if (!is.null(hop$finding)) {
      hop$finding$host <- hop$host
    }
  } else if (is.null(hop$finding)) {
    resolution <- resolve_hop(hop, policy)
    hop$finding <- resolution$finding
    validated <- resolution$validated
  }
  if (!is.null(hop$finding)) {
    return(outcome_of(hop$finding, hop_index, url))
  }
  # §5.3: elapsed time is re-checked after resolution.
  spent <- elapsed_since(started)
  if (spent >= policy$total_timeout) {
    return(new_ssrf_failure(
      "timeout",
      hop_index,
      host = hop$host,
      url = url,
      detail = list(step = 7L, check = "total", limit = "total_timeout")
    ))
  }
  new_binding(hop, policy, plan, validated, hop_index, spent)
}

# A finding of steps 1-8 as the outcome ssrf_prepare_hop() returns: a refusal
# for a reason code, a failure for a cause.
outcome_of <- function(finding, hop_index, url) {
  host <- finding$host
  address <- finding$address
  host <- if (is_string(host)) host else NA_character_
  address <- if (is_string(address)) address else NA_character_
  if (!is.null(finding$cause)) {
    return(new_ssrf_failure(
      finding$cause,
      hop_index,
      host = host,
      address = address,
      url = url,
      detail = finding$detail
    ))
  }
  new_ssrf_refusal(
    finding$code,
    hop_index,
    host = host,
    address = address,
    url = url,
    detail = finding$detail
  )
}

new_binding <- function(hop, policy, plan, validated, hop_index, spent) {
  b <- new.env(parent = emptyenv())
  b$hop <- hop_index
  b$url <- hop$wire
  b$origin <- list(scheme = hop$scheme, host = hop$host, port = hop$port)
  b$policy <- policy
  b$request <- plan
  b$validated <- validated
  b$pin <- validated[[1L]]
  b$tls <- list(verify_peer = TRUE, verify_host = TRUE, name = hop$host)
  b$budget <- list(
    max_redirects = policy$max_redirects,
    total_timeout = policy$total_timeout,
    elapsed = spent
  )
  state <- new.env(parent = emptyenv())
  state$fetchable <- TRUE
  state$fetched <- FALSE
  state$status <- NULL
  state$location <- NULL
  state$location_count <- NULL
  state$outcome <- NULL
  state$pin_used <- NULL
  state$attempts <- character()
  state$elapsed <- spent
  lockEnvironment(state, bindings = TRUE)
  b$state <- state
  lockEnvironment(b, bindings = TRUE)
  class(b) <- "ssrfr_binding"
  b
}

# Writes the named fields of a binding's state. Only ssrfr writes it.
set_state <- function(binding, ...) {
  values <- list(...)
  state <- binding$state
  for (field in names(values)) {
    unlockBinding(field, state)
    assign(field, values[[field]], envir = state)
    lockBinding(field, state)
  }
  invisible(binding)
}

#' @export
format.ssrfr_binding <- function(x, ...) {
  state <- x$state
  plan <- x$request
  fields <- names(plan$headers)
  headers <- if (length(fields)) {
    paste0(toString(fields), " (values withheld)")
  } else {
    "none"
  }
  body <- if (is.null(plan$body)) {
    "none"
  } else {
    paste0(length(plan$body), " bytes (withheld)")
  }
  status <- if (isTRUE(state$fetchable)) {
    "fetchable"
  } else if (isTRUE(state$fetched)) {
    "spent: fetched"
  } else {
    "spent"
  }
  origin <- x$origin
  c(
    paste0("<ssrfr_binding> (hop ", x$hop, ", ", status, ")"),
    paste0(
      "  origin: ",
      origin$scheme,
      "://",
      origin$host,
      ":",
      origin$port
    ),
    paste0("  url: ", redact_url(x$url)),
    paste0("  validated: ", toString(x$validated)),
    paste0("  pin: ", state$pin_used %||% x$pin),
    paste0("  method: ", plan$method),
    paste0("  headers: ", headers),
    paste0("  body: ", body),
    if (length(plan$carry)) paste0("  carry: ", toString(plan$carry)),
    "  tls: certificate and hostname verified",
    if (!is.null(state$status)) paste0("  status: ", state$status),
    if (!is.null(state$outcome)) paste0("  outcome: ", state$outcome)
  )
}

#' @export
print.ssrfr_binding <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}
