# L0, structural inspection (ssrfr-v1.md §1, §1.1): the facts a URL carries
# under a policy, with no I/O. L0 reports; it is not a gate and not a defense.
# It runs steps 1-6 of the request lifecycle (§12) and, for an address-literal
# host, gates 1-3 (§5), which need no resolution. A name is not resolved here:
# that is L1, and only L2's guarded fetch is a defense (S2).
#
# The internal steps are separate so later layers reuse them without parsing
# again: parse_hop() (R/parse.R) for steps 1-5, host_policy() for step 6, and
# address_gates() (R/address.R) for gates 1-3 on one address, which L1 calls
# once per resolved address.

# Steps 1-6, and gates 1-3 for an address literal. Returns parse_hop()'s list
# with `finding` set by the first step that refuses, and `address_facts` for
# an address literal that reached the address gates.
inspect_hop <- function(url, policy, base = NULL) {
  hop <- parse_hop(url, policy, base)
  if (is.null(hop$finding)) {
    hop$finding <- host_policy(hop, policy)
  }
  if (is.null(hop$finding) && hop$host_kind %in% c("ipv4", "ipv6")) {
    gates <- address_gates(hop$address, policy)
    hop$finding <- gates$finding
    hop$address_facts <- gates$facts
    if (!is.null(hop$finding)) {
      hop$finding$host <- hop$host
    }
  }
  hop
}

#' Inspect a URL without fetching it
#'
#' Reports what a URL is under a policy, without any network I/O: whether it
#' parses without ambiguity, what scheme, host and port the transport would
#' act on, and, for a host written as an address, how that address is
#' classified. This is `ssrfr`'s structural layer (L0). It is a fast
#' pre-filter and a way to lint a configuration, **not a defense**: it
#' resolves no name, so it cannot see where a name points, and a URL it finds
#' nothing wrong with may still be refused when fetched. Only the guarded
#' fetch protects a request.
#'
#' The URL is parsed as the guarded fetch parses it: `rurl` under the WHATWG
#' URL Standard, then libcurl's own parser on the string libcurl would be
#' handed. A URL the two parsers read differently is reported as `"parse"`.
#' Checks run in the order of a guarded hop, and the first one that applies
#' names the reason code: the length limit and the parse, the scheme, embedded
#' credentials, the port, an ambiguous numeric host spelling, the hostname
#' rules, and, for an address literal, the address rules. A relative
#' reference, such as a redirect's `Location`, is resolved against `base`
#' first.
#'
#' @param url The URL, a single string.
#' @param policy The policy to inspect it under, from [ssrf_policy()].
#' @param base The URL of the previous hop, a single string, when `url` came
#'   from a redirect: `url` may then be a relative reference, and an `https`
#'   `base` makes an `http` `url` a `"downgrade"`. `NULL`, the default, for a
#'   first hop, which must be an absolute URL.
#'
#' @return An object of class `ssrfr_inspection`, a list of facts:
#'   \describe{
#'     \item{`code`}{The reason code (see `ssrf_vocabulary("reason_codes")`)
#'       that the first applicable check reports, or `NA` when no check at
#'       this layer applies. `NA` is not an approval: a name is still to be
#'       resolved and every address it resolves to classified.}
#'     \item{`step`}{The step of a guarded hop that reported `code`, from 1
#'       (parse) to 8 (address classification), or `NA`.}
#'     \item{`detail`}{Operator detail for `code`: the gate and precedence
#'       tier, and the address category, embedding kind or provider-endpoint
#'       kind behind it.}
#'     \item{`url`}{The URL as given, for display, without userinfo.}
#'     \item{`scheme`, `host`, `port`}{The scheme, host and effective port
#'       libcurl reads, or `NA` when the URL did not parse that far.}
#'     \item{`userinfo`}{Whether the URL carries credentials.}
#'     \item{`host_kind`}{`"name"`, `"ipv4"` or `"ipv6"`, or `NA`.}
#'     \item{`address`}{For an address literal, `raddr`'s facts about it:
#'       its canonical text, reachability, category, embedded addresses and
#'       provider-endpoint row. `NULL` otherwise.}
#'   }
#'
#' @seealso [ssrf_policy()] for the rules; [ssrf_vocabulary()] for the reason
#'   codes, the provider endpoints and the metadata hostnames.
#'
#' @examples
#' ssrf_inspect_url("http://127.0.0.1/admin")$code
#' ssrf_inspect_url("http://0177.0.0.1/")$code
#' ssrf_inspect_url("http://[::ffff:169.254.169.254]/")$code
#'
#' # A name is not resolved: nothing applies at this layer.
#' ssrf_inspect_url("https://example.com/")
#'
#' # Lint a policy: does it reopen what it should, and nothing more?
#' policy <- ssrf_policy(allow_ranges = "10.0.0.0/8", deny_hosts = ".corp")
#' ssrf_inspect_url("http://10.1.2.3/", policy)$code
#' ssrf_inspect_url("http://api.corp/", policy)$code
#'
#' # A redirect's Location, resolved against the previous hop.
#' ssrf_inspect_url("//169.254.169.254/", base = "http://example.com/a")$code
#'
#' @export
ssrf_inspect_url <- function(url, policy = ssrf_policy(), base = NULL) {
  bad <- function(message) {
    abort_ssrfr("invalid_argument", message, fn = "ssrf_inspect_url")
  }
  if (!is_string(url)) {
    bad("`url` must be a single string.")
  }
  if (!inherits(policy, "ssrfr_policy")) {
    bad("`policy` must be a policy built by ssrf_policy().")
  }
  if (!is.null(base) && !is_string(base)) {
    bad("`base` must be a single string, or NULL for a first hop.")
  }
  hop <- inspect_hop(enc2utf8(url), policy, base = base)
  finding <- hop$finding
  str_or_na <- function(x) if (is.null(x)) NA_character_ else x
  structure(
    list(
      code = str_or_na(finding$code),
      step = if (is.null(finding)) NA_integer_ else finding$detail$step,
      detail = if (is.null(finding)) list() else finding$detail[-1L],
      url = redact_url(url),
      scheme = str_or_na(hop$scheme),
      host = str_or_na(hop$host),
      port = if (is.null(hop$port)) NA_integer_ else hop$port,
      userinfo = isTRUE(hop$userinfo),
      host_kind = if (is.null(hop$host_kind)) NA_character_ else hop$host_kind,
      address = hop$address_facts
    ),
    class = "ssrfr_inspection"
  )
}

#' @export
format.ssrfr_inspection <- function(x, ...) {
  line <- function(label, value) {
    if (length(value) != 1L || is.na(value)) {
      NULL
    } else {
      paste0("  ", label, ": ", value)
    }
  }
  detail <- NULL
  for (key in intersect(names(x$detail), display_detail_keys)) {
    detail <- c(
      detail,
      paste0("    ", key, ": ", toString(format(x$detail[[key]], trim = TRUE)))
    )
  }
  c(
    "<ssrfr_inspection> (L0: facts, not a defense)",
    paste0("  code: ", if (is.na(x$code)) "none at L0" else x$code),
    line("step", x$step),
    if (length(detail)) c("  detail:", detail),
    line("url", x$url),
    line("scheme", x$scheme),
    line("host", x$host),
    line("host kind", x$host_kind),
    line("port", x$port),
    if (x$userinfo) "  userinfo: present (withheld)"
  )
}

#' @export
print.ssrfr_inspection <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}
