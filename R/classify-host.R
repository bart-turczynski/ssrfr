# L0 structural classification — the public entry point.
#
# NAMING IS NORMATIVE (ssrf-guard-spec.md §2.1). L0 must be named so it cannot
# be mistaken for a security gate: `is_safe()`, `check()`, and `validate()` are
# explicitly non-conforming names for this layer. The inherited internal name
# was `ssrf_check()`; it does not survive the move, and neither does the
# `allowed` field, which claimed a permission this layer cannot grant.
#
# A caller who believes L0 is the defense has an SSRF vulnerability. The
# advisory for CVE-2026-41488 names the anti-pattern directly:
# "validate-then-fetch with separate DNS resolution."

# Build the small result record. `prohibited` is deliberately the positive
# polarity: FALSE means "not self-evidently prohibited", which is L0's entire
# guarantee, and reads as no kind of permission.
ssrf_classification <- function(prohibited, reason = NA_character_) {
  structure(
    list(prohibited = prohibited, reason = reason),
    class = "ssrfr_classification"
  )
}

# Range and name matching on the normalized host (brackets already stripped).
# Registered names other than the known metadata host pass: resolving them is
# L1's job, and L0 does no I/O.
ssrf_classify_literal <- function(bare) {
  reason <- if (grepl(":", bare, fixed = TRUE)) {
    ssrf_classify_ipv6(bare) # IPv6 literal (contains a colon)
  } else if (ssrf_is_dotted_quad(bare)) {
    ssrf_classify_ipv4(bare) # IPv4 dotted-quad
  } else if (tolower(bare) == "metadata.google.internal") {
    # Hostname rules are a permanent, first-class control, not a stopgap for
    # weak range matching: some metadata services have no link-local address
    # at all and are reached over public DNS and HTTPS, making them invisible
    # to any address classifier.
    "cloud-metadata"
  } else {
    NA_character_
  }
  ssrf_classification(!is.na(reason), reason)
}

#' Structurally classify a host and scheme
#'
#' Decides whether a host is *self-evidently* prohibited — a loopback, private,
#' link-local, or known cloud-metadata literal, an obfuscated numeric encoding,
#' or a scheme outside the `http`/`https` allowlist. Pure and instant: it
#' performs no DNS resolution, opens no socket, and reads no configuration.
#'
#' @section This is not an SSRF defense:
#' `ssrf_classify_host()` is a fast pre-filter and a configuration-linting aid.
#' It is **not** a protection against server-side request forgery, and a caller
#' who treats it as one has a vulnerability rather than a defense.
#'
#' It cannot be a defense because it never resolves anything. A hostname you
#' control resolving to `10.0.0.1` is indistinguishable here from any other
#' name, and a name that resolves differently between this call and a later
#' fetch is exactly the DNS-rebinding attack this layer cannot see. Blocking
#' those requires resolving every address, refusing on any prohibited one, and
#' connecting only to an address that was validated — none of which happens
#' here.
#'
#' Use it to reject obviously-bad configuration early, to give a caller a fast
#' answer before doing real work, or to test classification offline. Do not use
#' it as the gate in front of a fetch.
#'
#' @section Known gaps:
#' Classification is inherited verbatim from two sibling packages so that this
#' port is provably behaviour-preserving. It is an enumerated denylist, and it
#' is incomplete by construction. Known omissions include the IPv6 unique-local
#' space (`fc00::/7`), deprecated site-local (`fec0::/10`), multicast, several
#' reserved IPv4 ranges, and the 6to4, Teredo, and ISATAP address-embedding
#' forms. Malformed address literals currently reach the default allow rather
#' than failing closed.
#'
#' These are tracked and closed in later work; see `docs/decisions/` in the
#' project source. They are stated here because a security tool that is quiet
#' about its own coverage is worse than one that is loud about it.
#'
#' @param host The normalized host, as a URL parser emits it: a dotted-quad for
#'   numeric IPv4, a bracketed literal for IPv6, a lowercase registered name
#'   otherwise. `NA` or `""` is accepted and yields no verdict.
#' @param scheme The URL scheme, e.g. `"http"`. Compared case-insensitively.
#' @param raw_host The **pre-normalization** host string, typically the host
#'   portion of the original URL. Defaults to `host`.
#'
#'   Both spellings are needed. A parser rewrites `0x7f000001` and `2130706433`
#'   into the canonical `127.0.0.1`, so by the time you hold a normalized host
#'   the obfuscation is gone — and with it the evidence that the input was
#'   ambiguous in the first place. Pass the raw string or the numeric-literal
#'   rule cannot fire.
#'
#' @return An object of class `ssrfr_classification`: a list with
#'   \describe{
#'     \item{`prohibited`}{`TRUE` when a rule matched, `FALSE` when none did.
#'       `FALSE` means "not self-evidently prohibited" — it is not a permission
#'       and not a safety verdict.}
#'     \item{`reason`}{The machine-readable reason code, or `NA_character_`
#'       when nothing matched. See [ssrf_reason_codes()].}
#'   }
#'
#' @examples
#' ssrf_classify_host("127.0.0.1", "https")
#'
#' ssrf_classify_host("[::ffff:127.0.0.1]", "https")
#'
#' # The numeric-literal rule needs the raw spelling, which normalization eats.
#' ssrf_classify_host("127.0.0.1", "https", raw_host = "0x7f000001")
#'
#' # A registered name is never prohibited here: L0 does not resolve.
#' # This says nothing about where the name actually points.
#' ssrf_classify_host("example.com", "https")
#'
#' @seealso [ssrf_reason_codes()] for the vocabulary.
#' @export
ssrf_classify_host <- function(host, scheme, raw_host = host) {
  # 1. Scheme gate — http/https only.
  scheme_l <- if (is.na(scheme)) "" else tolower(scheme)
  if (!scheme_l %in% c("http", "https")) {
    return(ssrf_classification(TRUE, "scheme"))
  }

  # 2. Numeric-literal obfuscation on the raw, pre-normalization host. Checked
  #    before the empty-host guard so a numeric authority the parser failed on
  #    (host = NA) is still rejected on its raw form rather than slipping
  #    through as "no host".
  if (ssrf_numeric_literal_blocked(raw_host)) {
    return(ssrf_classification(TRUE, "numeric-literal"))
  }

  if (length(host) != 1L || is.na(host) || !nzchar(host)) {
    # Nothing to evaluate. L0 does not invent a verdict it has no basis for.
    return(ssrf_classification(FALSE))
  }

  # 3. Literal range matching and metadata-name check on the normalized host.
  ssrf_classify_literal(ssrf_strip_brackets(host))
}

#' @export
print.ssrfr_classification <- function(x, ...) {
  if (x$prohibited) {
    cat("<ssrfr classification> prohibited: ", x$reason, "\n", sep = "")
  } else {
    cat("<ssrfr classification> not self-evidently prohibited\n")
  }
  cat("  L0 is a structural pre-filter, not an SSRF defense.\n")
  invisible(x)
}
