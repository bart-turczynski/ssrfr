# Reason-code vocabulary (ssrf-guard-spec.md §5).
#
# Reason codes are a PUBLIC COMPATIBILITY SURFACE, not a debugging nicety.
# Downstream packages surface them to their own users as documented values —
# robotstxtr exposes them through its `ssrf_blocked` fetch outcome — so the
# string values are API and cannot be renamed without breaking consumers.
#
# The vocabulary is kebab-case. This deliberately diverges from the sibling
# TypeScript project's snake_case convention, to preserve the published values.

# The codes L0 can currently emit. Keep this in sync with the classifier; the
# test suite asserts that every code the classifier produces appears here.
ssrf_l0_reason_codes <- c(
  "loopback",
  "private",
  "link-local",
  "cloud-metadata",
  "unspecified",
  "ipv4-mapped",
  "ipv4-translated",
  "ipv4-compatible",
  "nat64",
  "numeric-literal",
  "scheme"
)

# Codes the specification requires but that only L1/L2 can emit (they need
# resolution, a transport, or a redirect chain). Listed here so the vocabulary
# is enumerable as a whole from the first commit rather than growing silently.
ssrf_pending_reason_codes <- c(
  "downgrade",
  "userinfo",
  "port",
  "host-denied",
  "parse",
  "malformed-address",
  "unresolvable",
  "pin-mismatch",
  "multicast"
)

#' Reason codes this package can report
#'
#' The machine-readable vocabulary used by the `reason` field of
#' [ssrf_classify_host()]. Codes are stable, documented values: treat them as
#' API and match on them exactly rather than parsing message text.
#'
#' @param layer Which codes to return. `"l0"` returns only the codes the
#'   structural classifier can emit today. `"all"` (the default) additionally
#'   returns codes reserved for the resolving and fetching layers, which are not
#'   implemented yet.
#'
#' @return A character vector of reason codes, sorted.
#'
#' @details
#' Two codes carry inherited misnomers that will be corrected before this
#' package's first release, so do not build on their current meaning:
#'
#' - `cloud-metadata` is reported for the whole of `100.64.0.0/10`
#'   (carrier-grade NAT). That range merely *contains* one provider's
#'   endpoint; it is not metadata space.
#' - `cloud-metadata` is likewise reported for `fd00:ec2::/32` while the
#'   unique-local space containing it is not classified at all.
#'
#' See `vignette` material and the project's `docs/decisions/` for the full
#' rationale.
#'
#' @examples
#' ssrf_reason_codes("l0")
#'
#' head(ssrf_reason_codes())
#'
#' @seealso [ssrf_classify_host()]
#' @export
ssrf_reason_codes <- function(layer = c("all", "l0")) {
  layer <- match.arg(layer)
  codes <- if (identical(layer, "l0")) {
    ssrf_l0_reason_codes
  } else {
    c(ssrf_l0_reason_codes, ssrf_pending_reason_codes)
  }
  sort(codes)
}
