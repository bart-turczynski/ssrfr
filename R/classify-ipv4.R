# IPv4 literal classification for the L0 structural layer.
#
# Vendored from robotstxtr/R/ssrf.R and sitemapr/R/ssrf.R, which are identical
# here apart from comments. Classification behaviour is preserved exactly, so
# the port is provable against the inherited corpus; the known gaps are closed
# in a later slice with conformance vectors rather than mixed into the move.
#
# Everything works on the NUMERIC value of a parsed address, never on a regex
# over the literal text (ssrf-guard-spec.md INV-3).

# Is `p` a single canonical IPv4 octet: 1-3 ASCII digits, value 0-255, with no
# leading-zero ambiguity? A leading zero like "017" is an octal obfuscation
# form and is rejected here.
ssrf_octet_ok <- function(p) {
  grepl("^[0-9]{1,3}$", p) &&
    !(nchar(p) > 1L && substr(p, 1L, 1L) == "0") &&
    as.integer(p) <= 255L
}

# Is `s` a plain dotted-quad of four decimal octets (0-255)? TRUE only for the
# canonical form a URL parser emits for an IPv4 host (e.g. "127.0.0.1"). Octal,
# hex, and short/raw-integer forms are not dotted-quads and return FALSE.
ssrf_is_dotted_quad <- function(s) {
  if (length(s) != 1L || is.na(s) || !nzchar(s)) {
    return(FALSE)
  }
  parts <- strsplit(s, ".", fixed = TRUE)[[1L]]
  length(parts) == 4L && all(vapply(parts, ssrf_octet_ok, logical(1L)))
}

# Convert a validated dotted-quad to its 32-bit unsigned integer, as a numeric
# to stay clear of R's signed 32-bit integer overflow at the top of the range.
ssrf_ipv4_to_num <- function(s) {
  parts <- as.numeric(strsplit(s, ".", fixed = TRUE)[[1L]])
  parts[1L] * 16777216 + parts[2L] * 65536 + parts[3L] * 256 + parts[4L]
}

# Does the numeric IPv4 `n` fall inside the CIDR block `base/bits`?
#
# This (n, base, bits) integer form is the seam a registry-driven classifier
# replaces later: swapping the table below for IANA-derived data is a data
# change, not a code change.
ssrf_in_cidr <- function(n, base, bits) {
  base_num <- ssrf_ipv4_to_num(base)
  size <- 2^(32 - bits)
  n >= base_num & n < (base_num + size)
}

# The prohibited IPv4 CIDR matrix as a (base, bits, reason) table; ranges are
# mutually disjoint so first-match order is immaterial. Kept as data so the
# whole matrix is reviewable in one place. 169.254.0.0/16 is handled separately
# because one address inside it maps to a distinct reason.
#
# KNOWN INCOMPLETE. This is an enumerated denylist, which the project's ADR-001
# §2 replaces with a positive routability predicate. Missing at least:
# multicast (224.0.0.0/4), reserved/future use (240.0.0.0/4), IETF protocol
# assignments (192.0.0.0/24), and benchmarking (198.18.0.0/15).
ssrf_ipv4_blocked <- list(
  list(base = "127.0.0.0", bits = 8L, reason = "loopback"),
  list(base = "10.0.0.0", bits = 8L, reason = "private"),
  list(base = "172.16.0.0", bits = 12L, reason = "private"),
  list(base = "192.168.0.0", bits = 16L, reason = "private"),
  list(base = "100.64.0.0", bits = 10L, reason = "cloud-metadata"),
  list(base = "0.0.0.0", bits = 8L, reason = "unspecified")
)

# Classify a canonical dotted-quad. NA_character_ when no rule matches.
ssrf_classify_ipv4 <- function(s) {
  n <- ssrf_ipv4_to_num(s)

  if (ssrf_in_cidr(n, "169.254.0.0", 16L)) {
    # 169.254.169.254 is the cloud-metadata endpoint and lives inside the
    # link-local /16. Report it as cloud-metadata for caller clarity.
    return(if (s == "169.254.169.254") "cloud-metadata" else "link-local")
  }
  for (r in ssrf_ipv4_blocked) {
    if (ssrf_in_cidr(n, r$base, r$bits)) {
      return(r$reason)
    }
  }
  NA_character_
}

# Render a 32-bit unsigned integer as a dotted-quad string.
ssrf_num_to_quad <- function(n) {
  paste(
    c(n %/% 16777216, (n %/% 65536) %% 256, (n %/% 256) %% 256, n %% 256),
    collapse = "."
  )
}

# Does the raw (pre-normalization) host use a numeric/hex/octal obfuscation
# form that is NOT a canonical dotted-quad? A URL parser normalizes such
# literals into a clean dotted-quad, so the obfuscation is visible only in the
# raw host — which is why the classifier takes both spellings.
#
# The stricter interpretation applies: any all-numeric, hex, or leading-zero
# octal literal that is not a canonical dotted-quad is rejected outright. This
# is the INV-2 position — an ambiguous authority is a block, not a warning,
# because the ambiguity IS the signal.
ssrf_numeric_literal_blocked <- function(raw_host) {
  raw <- ssrf_strip_brackets(if (is.na(raw_host)) "" else raw_host)
  if (
    !nzchar(raw) || grepl(":", raw, fixed = TRUE) || ssrf_is_dotted_quad(raw)
  ) {
    return(FALSE)
  }
  grepl("^0[xX][0-9a-fA-F]+$", raw) || # hex single-integer form
    grepl("^[0-9]+$", raw) || # raw decimal single-integer form
    grepl("^0[0-7]+(\\.0?[0-7]*){1,3}$", raw) # octal-style dotted form
}
