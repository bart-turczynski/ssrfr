# IPv6 literal classification for the L0 structural layer.
#
# Vendored from robotstxtr/R/ssrf.R and sitemapr/R/ssrf.R with classification
# behaviour preserved exactly.
#
# EVERY rule below reads the EXPANDED address — the 8 numeric hextets — never
# the literal string (ssrf-guard-spec.md INV-3). A hextet may be written with
# leading zeros and a "::" run may sit anywhere, so the same 128 bits have many
# spellings. Matching the literal decided them inconsistently and was a real
# bypass in BOTH directions, twice, in the same shape:
#
#   grepl("^fd00:ec2:", low)        let fd00:0ec2::254 through — the same
#                                   address as the AWS metadata endpoint it was
#                                   written to block.
#   grepl("^fe[89ab][0-9a-f]?:")    made the 4th hex digit optional, so "fe8"
#                                   (0x0fe8) matched despite being nowhere near
#                                   fe80::/10.
#
# The second bug survived the first fix. INV-3 exists because of this file.

# Strip the brackets a URL parser emits around IPv6 literal hosts.
ssrf_strip_brackets <- function(s) {
  if (grepl("^\\[.*\\]$", s)) {
    return(substr(s, 2L, nchar(s) - 1L))
  }
  s
}

# Fold a trailing dotted-quad IPv4 tail into two hex hextets, returning the
# rewritten string. Returns `low` unchanged when there is no tail, or NULL when
# a tail is present but is not a canonical dotted-quad — refusing rather than
# folding out-of-range octets, which would silently shift the address out of
# the range it should have matched.
ssrf_fold_ipv4_tail <- function(low) {
  m <- regexpr("[0-9]{1,3}(\\.[0-9]{1,3}){3}$", low)
  if (m == -1L) {
    return(low)
  }
  quad <- regmatches(low, m)
  if (!ssrf_is_dotted_quad(quad)) {
    return(NULL)
  }
  n <- ssrf_ipv4_to_num(quad)
  paste0(substr(low, 1L, m - 1L), sprintf("%x:%x", n %/% 65536, n %% 65536))
}

# Resolve an IPv6 literal into its vector of exactly 8 hextet strings: expand
# the (at most one) "::" zero-compression run, or split a fully-written literal
# on ":". Returns NULL when "::" appears more than once, when expansion cannot
# reach 8 hextets, or when a fully-written literal does not have 8 groups.
ssrf_expand_zero_run <- function(low) {
  if (!grepl("::", low, fixed = TRUE)) {
    groups <- strsplit(low, ":", fixed = TRUE)[[1L]]
    return(if (length(groups) == 8L) groups else NULL)
  }
  if (length(gregexpr("::", low, fixed = TRUE)[[1L]]) > 1L) {
    return(NULL)
  }
  pos <- regexpr("::", low, fixed = TRUE)
  left_s <- substr(low, 1L, pos - 1L)
  right_s <- substr(low, pos + 2L, nchar(low))
  left <- if (nzchar(left_s)) {
    strsplit(left_s, ":", fixed = TRUE)[[1L]]
  } else {
    character(0L)
  }
  right <- if (nzchar(right_s)) {
    strsplit(right_s, ":", fixed = TRUE)[[1L]]
  } else {
    character(0L)
  }
  fill <- 8L - length(left) - length(right)
  if (fill < 1L) {
    return(NULL)
  }
  c(left, rep("0", fill), right)
}

# Is `s` plausibly an IPv6 literal at all? Lowercases and screens the alphabet.
ssrf_ipv6_candidate <- function(s) {
  if (length(s) != 1L || is.na(s) || !nzchar(s)) {
    return(NULL)
  }
  low <- tolower(s)
  if (!grepl(":", low, fixed = TRUE) || !grepl("^[0-9a-f:.]+$", low)) {
    return(NULL)
  }
  low
}

# Convert expanded hextet strings to numbers, or NULL when any group is not
# 1-4 hex digits.
ssrf_ipv6_numeric_groups <- function(low) {
  groups <- ssrf_expand_zero_run(low)
  if (is.null(groups) || !all(grepl("^[0-9a-f]{1,4}$", groups))) {
    return(NULL)
  }
  as.numeric(strtoi(groups, base = 16L))
}

# Expand an IPv6 literal (brackets already stripped) into exactly 8 numeric
# hextets, each 0..65535, or NULL when `s` is not a well-formed IPv6 literal.
# Hextets are doubles so downstream arithmetic stays clear of R's signed-32-bit
# overflow. This single expander unifies every spelling, so the embedding
# detector works off bit positions rather than fragile per-form regexes.
#
# KNOWN POSTURE — a literal that cannot be expanded returns NULL, matches no
# rule, and reaches the default allow. ADR-001 §3 reverses this to fail closed
# with a `malformed-address` reason; that change lands with the L1 slice, since
# it adds a code to the stable vocabulary.
ssrf_ipv6_hextets <- function(s) {
  low <- ssrf_ipv6_candidate(s)
  if (is.null(low)) {
    return(NULL)
  }

  low <- ssrf_fold_ipv4_tail(low)
  if (is.null(low)) {
    return(NULL)
  }

  ssrf_ipv6_numeric_groups(low)
}

# Given the 8 expanded hextets, detect an IPv6->IPv4 embedding prefix and
# return `list(quad, reason)`, or NULL when no embedding prefix matches.
# Last-32-bit forms read the IPv4 from h7/h8; the NAT64 local-use /48 packs the
# IPv4 across the RFC 6052 §2.2 bit layout, skipping the reserved u-byte.
#
# Each `if` is a distinct RFC-defined embedding prefix written as an exact
# hextet pattern and compared with one vectorised `all()`. That reads as a flat
# spec table (prefix -> pattern) and keeps cyclomatic complexity low: a `&&`
# chain is charged per operator, whereas one `all(h[...] == c(...))` is a
# single branch.
#
# KNOWN INCOMPLETE — three further RFC-defined embeddings are not decoded here
# and so reach the default allow (ADR-001 §2.3):
#   6to4   RFC 3056  2002::/16   IPv4 in bits 16-47, not the low 32
#   Teredo RFC 4380  2001::/32   IPv4 in the low 32 bits, XOR'd with 0xffffffff
#   ISATAP RFC 5214  any prefix  IPv4 after a 0000:5efe / 0200:5efe marker
# Decoders and vectors for all three land in a later slice.
ssrf_embedded_ipv4 <- function(h) {
  tail32 <- h[7L] * 65536 + h[8L]

  # IPv4-mapped: five zero hextets then ffff, IPv4 in the last 32 bits.
  if (all(h[1:6] == c(0, 0, 0, 0, 0, 0xffff))) {
    return(list(ssrf_num_to_quad(tail32), "ipv4-mapped"))
  }
  # IPv4-translated: four zero hextets, then ffff and a zero hextet.
  if (all(h[1:6] == c(0, 0, 0, 0, 0xffff, 0))) {
    return(list(ssrf_num_to_quad(tail32), "ipv4-translated"))
  }
  # NAT64 well-known prefix, IPv4 in the last 32 bits.
  if (all(h[1:6] == c(0x64, 0xff9b, 0, 0, 0, 0))) {
    return(list(ssrf_num_to_quad(tail32), "nat64"))
  }
  # NAT64 local-use prefix; IPv4 split per RFC 6052 §2.2 around the u-byte.
  if (all(h[1:3] == c(0x64, 0xff9b, 1))) {
    o <- c(h[4L] %/% 256, h[4L] %% 256, h[5L] %% 256, h[6L] %/% 256)
    return(list(paste(o, collapse = "."), "nat64"))
  }
  # IPv4-compatible (deprecated): six zero hextets. tail32 > 1 excludes the
  # unspecified (::) and loopback (::1) specials, which must not be read as
  # 0.0.0.0 / 0.0.0.1; ssrf_ipv6_special() has already claimed those two.
  if (all(h[1:6] == 0) && tail32 > 1) {
    return(list(ssrf_num_to_quad(tail32), "ipv4-compatible"))
  }
  NULL
}

# If the hextets embed an IPv4 address that itself falls in a prohibited range,
# return the embedding's reason code. A public embedded address is allowed,
# matching the IPv4-literal policy; NA when there is no prohibited embedding.
ssrf_embedded_reason <- function(h) {
  if (is.null(h)) {
    return(NA_character_)
  }
  emb <- ssrf_embedded_ipv4(h)
  if (is.null(emb) || !ssrf_is_dotted_quad(emb[[1L]])) {
    return(NA_character_)
  }
  if (is.na(ssrf_classify_ipv4(emb[[1L]]))) {
    return(NA_character_)
  }
  emb[[2L]]
}

# The two all-zero-prefix IPv6 specials, decided on the expanded address: `::1`
# is loopback and `::` is unspecified. Matching the expansion is what makes
# every spelling of those same 128 bits agree — compressed ("::1"), fully
# written ("0:0:0:0:0:0:0:1"), partially compressed ("0::1"), and the
# dotted-quad tails ("::0.0.0.1"). NA when `h` is neither special, including
# when the literal did not expand to 8 hextets at all.
ssrf_ipv6_special <- function(h) {
  if (is.null(h) || !all(h[1:7] == 0) || h[8L] > 1) {
    return(NA_character_)
  }
  if (h[8L] == 1) "loopback" else "unspecified"
}

# The two prefix-matched IPv6 blocks, decided on the expanded hextets:
#   link-local     fe80::/10     -> first hextet 0xfe80..0xfebf
#   cloud-metadata fd00:ec2::/32 -> first two hextets exactly (AWS metadata)
#
# KNOWN INCOMPLETE — fd00:ec2::/32 sits inside fc00::/7, the IPv6 unique-local
# space and direct analogue of RFC 1918. The REST of fc00::/7 is not classified
# at all, so fd00::1 and fc00::1 reach the default allow while 10.0.0.1 is
# refused. fec0::/10 (deprecated site-local) is likewise absent. See ADR-001
# §2.1 — this asymmetry is the motivating example for replacing the denylist
# with a positive routability predicate.
ssrf_ipv6_prefix_block <- function(h) {
  if (is.null(h)) {
    return(NA_character_)
  }
  if (bitwAnd(h[1L], 0xffc0) == 0xfe80) {
    return("link-local")
  }
  if (h[1L] == 0xfd00 && h[2L] == 0x0ec2) {
    return("cloud-metadata")
  }
  NA_character_
}

# Classify an IPv6 literal (brackets already stripped). The literal is expanded
# once here and every rule below reads those hextets, so no rule can disagree
# with another about what address it is looking at. NA when the literal is
# allowed or did not expand to 8 hextets.
ssrf_classify_ipv6 <- function(s) {
  h <- ssrf_ipv6_hextets(s)

  # Pure-address specials first, so an embedding decoder can never mislabel
  # them (e.g. read "::1" as the IPv4-compatible address 0.0.0.1).
  special <- ssrf_ipv6_special(h)
  if (!is.na(special)) {
    return(special)
  }

  embedded <- ssrf_embedded_reason(h)
  if (!is.na(embedded)) {
    return(embedded)
  }

  ssrf_ipv6_prefix_block(h)
}
