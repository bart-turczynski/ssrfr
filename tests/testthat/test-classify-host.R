# L0 structural classification (SSRF-sefcrgrj).
#
# The corpus is inherited from robotstxtr and sitemapr, whose matchers this
# file's subject was vendored from. Keeping the vectors intact is what makes
# the port provably behaviour-preserving: classification must agree with the
# siblings vector-for-vector, so a behaviour change cannot hide inside a
# 480-line move. That is not hypothetical — the same IPv6 string-matching bug
# shipped twice across those two packages, in the same shape, and survived a
# code review, a test suite, and a first fix.

reason_of <- function(host, scheme = "http", raw_host = host) {
  ssrf_classify_host(host, scheme, raw_host = raw_host)$reason
}

prohibited <- function(host, scheme = "http", raw_host = host) {
  ssrf_classify_host(host, scheme, raw_host = raw_host)$prohibited
}

# ---- IPv4 --------------------------------------------------------------------

test_that("the documented IPv4 ranges classify with stable reasons", {
  expect_identical(reason_of("127.0.0.1"), "loopback")
  expect_identical(reason_of("10.0.0.1"), "private")
  expect_identical(reason_of("172.16.0.1"), "private")
  expect_identical(reason_of("192.168.1.1"), "private")
  expect_identical(reason_of("169.254.169.254"), "cloud-metadata")
  expect_identical(reason_of("169.254.0.1"), "link-local")
  expect_identical(reason_of("0.0.0.0"), "unspecified")
  expect_true(prohibited("127.0.0.1"))
})

test_that("ordinary public hosts and public IPs are not prohibited", {
  pub_name <- ssrf_classify_host("example.com", "https")
  expect_false(pub_name$prohibited)
  expect_true(is.na(pub_name$reason))
  expect_false(prohibited("93.184.216.34"))
})

# ---- IPv6 specials, prefixes, and spellings ----------------------------------

test_that("IPv6 loopback, embeddings, and metadata names classify", {
  expect_identical(reason_of("[::1]"), "loopback")
  expect_identical(reason_of("[::ffff:127.0.0.1]"), "ipv4-mapped")
  expect_identical(reason_of("metadata.google.internal"), "cloud-metadata")
})

test_that("IPv6 unspecified, link-local, and metadata prefixes classify", {
  expect_identical(reason_of("[::]"), "unspecified")
  # fe80::/10 spans fe80..febf in the leading hextet.
  expect_identical(reason_of("[fe80::1]"), "link-local")
  expect_identical(reason_of("[febf::1]"), "link-local")
  expect_identical(reason_of("[fe80::]"), "link-local")
  expect_identical(reason_of("[fd00:ec2::254]"), "cloud-metadata")
  expect_identical(reason_of("[fd00:ec2:1::5]"), "cloud-metadata")
})

test_that("every spelling of the AWS IPv6 metadata prefix classifies", {
  # A hextet may carry leading zeros, so "ec2" and "0ec2" are the same 16 bits.
  # Matching the literal "^fd00:ec2:" blocked the first spelling and let the
  # second through — a real bypass of the metadata block, not merely an
  # inconsistency. All of these are fd00:0ec2::/32.
  expect_identical(reason_of("[fd00:ec2::254]"), "cloud-metadata")
  expect_identical(reason_of("[fd00:0ec2::254]"), "cloud-metadata")
  expect_identical(reason_of("[fd00:0ec2:0:0:0:0:0:0254]"), "cloud-metadata")
  expect_identical(reason_of("[fd00:ec2:0:0:0:0:0:254]"), "cloud-metadata")
  expect_identical(reason_of("[FD00:0EC2::254]"), "cloud-metadata")
  expect_identical(reason_of("[fd00:0ec2:ffff::1]"), "cloud-metadata")
  expect_true(prohibited("[fd00:0ec2::254]"))
  # Neighbours outside the /32: only these two hextets match.
  expect_true(is.na(reason_of("[fd00:ec3::254]")))
  expect_true(is.na(reason_of("[fd01:ec2::254]")))
})

test_that("link-local matches fe80::/10 by value, not by literal prefix", {
  # The old "^fe[89ab][0-9a-f]?:" made the 4th hex digit optional, so a 3-digit
  # first hextet ("fe8" = 0x0fe8) matched despite being nowhere near fe80::/10.
  # The block is exactly 0xfe80..0xfebf.
  expect_identical(reason_of("[fe80::1]"), "link-local")
  expect_identical(reason_of("[fe80:0:0:0:0:0:0:1]"), "link-local")
  expect_identical(reason_of("[FE80::1]"), "link-local")
  expect_identical(
    reason_of("[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]"),
    "link-local"
  )
  # Formerly over-blocked: 0x0fe8/0x0fea/0x0feb are ordinary global addresses.
  expect_true(is.na(reason_of("[fe8::]")))
  expect_true(is.na(reason_of("[fe8:0:0:0:0:0:0:1]")))
  expect_true(is.na(reason_of("[fe9::]")))
  expect_true(is.na(reason_of("[fea::1]")))
  expect_true(is.na(reason_of("[feb::]")))
  # Immediately outside the /10 on the low side.
  expect_true(is.na(reason_of("[fe7f::1]")))
  # A literal that does not expand to 8 hextets matches no prefix block.
  expect_true(is.na(ssrf_ipv6_prefix_block(ssrf_ipv6_hextets("fea:"))))
  expect_true(is.na(ssrf_ipv6_prefix_block(NULL)))
})

test_that("every spelling of ::1 and :: classifies on the expanded address", {
  # ::0.0.0.1 is the SAME 128 bits as ::1, and ::0.0.0.0 the same as ::.
  # Deciding the two specials on the literal string blocked one spelling while
  # allowing an identical other one, so they are matched on the expanded
  # hextets: every form the expander accepts must agree.
  expect_identical(reason_of("[::1]"), "loopback")
  expect_identical(reason_of("[0::1]"), "loopback")
  expect_identical(reason_of("[::0:1]"), "loopback")
  expect_identical(reason_of("[0:0:0:0:0:0:0:1]"), "loopback")
  expect_identical(reason_of("[::0.0.0.1]"), "loopback")
  expect_identical(reason_of("[0:0:0:0:0:0:0.0.0.1]"), "loopback")
  expect_identical(reason_of("[::]"), "unspecified")
  expect_identical(reason_of("[0::]"), "unspecified")
  expect_identical(reason_of("[::0]"), "unspecified")
  expect_identical(reason_of("[0:0:0:0:0:0:0:0]"), "unspecified")
  expect_identical(reason_of("[::0.0.0.0]"), "unspecified")
  expect_identical(reason_of("[0:0:0:0:0:0:0.0.0.0]"), "unspecified")
  expect_true(prohibited("[::0.0.0.1]"))
  expect_true(prohibited("[::0.0.0.0]"))
  # One past the loopback special: with the low hextet above 1 the literal is
  # no longer a special and routes to the embedding decoder instead.
  expect_identical(reason_of("[::2]"), "ipv4-compatible")
  expect_true(is.na(ssrf_ipv6_special(ssrf_ipv6_hextets("1:2:3"))))
})

# ---- IPv6 -> IPv4 embeddings -------------------------------------------------

test_that("every documented IPv6->IPv4 embedding is decoded", {
  # Each spelling below carries a prohibited IPv4 address in its low 32 bits.
  # Left undecoded, any one of them walks straight past the IPv4 matrix, so the
  # classifier must report the embedding form as the reason code.
  expect_identical(reason_of("[::ffff:0:7f00:1]"), "ipv4-translated")
  expect_identical(reason_of("[::ffff:0:127.0.0.1]"), "ipv4-translated")
  expect_identical(reason_of("[64:ff9b::7f00:1]"), "nat64")
  expect_identical(reason_of("[64:ff9b::10.0.0.1]"), "nat64")
  expect_identical(reason_of("[::7f00:1]"), "ipv4-compatible")
  expect_identical(reason_of("[::127.0.0.1]"), "ipv4-compatible")
  # a9fe:a9fe is 169.254.169.254, the cloud-metadata endpoint.
  expect_identical(reason_of("[::a9fe:a9fe]"), "ipv4-compatible")
  expect_true(prohibited("[64:ff9b::7f00:1]"))
  # The fully written form still classifies: it is ::ffff:127.0.0.1.
  expect_identical(reason_of("[0:0:0:0:0:ffff:7f00:1]"), "ipv4-mapped")
  expect_identical(reason_of("[::FFFF:7F00:1]"), "ipv4-mapped")
})

test_that("the NAT64 local-use /48 unpacks the u-byte-split IPv4", {
  # RFC 6052 §2.2: behind a 64:ff9b:1::/48 prefix the embedded IPv4 straddles
  # the reserved u-byte — octets 1-2 in hextet 4, octet 3 in the LOW byte of
  # hextet 5, octet 4 in the HIGH byte of hextet 6. Reading the last 32 bits
  # instead, as the /96 forms do, would miss these entirely.
  expect_identical(reason_of("[64:ff9b:1:7f00:0:100::]"), "nat64") # 127.0.0.1
  expect_identical(reason_of("[64:ff9b:1:a00:0:100::]"), "nat64") # 10.0.0.1
  # A public embedded address behind the same prefix is not prohibited,
  # matching the IPv4-literal policy: 5db8 / d8 / 2200 -> 93.184.216.34.
  expect_false(prohibited("[64:ff9b:1:5db8:d8:2200::]"))
})

test_that("a public embedded address is treated like the bare IPv4", {
  expect_false(prohibited("[2001:db8::1]"))
  expect_true(is.na(reason_of("[2001:db8::1]")))
  # 5db8:d822 is 93.184.216.34.
  expect_false(prohibited("[64:ff9b::5db8:d822]"))
  expect_false(prohibited("[::ffff:8.8.8.8]"))
  expect_false(prohibited("[::8.8.8.8]"))
})

# ---- scheme and numeric-literal gates ----------------------------------------

test_that("non-http(s) schemes are prohibited on the scheme", {
  expect_identical(ssrf_classify_host("example.com", "ftp")$reason, "scheme")
  expect_identical(ssrf_classify_host("example.com", "file")$reason, "scheme")
  expect_identical(ssrf_classify_host("example.com", "gopher")$reason, "scheme")
  expect_identical(
    ssrf_classify_host("example.com", NA_character_)$reason,
    "scheme"
  )
  # Case-insensitive, and https passes.
  expect_false(prohibited("example.com", scheme = "HTTPS"))
})

test_that("obfuscated numeric literals are read from the raw host", {
  # Normalization rewrites these into a canonical dotted-quad, taking the
  # evidence of ambiguity with it — hence the separate raw spelling.
  expect_identical(
    ssrf_classify_host(NA_character_, "http", raw_host = "0x7f000001")$reason,
    "numeric-literal"
  )
  expect_identical(
    ssrf_classify_host(NA_character_, "http", raw_host = "2130706433")$reason,
    "numeric-literal"
  )
  # Leading-zero (octal) first octet: 0177.0.0.1 is 127.0.0.1.
  expect_identical(
    reason_of("127.0.0.1", raw_host = "0177.0.0.1"),
    "numeric-literal"
  )
  expect_identical(
    reason_of("127.0.0.1", raw_host = "017700000001"),
    "numeric-literal"
  )
  # A canonical dotted-quad is not an obfuscation; it classifies on its range.
  expect_identical(reason_of("127.0.0.1", raw_host = "127.0.0.1"), "loopback")
  # An octal octet anywhere disqualifies the string as a canonical dotted-quad.
  expect_false(ssrf_is_dotted_quad("127.017.0.1"))
  expect_false(ssrf_is_dotted_quad("256.0.0.1"))
})

test_that("an absent host yields no verdict rather than an invented one", {
  na_host <- ssrf_classify_host(NA_character_, "http", raw_host = NA_character_)
  expect_false(na_host$prohibited)
  expect_true(is.na(na_host$reason))
  expect_false(ssrf_classify_host("", "http", raw_host = "")$prohibited)
  zero_len <- ssrf_classify_host(character(0L), "http", raw_host = NA)
  expect_false(zero_len$prohibited)
})

# ---- helper-level edge cases -------------------------------------------------

test_that("the expander resolves every :: placement to 8 hextets", {
  expect_identical(
    ssrf_expand_zero_run("0:0:0:0:0:ffff:7f00:1"),
    c("0", "0", "0", "0", "0", "ffff", "7f00", "1")
  )
  expect_identical(ssrf_expand_zero_run("::1"), c(rep("0", 7L), "1"))
  expect_identical(ssrf_expand_zero_run("fe80::"), c("fe80", rep("0", 7L)))
  expect_identical(
    ssrf_expand_zero_run("64:ff9b::7f00:1"),
    c("64", "ff9b", "0", "0", "0", "0", "7f00", "1")
  )
})

test_that("the expander rejects malformed IPv6 shapes", {
  # A literal without "::" must carry exactly 8 groups.
  expect_null(ssrf_expand_zero_run("1:2:3"))
  # A second "::" makes the zero run ambiguous, so nothing is expanded.
  expect_null(ssrf_expand_zero_run("::ffff::1"))
  expect_null(ssrf_expand_zero_run("1::2::3"))
  # Nothing left to fill: 8 groups are already written around the "::".
  expect_null(ssrf_expand_zero_run("1:2:3:4:5:6:7:8::"))
})

test_that("a malformed IPv4 tail makes the whole literal unparseable", {
  # 999.1.1.1 and 256.0.0.1 are not canonical dotted-quads. The fold refuses
  # rather than folding out-of-range octets into hextets, which would silently
  # shift the address out of the range it should have matched.
  expect_null(ssrf_fold_ipv4_tail("::ffff:999.1.1.1"))
  expect_null(ssrf_fold_ipv4_tail("::ffff:256.0.0.1"))
  expect_null(ssrf_ipv6_hextets("::ffff:999.1.1.1"))
  # No tail at all: returned unchanged.
  expect_identical(ssrf_fold_ipv4_tail("::1"), "::1")
  expect_identical(ssrf_fold_ipv4_tail("::ffff:127.0.0.1"), "::ffff:7f00:1")
  expect_null(ssrf_ipv6_hextets("example.com"))
  expect_null(ssrf_ipv6_numeric_groups("1:2:3"))
  expect_null(ssrf_ipv6_numeric_groups("1:2:3:4:5:6:7:abcde"))
  expect_identical(ssrf_ipv6_numeric_groups("::1"), c(rep(0, 7L), 1))
})

test_that("the IPv6 helpers reject non-scalar, NA, and malformed input", {
  expect_false(ssrf_is_dotted_quad(c("1.2.3.4", "5.6.7.8")))
  expect_false(ssrf_is_dotted_quad(character(0L)))
  expect_false(ssrf_is_dotted_quad(NA_character_))
  expect_false(ssrf_is_dotted_quad(""))
  expect_null(ssrf_ipv6_candidate(NULL))
  expect_null(ssrf_ipv6_candidate(NA_character_))
  expect_null(ssrf_ipv6_candidate(""))
  expect_null(ssrf_ipv6_candidate(character(0L)))
  # No colon at all: a registered name is not an IPv6 candidate.
  expect_null(ssrf_ipv6_candidate("example.com"))
  # A percent-encoded zone id falls outside the hex/colon/dot alphabet.
  expect_null(ssrf_ipv6_candidate("::1%25eth0"))
  # Brackets are stripped upstream, so a bracketed literal is not a candidate.
  expect_null(ssrf_ipv6_candidate("[::1]"))
  expect_identical(ssrf_ipv6_candidate("::FFFF:1"), "::ffff:1")
})

# ---- result shape and vocabulary ---------------------------------------------

test_that("the result is a classed record with the documented fields", {
  x <- ssrf_classify_host("127.0.0.1", "https")
  expect_s3_class(x, "ssrfr_classification")
  expect_identical(names(x), c("prohibited", "reason"))
  expect_type(x$prohibited, "logical")
  expect_type(x$reason, "character")
  expect_output(print(x), "prohibited: loopback")
  # The disclaimer travels with the object, so it cannot be read as a verdict.
  expect_output(print(x), "not an SSRF defense")
  expect_output(
    print(ssrf_classify_host("example.com", "https")),
    "not self-evidently prohibited"
  )
})

test_that("every reason code the classifier emits is enumerable", {
  # ssrf-guard-spec.md §5.1 requires the vocabulary to be enumerable at
  # runtime, because downstream packages surface these values as documented
  # API. A code the classifier can emit but ssrf_reason_codes() omits would be
  # an undocumented public value.
  emitted <- unique(vapply(
    c(
      "127.0.0.1", "10.0.0.1", "169.254.0.1", "169.254.169.254", "0.0.0.0",
      "[::ffff:127.0.0.1]", "[::ffff:0:7f00:1]", "[::7f00:1]",
      "[64:ff9b::7f00:1]", "metadata.google.internal"
    ),
    function(h) ssrf_classify_host(h, "http")$reason,
    character(1L)
  ))
  emitted <- c(emitted, "scheme", "numeric-literal")
  expect_true(all(emitted %in% ssrf_reason_codes("l0")))
  expect_true(all(ssrf_reason_codes("l0") %in% ssrf_reason_codes()))
  expect_identical(ssrf_reason_codes(), sort(ssrf_reason_codes()))
  expect_error(ssrf_reason_codes("l2"))
})

# ---- characterization: known gaps --------------------------------------------

# These assert what the vendored classifier does TODAY, not what it should do.
# Each one is a documented gap in ADR-001 §2 and each expectation MUST invert
# when that gap closes. They exist so the fix shows up as a deliberate,
# reviewable test change instead of a silent behaviour shift — and so nobody
# reads the passing suite as evidence of coverage that is not there.

test_that("KNOWN GAP: IPv6 unique-local is unclassified (ADR-001 §2.1)", {
  # fd00:ec2::/32 sits inside fc00::/7, the IPv6 analogue of RFC 1918. Exactly
  # that one /32 is classified; the rest of the space is not, so these reach
  # the default allow while 10.0.0.1 does not.
  expect_false(prohibited("[fd00::1]"))
  expect_false(prohibited("[fc00::1]"))
  expect_false(prohibited("[fd12:3456:789a::1]"))
  # Deprecated site-local, RFC 3879.
  expect_false(prohibited("[fec0::1]"))
})

test_that("KNOWN GAP: transition embeddings are not decoded (ADR-001 §2.3)", {
  # Every implemented decoder reads the low 32 bits. These three put the IPv4
  # somewhere else, so the embedded private address is never seen.
  expect_false(prohibited("[2002:7f00:1::]")) # 6to4    -> 127.0.0.1
  expect_false(prohibited("[2002:a9fe:a9fe::]")) # 6to4    -> 169.254.169.254
  expect_false(prohibited("[2001:0:0:0:0:0:f5ff:fffe]")) # Teredo -> 10.0.0.1
  expect_false(prohibited("[2001:db8::5efe:a00:1]")) # ISATAP -> 10.0.0.1
  # ISATAP under a link-local prefix IS prohibited today — but incidentally,
  # by the outer fe80::/10 rule rather than by decoding the embedded address.
  # Asserting the REASON is what exposes that; a verdict-only check would read
  # as coverage this classifier does not have.
  expect_identical(reason_of("[fe80::5efe:a00:1]"), "link-local")
})

test_that("KNOWN GAP: multicast and reserved IPv4 are unclassified", {
  expect_false(prohibited("224.0.0.1")) # IPv4 multicast
  expect_false(prohibited("[ff02::1]")) # IPv6 multicast
  expect_false(prohibited("240.0.0.1")) # reserved / future use
  expect_false(prohibited("192.0.0.1")) # IETF protocol assignments
  expect_false(prohibited("198.18.0.1")) # benchmarking
})

test_that("KNOWN GAP: the octal rule only fires on a leading octal octet", {
  # The octal-dotted pattern is anchored at the start ("^0[0-7]+..."), so an
  # octal octet in any later position is not reported as numeric-literal — the
  # normalized host is classified on its range instead.
  expect_identical(reason_of("127.0.0.1", raw_host = "127.017.0.1"), "loopback")
  expect_identical(reason_of("10.15.0.1", raw_host = "10.017.0.1"), "private")

  # Practical exposure is narrow rather than absent, and the distinction
  # matters for how urgently this is fixed. An octal octet only changes the
  # value of the octet it sits in, and the leading octet is what decides which
  # range an address falls in — so a non-leading octal form generally lands in
  # the same classification as its canonical spelling, as both cases above do.
  # Getting from a public-looking literal into a private range requires
  # rewriting the FIRST octet, which is the form the rule already catches.
  expect_identical(
    reason_of("127.0.0.1", raw_host = "0177.0.0.1"),
    "numeric-literal"
  )
})

test_that("KNOWN GAP: malformed literals fail open (ADR-001 §3)", {
  # A literal the expander cannot resolve to 8 hextets matches no rule and
  # reaches the default allow. ADR-001 §3 reverses this to a `malformed-address`
  # refusal; that lands with L1, since it adds a code to the stable vocabulary.
  expect_false(prohibited("[1:2:3]"))
  expect_false(prohibited("[::ffff::1]"))
  expect_false(prohibited("[1:2:3:4:5:6:7:8::]"))
  expect_false(prohibited("[::12345]"))
  expect_false(prohibited("[::ffff:999.1.1.1]"))
  expect_false(prohibited("[fe80:::1]"))
})
