# Parity against the inherited matcher (SSRF-sefcrgrj).
#
# The L0 classifier was vendored from robotstxtr/R/ssrf.R and sitemapr/R/ssrf.R,
# which are identical to each other apart from comments. The vendoring was
# deliberately behaviour-preserving: the known gaps are closed in a separate
# slice, with their own vectors, so that a 480-line move and a classification
# change never appear in one diff. That discipline is not academic — the same
# IPv6 string-matching bug shipped twice across those two packages and survived
# a first fix.
#
# This test is the evidence for that claim. It is skipped unless a sibling
# matcher is available, since neither sibling is a dependency. To run it, point
# the SSRFR_SIBLING_MATCHER environment variable at a sibling's R/ssrf.R and
# run the test suite filtered to "parity".
#
# When it does run it compares the two implementations across every (host,
# scheme) pair below and requires exact agreement on BOTH the verdict and the
# reason code. Comparing verdicts alone would let a rule fire for the wrong
# reason and still pass.

sibling_matcher <- function() {
  path <- Sys.getenv("SSRFR_SIBLING_MATCHER", "")
  skip_if(identical(path, ""), "SSRFR_SIBLING_MATCHER is not set")
  path <- path.expand(path)
  skip_if_not(file.exists(path), paste0("no sibling matcher at ", path))
  env <- new.env()
  sys.source(path, envir = env)
  skip_if_not(
    is.function(env$ssrf_check),
    "sibling matcher does not define ssrf_check()"
  )
  env
}

parity_hosts <- c(
  # IPv4, both sides of every boundary in the range matrix
  "127.0.0.1", "127.255.255.255", "126.255.255.255", "128.0.0.0",
  "10.0.0.0", "10.255.255.255", "9.255.255.255", "11.0.0.0",
  "172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0",
  "192.167.255.255", "192.168.0.0", "192.168.255.255", "192.169.0.0",
  "100.63.255.255", "100.64.0.0", "100.127.255.255", "100.128.0.0",
  "0.0.0.0", "0.255.255.255", "1.0.0.0",
  "169.253.255.255", "169.254.0.0", "169.254.169.253", "169.254.169.254",
  "169.254.169.255", "169.254.255.255", "169.255.0.0",
  "93.184.216.34", "8.8.8.8", "224.0.0.1", "240.0.0.1", "255.255.255.255",
  "192.0.0.1", "198.18.0.1",
  # IPv6 specials, every spelling
  "[::1]", "[0::1]", "[::0:1]", "[0:0:0:0:0:0:0:1]", "[::0.0.0.1]",
  "[0:0:0:0:0:0:0.0.0.1]", "[::]", "[0::]", "[::0]", "[0:0:0:0:0:0:0:0]",
  "[::0.0.0.0]", "[0:0:0:0:0:0:0.0.0.0]", "[::2]",
  # link-local boundaries, including the historically over-blocked forms
  "[fe7f::1]", "[fe80::]", "[fe80::1]", "[febf::1]",
  "[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", "[fec0::1]", "[FE80::1]",
  "[fe8::]", "[fe9::]", "[fea::1]", "[feb::]", "[fe8:0:0:0:0:0:0:1]",
  # AWS metadata prefix spellings and its neighbours
  "[fd00:ec2::254]", "[fd00:0ec2::254]", "[fd00:0ec2:0:0:0:0:0:0254]",
  "[fd00:ec2:0:0:0:0:0:254]", "[FD00:0EC2::254]", "[fd00:0ec2:ffff::1]",
  "[fd00:ec3::254]", "[fd01:ec2::254]", "[fd00::1]", "[fc00::1]",
  "[fd12:3456:789a::1]",
  # embeddings, prohibited and public
  "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[::FFFF:7F00:1]",
  "[0:0:0:0:0:ffff:7f00:1]", "[::ffff:8.8.8.8]", "[::ffff:0:7f00:1]",
  "[::ffff:0:127.0.0.1]", "[::7f00:1]", "[::127.0.0.1]", "[::a9fe:a9fe]",
  "[::8.8.8.8]", "[64:ff9b::7f00:1]", "[64:ff9b::10.0.0.1]",
  "[64:ff9b::5db8:d822]", "[64:ff9b:1:7f00:0:100::]",
  "[64:ff9b:1:a00:0:100::]", "[64:ff9b:1:5db8:d8:2200::]",
  # transition forms — currently a documented gap on BOTH sides
  "[2002:7f00:1::]", "[2002:a9fe:a9fe::]", "[2001:0:0:0:0:0:f5ff:fffe]",
  "[2001:db8::5efe:a00:1]", "[fe80::5efe:a00:1]", "[ff02::1]",
  # malformed literals
  "[1:2:3]", "[::ffff::1]", "[1:2:3:4:5:6:7:8::]", "[::12345]",
  "[::ffff:999.1.1.1]", "[fe80:::1]", "[1::2::3]", "[::1.2.3.999]",
  "[256.0.0.1]", "[2001:db8::1]",
  # registered names and empty input
  "example.com", "metadata.google.internal", "METADATA.GOOGLE.INTERNAL",
  "", NA_character_
)

parity_raw_hosts <- c(
  "0x7f000001", "2130706433", "017700000001", "0177.0.0.1", "127.017.0.1",
  "127.0.0.1", "0x1", "0", "00", "0.0.0.0", "example.com", "[::1]",
  "1.2.3.4.5", "999", "0xZZ", "010.0.0.1", NA_character_, ""
)

parity_schemes <- c(
  "http", "https", "HTTP", "ftp", "file", "gopher", "", NA_character_
)

test_that("the vendored classifier agrees with the inherited matcher", {
  env <- sibling_matcher()

  for (host in parity_hosts) {
    for (scheme in parity_schemes) {
      old <- env$ssrf_check(host, scheme, raw_host = host)
      new <- ssrf_classify_host(host, scheme, raw_host = host)
      label <- sprintf("host=%s scheme=%s", host, scheme)
      expect_identical(new$reason, old$reason, label = label)
      expect_identical(new$prohibited, !old$allowed, label = label)
    }
  }
})

test_that("the vendored classifier agrees on raw-host obfuscation forms", {
  env <- sibling_matcher()

  for (raw in parity_raw_hosts) {
    for (scheme in c("http", "ftp")) {
      old <- env$ssrf_check(NA_character_, scheme, raw_host = raw)
      new <- ssrf_classify_host(NA_character_, scheme, raw_host = raw)
      label <- sprintf("raw_host=%s scheme=%s", raw, scheme)
      expect_identical(new$reason, old$reason, label = label)
      expect_identical(new$prohibited, !old$allowed, label = label)
    }
  }
})
