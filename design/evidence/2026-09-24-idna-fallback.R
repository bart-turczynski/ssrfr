# Probe behind the [proposed] ssrfr-v1.md §5.0 rule that a host with no A-label
# refuses: what rurl and libcurl do with hosts whose domain-to-ASCII fails
# (fp SSRF-aylqwknz).
#
# Run from the repository root with rurl and curl installed. No network access
# is needed.
#   Rscript design/evidence/2026-09-24-idna-fallback.R
#
# Recorded environment: R 4.6.0, rurl 3.0.1, curl 8.0.0 (bundled libcurl
# 8.14.1, built without IDN), macOS 26 (Darwin 25.6). Expected output is in the
# comment after the block. A different answer on another platform or version
# is a finding, not a failure of this script.

# Two U-label hosts whose domain-to-ASCII fails (a leading combining mark, a
# bare ZWNJ), then three invalid ACE labels. WHATWG's host parser returns
# failure for all five.
us <- c("http://́a.example/", "http://x‌.example/",
        "http://xn--a.example/", "http://xn--.example/",
        "http://xn--ASCII-.example/")
v  <- as.data.frame(rurl::get_parse_verdicts(us, url_standard = "whatwg"))
h  <- rurl::get_host(us, url_standard = "whatwg", host_encoding = "idna")
cp <- vapply(us, function(u) tryCatch(curl::curl_parse_url(u)$host,
                                      error = function(e) NA_character_), "")
print(data.frame(layer1 = v$layer1_syntax_verdict, idna = h, curl = unname(cp)))
# layer1: fail, fail, pass, pass, pass
# idna:   NA,   NA,   xn--a.example, xn--.example, xn--ascii-.example
# So the U-label failures are refused by rurl's verdict, but the invalid ACE
# labels pass it, and libcurl sees the same string, so the rurl-versus-libcurl
# disagreement check (ssrfr-v1.md §4.1) does not fire either.
