# Probe behind ssrfr-v1.md §4.1's disagreement check as a named test: rurl
# passes fullwidth URL separators in a host, and libcurl then reads a different
# host from rurl's serialized string (fp SSRF-qttneqxp).
#
# Run from the repository root with rurl and curl installed. No network access
# is needed.
#   Rscript design/evidence/2026-09-25-fullwidth-separators.R
#
# Recorded environment: R 4.6.0, rurl 3.0.1, curl 8.0.0 (bundled libcurl
# 8.14.1, built without IDN), macOS 26 (Darwin 25.6). Expected output is in the
# comment after the block. A different answer on another platform or version
# is a finding, not a failure of this script.

# FULLWIDTH NUMBER SIGN, SOLIDUS, QUESTION MARK and COLON (U+FF03, U+FF0F,
# U+FF1F, U+FF1A). UTS-46 maps each to its ASCII form, which is a forbidden
# domain code point, so WHATWG's host parser returns failure for all four.
cps <- c(0xFF03, 0xFF0F, 0xFF1F, 0xFF1A)
us <- paste0("http://127.0.0.1", vapply(cps, intToUtf8, ""), ".evil.com/")
v <- as.data.frame(rurl::get_parse_verdicts(us, url_standard = "whatwg"))
h <- rurl::get_host(us, url_standard = "whatwg")
w <- rurl::serialize_url(us, standard = "whatwg")
cp <- vapply(
  w,
  function(u) {
    tryCatch(curl::curl_parse_url(u)$host, error = function(e) NA_character_)
  },
  ""
)
print(data.frame(
  cp = sprintf("U+%X", cps),
  layer1 = v$layer1_syntax_verdict,
  rurl = h,
  wire = w,
  curl = unname(cp)
))
#       cp layer1                rurl                        wire      curl
# 1 U+FF03   pass 127.0.0.1#.evil.com http://127.0.0.1#.evil.com/ 127.0.0.1
# 2 U+FF0F   pass 127.0.0.1/.evil.com http://127.0.0.1/.evil.com/ 127.0.0.1
# 3 U+FF1F   pass 127.0.0.1?.evil.com http://127.0.0.1?.evil.com/ 127.0.0.1
# 4 U+FF1A   pass 127.0.0.1:.evil.com http://127.0.0.1:.evil.com/      <NA>
# rurl maps each separator to ASCII and keeps it in the host, and its layer-1
# verdict passes. Its serialized string then carries a real separator, so
# libcurl reads the host as 127.0.0.1 (or fails to parse the port, for the
# colon). Only §4.1's host disagreement check, or the parse failure, stops the
# hop. Node 26.3.1's `new URL()` throws ERR_INVALID_URL for all four.
