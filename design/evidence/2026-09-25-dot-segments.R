# Probe behind r-binding.md §5's `path_as_is = 1L`: rurl's WHATWG serialization
# removes every dot segment, percent-encoded forms included, before libcurl
# sees the URL (fp SSRF-qttneqxp).
#
# Run from the repository root with rurl installed. No network access is
# needed.
#   Rscript design/evidence/2026-09-25-dot-segments.R
#
# Recorded environment: R 4.6.0, rurl 3.0.1, macOS 26 (Darwin 25.6). Expected
# output is in the comment after the block. A different answer on another
# platform or version is a finding, not a failure of this script.

us <- c(
  "http://h.example/a/../b",
  "http://h.example/a/./b",
  "http://h.example/a/%2e%2e/b",
  "http://h.example/a/%2E/b",
  "http://h.example/a/.%2e/b",
  "http://h.example/../../x",
  "http://h.example/a/..",
  "http://h.example/a/b/%2e%2E"
)
print(data.frame(
  input = us,
  wire = rurl::serialize_url(us, standard = "whatwg")
))
#                         input                 wire
# 1     http://h.example/a/../b   http://h.example/b
# 2      http://h.example/a/./b http://h.example/a/b
# 3 http://h.example/a/%2e%2e/b   http://h.example/b
# 4    http://h.example/a/%2E/b http://h.example/a/b
# 5   http://h.example/a/.%2e/b   http://h.example/b
# 6    http://h.example/../../x   http://h.example/x
# 7       http://h.example/a/..    http://h.example/
# 8 http://h.example/a/b/%2e%2E  http://h.example/a/
# No wire string carries a dot segment, so libcurl's own dot-segment removal
# has nothing to act on and `path_as_is = 1L` changes no request path.
