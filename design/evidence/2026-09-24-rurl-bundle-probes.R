# rurl option-bundle probes behind r-binding.md §2.1: which calls default
# url_standard, which knobs change the components ssrfr reads, what
# clean_url and resolve_url()'s default output drop, and how schemeless and
# scheme-relative input is graded.
#
# Run from the repository root with rurl and curl installed:
#   Rscript --vanilla design/evidence/2026-09-24-rurl-bundle-probes.R
#
# Recorded environment: R 4.6.0, rurl 3.0.1, curl 8.0.0 (libcurl 8.14.1),
# macOS 26 (Darwin 25.6). Expected output is in the comment after each block.

suppressMessages({
  library(rurl)
  library(curl)
})
cat("rurl", as.character(packageVersion("rurl")), "\n")
err <- function(expr) {
  tryCatch(
    {
      force(expr)
      "returns"
    },
    error = function(e) paste("ERROR:", conditionMessage(e))
  )
}

# 1. url_standard: required by two calls, defaulted (NULL) by three. NULL is
#    a legacy mode, not WHATWG.
cat("get_url_diagnostics:", err(get_url_diagnostics("http://h.example/")), "\n")
cat("get_host_type:      ", err(get_host_type("http://h.example/")), "\n")
cat("get_parse_verdicts: ", err(get_parse_verdicts("http://h.example/")), "\n")
cat("safe_parse_url:     ", err(safe_parse_url("http://h.example/")), "\n")
cat("resolve_url:        ", err(resolve_url("x", "http://h.example/")), "\n")
cat(
  "0177.0.0.1 under NULL:    safe_parse_url() is",
  format(safe_parse_url("http://0177.0.0.1/")),
  "| layer 1",
  get_parse_verdicts("http://0177.0.0.1/")$layer1_syntax_verdict,
  "\n"
)
for (s in c("rfc3986", "whatwg")) {
  p <- safe_parse_url("http://0177.0.0.1/", url_standard = s)
  cat(sprintf(
    "0177.0.0.1 under %-8s host=%-12s status=%s\n",
    s,
    dQuote(p$host, FALSE),
    p$parse_status
  ))
}
# diagnostics, host_type: ERROR `url_standard` is required ...; the other three return.
# NULL: safe_parse_url() is NULL, layer 1 fail (a legacy RFC-model parse)
# rfc3986: host="0177.0.0.1" | whatwg: host="127.0.0.1" ok

# 2. Cleaning knobs that change the components, not only clean_url.
u <- "HTTP://User:pw@WWW.Example.COM:8080/A/./b//index.html?z=1&a=2#frag"
cols <- c("scheme", "host", "port", "path", "query", "user", "password")
b <- safe_parse_url(u, url_standard = "whatwg")
cat("baseline:", paste(cols, unlist(b[cols]), sep = "=", collapse = " "), "\n")
cat("clean_url:", b$clean_url, "\n")
knobs <- list(
  www_handling = "strip",
  protocol_handling = "https",
  index_page_handling = "strip",
  profile = "seo",
  port_handling = "keep",
  query_handling = "keep",
  case_handling = "keep",
  path_normalization = "none"
)
for (i in seq_along(knobs)) {
  r <- tryCatch(
    do.call(safe_parse_url, c(list(u, url_standard = "whatwg"), knobs[i])),
    error = function(e) conditionMessage(e)
  )
  lab <- sprintf("%s = \"%s\"", names(knobs)[i], knobs[[i]])
  if (is.character(r)) {
    cat(sprintf("%-32s ERROR: %s\n", lab, substr(r, 1, 60)))
    next
  }
  d <- cols[!mapply(identical, b[cols], r[cols])]
  cat(sprintf(
    "%-32s %s\n",
    lab,
    if (length(d)) {
      paste(sprintf("%s -> %s", d, unlist(r[d])), collapse = "; ")
    } else {
      "no component changes"
    }
  ))
}
# baseline: scheme=http host=www.example.com port=8080 path=/A/b//index.html
#   query=z=1&a=2 user=User password=pw
# clean_url: http://www.example.com/A/b//index.html   (port, query, userinfo, fragment gone)
# www_handling strip: host -> example.com | protocol_handling https: scheme -> https
# index_page_handling strip: path -> /A/b/ | profile seo: scheme, host, path change
# port_handling, query_handling: no component changes (clean_url only)
# case_handling, path_normalization: ERROR url_standard = "whatwg" governs ...

# 3. resolve_url(): the default output is the clean URL.
cat(
  "default:   ",
  resolve_url(
    "../x?q=1",
    "http://h.example:8080/a/b/c",
    url_standard = "whatwg"
  ),
  "\n"
)
cat(
  "serialized:",
  resolve_url(
    "../x?q=1",
    "http://h.example:8080/a/b/c",
    url_standard = "whatwg",
    output = "serialized"
  ),
  "\n"
)
cat(
  "serialize_url():",
  serialize_url("http://bücher.example:8080/p?q=1#f", standard = "whatwg"),
  "\n"
)
cat(
  "serialize_url(url_standard =):",
  err(serialize_url("http://h.example/", url_standard = "whatwg")),
  "\n"
)
# default:    http://h.example/a/x
# serialized: http://h.example:8080/a/x?q=1
# serialize_url(): http://xn--bcher-kva.example:8080/p?q=1#f
# serialize_url(url_standard =): ERROR: unused argument (url_standard = "whatwg")

# 4. Schemeless and scheme-relative input under the default and the bundle.
bundle <- list(
  url_standard = "whatwg",
  scheme_policy = "require",
  scheme_relative_handling = "error",
  scheme_acceptance = "web",
  protocol_handling = "keep"
)
g <- function(x, a) {
  v <- do.call(get_parse_verdicts, c(list(x), a))
  paste(v$layer1_syntax_verdict, v$layer2_policy_verdict, sep = "/")
}
for (x in c("h.example/x", "//h.example/x", "/x", "http://h.example/x")) {
  cat(sprintf(
    "%-20s default %-32s bundle %s\n",
    x,
    g(x, list(url_standard = "whatwg")),
    g(x, bundle)
  ))
}
p <- safe_parse_url("h.example/x", url_standard = "whatwg")
cat("safe_parse_url('h.example/x'):", p$scheme, p$host, p$parse_status, "\n")
# h.example/x     default pass/admitted                  bundle fail/admitted
# //h.example/x   default pass/admitted-scheme-relative  bundle fail/admitted
# /x              default fail/admitted                  bundle fail/admitted
# http://...      default pass/admitted                  bundle pass/admitted
# safe_parse_url('h.example/x'): http h.example warning-invalid-tld (scheme inferred)
