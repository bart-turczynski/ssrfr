# Probes behind the [proposed] ssrfr-v1.md §9 bullet on content-driven fetches
# and §8 row 22 (maximum URL length) (fp SSRF-aylqwknz).
#
# Run from the repository root with xml2, rurl, curl and webfakes installed:
#   Rscript design/evidence/2026-09-24-content-fetches.R
#
# Recorded environment: R 4.6.0, xml2 1.6.0 (libxml2 2.14.4), rurl 3.0.1,
# curl 8.0.0 (bundled libcurl 8.14.1), webfakes 1.5.0, macOS 26 (Darwin 25.6).
# Expected output is in the comment after each block. A different answer on
# another platform or version is a finding, not a failure of this script.

logf <- tempfile(fileext = ".log")
app <- webfakes::new_app()
app$get("/ext", function(req, res) {
  res$set_type("application/xml")$send("<!ELEMENT r ANY>")
})
web <- webfakes::local_app_process(
  app,
  opts = webfakes::server_opts(access_log_file = logf)
)
u <- function(tag) web$url(paste0("/ext?", tag))
doc_dtd <- function(tag) {
  sprintf('<?xml version="1.0"?><!DOCTYPE r SYSTEM "%s"><r/>', u(tag))
}
doc_ent <- function(tag) {
  sprintf(
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "%s">]><r>&e;</r>',
    u(tag)
  )
}
parse <- function(doc, opts) {
  invisible(suppressWarnings(try(
    xml2::read_xml(doc, options = opts),
    silent = TRUE
  )))
}

# 1. xml2 on content: default options make no request; DTDLOAD fetches the
#    external DTD and NOENT the external entity, outside any guard.
parse(doc_dtd("default-dtd"), "NOBLANKS")
parse(doc_ent("default-entity"), "NOBLANKS")
parse(doc_dtd("dtdload"), c("NOBLANKS", "DTDLOAD"))
parse(doc_ent("noent"), c("NOBLANKS", "NOENT"))
Sys.sleep(0.5)
print(regmatches(readLines(logf), regexpr("ext\\?[a-z-]+", readLines(logf))))
# "ext?dtdload" "ext?noent"

# 1b. NOENT also reads a local file into the document; the default does not.
f <- tempfile()
writeLines("LOCAL-SECRET", f)
doc_file <- sprintf(
  '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file://%s">]><r>&e;</r>',
  f
)
c(
  default = xml2::xml_text(xml2::read_xml(doc_file)),
  noent = trimws(xml2::xml_text(xml2::read_xml(
    doc_file,
    options = c("NOBLANKS", "NOENT")
  )))
)
# default "" ; noent "LOCAL-SECRET"

# 2. xml2 on a URL string opens it with curl::curl(), not through a guard.
trimws(grep(
  "curl::curl|url\\(path\\)",
  deparse(xml2:::path_to_connection),
  value = TRUE
))
# "if (is_url(path)) {" "return(curl::curl(path))" "return(url(path))"

# 3. rurl 3.0.1 raises an R error, not a parse verdict, once its parse-cache
#    key passes R's 10,000-byte variable-name limit: from 9,914 ASCII
#    characters, and from under 1,720 characters of non-ASCII text.
try_parse <- function(u) {
  tryCatch(
    rurl::safe_parse_url(u, url_standard = "whatwg")$parse_status,
    error = function(e) paste("error:", conditionMessage(e))
  )
}
ascii <- function(n) paste0("http://example.com/", strrep("a", n - 19))
try_parse(ascii(9913))
# "ok"
try_parse(ascii(9914))
# "error: variable names are limited to 10000 bytes"
try_parse(paste0("http://example.com/", strrep("é", 1700)))
# "error: variable names are limited to 10000 bytes"

# 4. libcurl refuses any URL longer than 8,000,000 bytes (CURL_MAX_INPUT_LENGTH).
tryCatch(
  curl::curl_parse_url(paste0("http://example.com/", strrep("a", 8e6)))$host,
  error = function(e) conditionMessage(e)
)
# "Failed to parse URL: Malformed input to a URL function"
