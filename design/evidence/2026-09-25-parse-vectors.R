# Generates the measured columns of the parse-vector corpus
# (tests/testthat/fixtures/parse-vectors.tsv; ssrfr-v1.md §7 component 2) and
# refreshes the corpus manifest (fp SSRF-rsxokejd).
#
# The hand-written columns (id, input, expect, status, source, note) are read
# from the file and kept; every other column is regenerated here and must never
# be edited by hand. Re-run it whenever rurl, curl or libcurl changes, and
# commit the file and the manifest together (§7.2): a changed parse shows up as
# a diff instead of a silent bypass.
#
# Run from the repository root with rurl, curl and raddr installed:
#   Rscript design/evidence/2026-09-25-parse-vectors.R
#
# No name is ever resolved. The dial column opens a TCP connection (no bytes
# sent) only for an http or https URL whose libcurl host is a loopback or
# unspecified address literal, which stays on this machine; otherwise it is "-".
#
# Recorded environment: R 4.6.0, rurl 3.0.1, curl 8.0.0 (bundled libcurl
# 8.14.1, built without IDN), raddr 0.1.2, macOS 26 (Darwin 25.6). A different
# measurement on another platform or version is a finding, not a failure of
# this script.

path <- file.path("tests", "testthat", "fixtures", "parse-vectors.tsv")
hand <- c("id", "input", "expect", "status", "source", "note")

# The escapes of fixtures/README.md: \\ \t \n \r \0 and \u{XXXX}.
unescape <- function(s) {
  out <- character()
  i <- 1L
  ch <- strsplit(s, "")[[1]]
  while (i <= length(ch)) {
    if (ch[i] == "\\" && i < length(ch)) {
      nx <- ch[i + 1L]
      simple <- c("\\" = "\\", t = "\t", n = "\n", r = "\r")
      if (nx %in% names(simple)) {
        out <- c(out, simple[[nx]])
        i <- i + 2L
        next
      }
      if (nx == "0") {
        stop("an R string cannot hold NUL: ", s)
      }
      if (nx == "u") {
        close <- match("}", ch[(i + 3L):length(ch)]) + i + 2L
        out <- c(
          out,
          intToUtf8(strtoi(
            paste(ch[(i + 3L):(close - 1L)], collapse = ""),
            16L
          ))
        )
        i <- close + 1L
        next
      }
    }
    out <- c(out, ch[i])
    i <- i + 1L
  }
  paste(out, collapse = "")
}

# ssrfr's fixed rurl bundle (r-binding.md §2.1), minus the arguments a given
# function does not take.
verdict_args <- list(
  url_standard = "whatwg",
  scheme_policy = "require",
  scheme_relative_handling = "error",
  scheme_acceptance = "web",
  protocol_handling = "keep"
)
parse_args <- c(
  verdict_args,
  list(
    www_handling = "none",
    index_page_handling = "keep",
    host_encoding = "idna"
  )
)
numeric_shapes <- c(
  "ipv4-octal",
  "ipv4-non-dotted",
  "ipv4-short-form",
  "ipv4-non-decimal",
  "ipv4-leading-zero",
  "ipv4-number-form"
)

try_or <- function(expr, fallback) tryCatch(expr, error = function(e) fallback)
field <- function(x, name) {
  v <- x[[name]]
  if (is.null(v) || length(v) == 0L || is.na(v) || !nzchar(v)) {
    "-"
  } else {
    as.character(v)
  }
}
userinfo <- function(x) {
  u <- field(x, "user")
  p <- field(x, "password")
  if (u == "-" && p == "-") "-" else paste0(u, ":", p)
}
unbracket <- function(h) tolower(sub("^\\[(.*)\\]$", "\\1", h))

# Hosts compared as raddr values when both are addresses, else as lowercase
# A-label strings (ssrfr-v1.md §4.1).
same_host <- function(a, b) {
  if (a == "-" && b == "-") {
    return("yes")
  }
  if (a == "-" || b == "-") {
    return("no")
  }
  aa <- suppressWarnings(raddr::addr_pton(unbracket(a)))
  bb <- suppressWarnings(raddr::addr_pton(unbracket(b)))
  same <- if (!is.na(aa) && !is.na(bb)) {
    isTRUE(aa == bb)
  } else {
    identical(unbracket(a), unbracket(b))
  }
  if (same) "yes" else "no"
}

# The address libcurl dials for a loopback or unspecified literal, from its
# debug trace; nothing leaves the machine.
dial <- function(wire, host) {
  a <- suppressWarnings(raddr::addr_pton(unbracket(host)))
  if (
    is.na(a) ||
      !(as.character(raddr::addr_category(a)) %in% c("loopback", "unspecified"))
  ) {
    return("-")
  }
  log <- character()
  h <- curl::new_handle(
    connect_only = 1L,
    connecttimeout_ms = 500L,
    proxy = "",
    noproxy = "*",
    verbose = TRUE,
    debugfunction = function(type, msg) {
      if (type == 0L) log <<- c(log, trimws(rawToChar(msg)))
    }
  )
  try(curl::curl_fetch_memory(wire, handle = h), silent = TRUE)
  hit <- regmatches(
    log,
    regexpr("(?<=^Trying ).*(?=\\.\\.\\.$)", log, perl = TRUE)
  )
  if (length(hit)) hit[1] else "none"
}

measure <- function(input) {
  u <- unescape(input)
  v <- try_or(
    as.data.frame(do.call(rurl::get_parse_verdicts, c(list(u), verdict_args))),
    NULL
  )
  p <- try_or(do.call(rurl::safe_parse_url, c(list(u), parse_args)), NULL)
  diag <- try_or(
    unlist(rurl::get_url_diagnostics(u, url_standard = "whatwg")),
    character()
  )
  wire <- try_or(rurl::serialize_url(u, standard = "whatwg"), NA_character_)
  cp <- if (is.na(wire)) NULL else try_or(curl::curl_parse_url(wire), NULL)
  raw <- try_or(curl::curl_parse_url(u)$host, NULL)
  m <- list(
    rurl_l1 = if (is.null(v)) "error" else v$layer1_syntax_verdict,
    rurl_l2 = if (is.null(v)) "error" else v$layer2_policy_verdict,
    rurl_numeric = if (length(intersect(diag, numeric_shapes))) {
      paste(intersect(diag, numeric_shapes), collapse = ",")
    } else {
      "-"
    },
    rurl_scheme = if (is.null(p)) "error" else field(p, "scheme"),
    rurl_userinfo = if (is.null(p)) "error" else userinfo(p),
    rurl_host = if (is.null(p)) "error" else field(p, "host"),
    rurl_port = if (is.null(p)) "error" else field(p, "port"),
    wire = if (is.na(wire)) "-" else wire,
    curl_scheme = if (is.null(cp)) "error" else field(cp, "scheme"),
    curl_userinfo = if (is.null(cp)) "error" else userinfo(cp),
    curl_host = if (is.null(cp)) "error" else field(cp, "host"),
    curl_port = if (is.null(cp)) "error" else field(cp, "port"),
    raw_curl_host = if (is.null(raw)) {
      "error"
    } else {
      field(list(host = raw), "host")
    }
  )
  m$host_agree <- if (is.null(p) || is.null(cp)) {
    "-"
  } else {
    same_host(m$rurl_host, m$curl_host)
  }
  # rurl's layered verdict is the gate (§4.2, §6.5): layer 1 names `parse` and
  # layer 2 `scheme`. Then the parse must succeed and the hosts agree. Last,
  # step 3 reads libcurl's scheme against the default allow_schemes (§12):
  # rurl's layer 2 admits file:, so its verdict alone is not that refusal.
  web <- tolower(m$curl_scheme) %in% c("http", "https")
  m$measured <- if (is.null(v) || v$layer1_syntax_verdict != "pass") {
    "parse"
  } else if (v$layer2_policy_verdict != "admitted") {
    "scheme"
  } else if (is.null(p) || is.null(cp) || m$host_agree != "yes") {
    "parse"
  } else if (!web) {
    "scheme"
  } else {
    "agree"
  }
  m$dial <- if (is.null(cp) || !web) "-" else dial(wire, m$curl_host)
  vapply(m, escape, "")
}

# The inverse of unescape() for the characters a TSV field cannot hold raw.
escape <- function(x) {
  for (r in list(
    c("\\", "\\\\"),
    c("\t", "\\t"),
    c("\n", "\\n"),
    c("\r", "\\r")
  )) {
    x <- gsub(r[1], r[2], x, fixed = TRUE)
  }
  x
}

x <- utils::read.delim(
  path,
  quote = "",
  comment.char = "",
  na.strings = character(),
  colClasses = "character",
  encoding = "UTF-8"
)[hand]
x <- cbind(x, do.call(rbind, lapply(x$input, measure)))
write.table(
  x,
  path,
  sep = "\t",
  quote = FALSE,
  row.names = FALSE,
  eol = "\n",
  fileEncoding = "UTF-8"
)
source(file.path("scripts", "corpus-manifest.R"))

cat("\nexpect vs measured:\n")
print(table(expect = x$expect, measured = x$measured))
off <- x[
  x$expect != x$measured,
  c("id", "input", "expect", "measured", "status")
]
if (nrow(off)) {
  print(off, row.names = FALSE)
}
