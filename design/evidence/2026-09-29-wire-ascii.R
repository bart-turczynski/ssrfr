# Probe behind ssrfr-v1.md §4.1's wire-string precondition (§8 item 34, fp
# SSRF-ljqshjmj): is every string rurl serializes for libcurl, once past the
# syntax and scheme gates, printable ASCII? If so, refusing any other string as
# `parse` refuses nothing the binding admits today.
#
# Run from the repository root with pkgload, rurl and curl installed. No network
# access is needed.
#   Rscript design/evidence/2026-09-29-wire-ascii.R
#
# Recorded environment: R 4.6.0, rurl 3.0.1, curl 8.0.0 (bundled libcurl
# 8.14.1, built without IDN), macOS 26 (Darwin 25.6). Expected output is in the
# comment at the end. A different answer on another platform or version is a
# finding, not a failure of this script.

suppressMessages(pkgload::load_all(".", quiet = TRUE, export_all = TRUE))
test_path <- function(...) file.path("tests/testthat", ...)
source("tests/testthat/helper-corpus.R")

# Every input of the parse-vector and verdict corpora.
corpus <- c(
  read_corpus("parse-vectors.tsv")$input,
  read_corpus("verdict-vectors.tsv")$input
)
corpus <- vapply(corpus, unescape_field, "", USE.NAMES = FALSE)

# Non-ASCII in each component: space, DEL, C1 controls, soft hyphen, Latin-1,
# zero-width and bidi controls, line separator, ideographic space, BOM,
# fullwidth full stop, replacement character, emoji, and UTS-46 special cases.
cps <- c(
  0x20, 0x7F, 0x80, 0x85, 0xA0, 0xAD, 0xE9, 0xFC, 0x200B, 0x200E, 0x202E,
  0x2028, 0x3000, 0xFEFF, 0xFF0E, 0xFFFD, 0x1F600, 0x0130, 0x00DF, 0x03C2
)
cs <- vapply(cps, intToUtf8, "")
generated <- c(
  paste0("http://b", cs, "cher.example/"),
  paste0("http://u", cs, "ser:p", cs, "w@example.com/"),
  paste0("http://example.com/p", cs, "th"),
  paste0("http://example.com/?q=", cs, "&", cs, "=1"),
  paste0("https://example.com/#f", cs),
  paste0("http://example.com:80/", cs, "/", cs, "?", cs, "#", cs),
  "http://bücher.example/", "http://xn--bcher-kva.example/",
  "http://BÜCHER.example./", "http://%62%C3%BCcher.example/",
  "http://ab%E2%80%8Bc.example/",
  "http://例え.テスト/パス?q=値",
  "http://[::1]/é", "http://1.2.3.4/é?é",
  "http://example.com/a b?c d", "http://example.com/é",
  "http://ex­ample.com/", "http://faß.de/", "http://ⓔxample.com/"
)
inputs <- unique(c(corpus, generated))

# The string parse_boundary() hands curl_parse_url(): rurl's serialization,
# fragment removed, for an input past rurl's syntax and scheme verdicts.
rows <- lapply(inputs, function(u) {
  v <- read_verdicts(u)
  if (is.null(v) || v$layer1 != "pass" || v$layer2 != "admitted") {
    return(NULL)
  }
  w <- read_serialization(u)
  if (is.null(w)) {
    return(NULL)
  }
  w <- sub("#.*$", "", w)
  data.frame(
    input = u,
    wire = w,
    ascii = !grepl("[^\\x21-\\x7e]", w, perl = TRUE),
    today = if (is.null(parse_boundary(u)$finding)) "admitted" else "refused"
  )
})
res <- do.call(rbind, rows)
cat(
  "inputs:", length(inputs),
  "| past the syntax and scheme gates:", nrow(res),
  "| wire not printable ASCII:", sum(!res$ascii),
  "| of those admitted today:", sum(!res$ascii & res$today == "admitted"), "\n"
)
print(res[!res$ascii, ], right = FALSE, row.names = FALSE)
# inputs: 676 | past the syntax and scheme gates: 571 | wire not printable ASCII: 2 | of those admitted today: 0
#  input                   wire                   ascii today
#  http://b cher.example/  http://b cher.example/ FALSE refused
#  http://b　cher.example/ http://b cher.example/ FALSE refused
