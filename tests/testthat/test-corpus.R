# The conformance corpus (ssrfr-v1.md §7). Each file is checked against the row
# count and MD5 committed in corpus-manifest.tsv before any row is read, so a
# truncated or emptied file fails instead of passing vacuously (§7.2). The rows
# are evaluated against the guard once it exists; until then these tests check
# the files' shape and vocabulary.

read_corpus <- function(file) {
  utils::read.delim(
    test_path("fixtures", file),
    quote = "",
    comment.char = "",
    na.strings = character(),
    colClasses = "character",
    encoding = "UTF-8",
    check.names = FALSE
  )
}

# A field may carry only the escapes defined in fixtures/README.md.
has_bad_escape <- function(x) {
  rest <- gsub("\\\\(\\\\|t|n|r|0|u\\{[0-9A-Fa-f]{4,6}\\})", "", x)
  grepl("\\", rest, fixed = TRUE)
}

reason_codes <- c(
  "loopback",
  "private",
  "link-local",
  "cloud-metadata",
  "shared",
  "unspecified",
  "this-network",
  "ipv4-mapped",
  "ipv4-translated",
  "ipv4-compatible",
  "nat64",
  "6to4",
  "teredo",
  "isatap",
  "malformed-address",
  "numeric-literal",
  "scheme",
  "downgrade",
  "userinfo",
  "port",
  "host-denied",
  "range-denied",
  "parse",
  "multicast",
  "redirect-limit",
  "reserved"
)
causes <- c(
  "unresolvable",
  "pin-mismatch",
  "connect-failed",
  "tls-failed",
  "timeout",
  "response-too-large",
  "protocol-error"
)
status_ok <- function(x) grepl("^(active|pending:.+|superseded:.+)$", x)

test_that("every corpus file matches its committed row count and checksum", {
  manifest <- read_corpus("corpus-manifest.tsv")
  expect_setequal(
    manifest$file,
    c("verdict-vectors.tsv", "parse-vectors.tsv", "requirements.tsv")
  )
  for (i in seq_len(nrow(manifest))) {
    path <- test_path("fixtures", manifest$file[i])
    expect_identical(
      unname(tools::md5sum(path)),
      manifest$md5[i],
      label = paste("MD5 of", manifest$file[i])
    )
    expect_identical(
      nrow(read_corpus(manifest$file[i])),
      as.integer(manifest$rows[i]),
      label = paste("rows of", manifest$file[i])
    )
  }
})

test_that("verdict vectors are well formed", {
  v <- read_corpus("verdict-vectors.tsv")
  expect_named(
    v,
    c(
      "id",
      "group",
      "input",
      "answers",
      "policy",
      "hop",
      "verdict",
      "code",
      "layer",
      "status",
      "source",
      "note"
    )
  )
  expect_true(all(grepl("^V[0-9]{4}$", v$id)))
  expect_false(anyDuplicated(v$id) > 0)
  expect_false(anyDuplicated(v[c("input", "answers", "policy", "hop")]) > 0)
  expect_true(all(
    v$group %in%
      c(
        "ipv4-literal",
        "numeric-literal",
        "ipv6-spelling",
        "ipv6-literal",
        "embedding",
        "provider-endpoint",
        "metadata-hostname",
        "parser-confusion",
        "idn",
        "dns-answer",
        "redirect",
        "scheme",
        "port",
        "userinfo",
        "policy",
        "limit",
        "operational"
      )
  ))
  expect_true(all(v$verdict %in% c("refuse", "fail", "admit")))
  expect_true(all(v$code[v$verdict == "refuse"] %in% reason_codes))
  expect_true(all(v$code[v$verdict == "fail"] %in% causes))
  expect_true(all(v$code[v$verdict == "admit"] == "-"))
  expect_true(all(v$layer %in% c("L0", "L1", "L2")))
  expect_true(all(grepl("^(first|redirect:.+)$", v$hop)))
  expect_true(all(status_ok(v$status)))
  expect_false(any(has_bad_escape(v$input)))
  expect_true(all(nzchar(v$input) & nzchar(v$answers) & nzchar(v$policy)))
})

test_that("parse vectors are well formed", {
  p <- read_corpus("parse-vectors.tsv")
  expect_identical(
    names(p)[1:6],
    c(
      "id",
      "input",
      "expect",
      "status",
      "source",
      "note"
    )
  )
  expect_true(all(grepl("^P[0-9]{4}$", p$id)))
  expect_false(anyDuplicated(p$id) > 0)
  expect_false(anyDuplicated(p$input) > 0)
  expect_true(all(p$expect %in% c("parse", "scheme", "agree")))
  expect_true(all(p$measured %in% c("parse", "scheme", "agree")))
  expect_true(all(status_ok(p$status)))
  expect_false(any(has_bad_escape(p$input)))
})

test_that("requirement coverage is well formed", {
  r <- read_corpus("requirements.tsv")
  expect_named(
    r,
    c(
      "id",
      "framework",
      "external_id",
      "requirement",
      "class",
      "spec",
      "evidence",
      "source",
      "note"
    )
  )
  expect_true(all(grepl("^REQ-[0-9]{3}$", r$id)))
  expect_false(anyDuplicated(r$id) > 0)
  expect_true(all(
    r$class %in%
      c(
        "enforced-by-library",
        "enforced-by-application",
        "out-of-scope"
      )
  ))
})

# The research notes are git-ignored, so a row citing one cites nothing a
# reader can check (§7.1).
test_that("every row cites a committed or public source", {
  files <- c("verdict-vectors.tsv", "parse-vectors.tsv", "requirements.tsv")
  for (file in files) {
    src <- read_corpus(file)$source
    label <- paste("sources in", file)
    expect_true(all(nzchar(src)), label = label)
    expect_false(any(grepl("_scratch|(^|[ ;(])research/", src)), label = label)
  }
})
