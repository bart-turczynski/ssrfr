# The conformance corpus (ssrfr-v1.md §7). Each file is checked against the row
# count and MD5 committed in corpus-manifest.tsv before any row is read, so a
# truncated or emptied file fails instead of passing vacuously (§7.2). Then
# the files' shape and vocabulary are checked, and the rows the implemented
# layers decide are evaluated: every L0 verdict vector through
# ssrf_inspect_url(), and every parse vector through the parse boundary.
# The readers live in helper-corpus.R.
#
# A pending row is never skipped (§7.2): its marker is asserted, and so is the
# fact that its expectation still does not hold, so the day the upstream fix
# lands the test fails and the row is promoted to active.

# A field may carry only the escapes defined in fixtures/README.md.
has_bad_escape <- function(x) {
  rest <- gsub("\\\\(\\\\|t|n|r|0|u\\{[0-9A-Fa-f]{4,6}\\})", "", x)
  grepl("\\", rest, fixed = TRUE)
}

# The corpus may use only codes and causes from the closed domains (§6.1), which
# test-vocabulary.R pins.
reason_codes <- ssrf_vocabulary("reason_codes")$code
causes <- ssrf_vocabulary("causes")$cause
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

# Evidence of the form `test-<file>.R: <test_that name>` names a test that
# exists, so a renamed test cannot leave a requirement citing nothing.
test_that("every requirement cites tests that exist", {
  evidence <- read_corpus("requirements.tsv")$evidence
  evidence <- unlist(strsplit(evidence, " ; ", fixed = TRUE))
  cited <- grep("^test-[a-z-]+[.]R: ", evidence, value = TRUE)
  expect_gt(length(cited), 0L)
  for (item in unique(cited)) {
    file <- sub(": .*$", "", item)
    name <- sub("^[^:]*: ", "", item)
    src <- paste(
      readLines(test_path(file), encoding = "UTF-8"),
      collapse = "\n"
    )
    expect_true(
      grepl(paste0("test_that(\"", name, "\""), src, fixed = TRUE),
      label = item
    )
  }
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

# The rows below are evaluated only when every file matches its manifest
# (§7.2): a mismatch stops this file before any row is read.
local({
  manifest <- read_corpus("corpus-manifest.tsv")
  for (i in seq_len(nrow(manifest))) {
    path <- test_path("fixtures", manifest$file[i])
    if (!identical(unname(tools::md5sum(path)), manifest$md5[i])) {
      stop("corpus file does not match its manifest: ", manifest$file[i])
    }
  }
})

test_that("every active L0 verdict vector is decided at L0 with its code", {
  v <- read_corpus("verdict-vectors.tsv")
  rows <- v[v$layer == "L0" & v$status == "active", ]
  expect_gt(nrow(rows), 0L)
  for (i in seq_len(nrow(rows))) {
    expect_identical(
      inspect_row(rows[i, ]),
      rows$code[i],
      label = paste(rows$id[i], rows$group[i], rows$input[i])
    )
  }
})

test_that("pending L0 verdict vectors keep their marker and still differ", {
  v <- read_corpus("verdict-vectors.tsv")
  rows <- v[v$layer == "L0" & startsWith(v$status, "pending:"), ]
  expect_identical(rows$id, "V0350")
  expect_identical(rows$status, "pending:RURL-vicyvlvh")
  for (i in seq_len(nrow(rows))) {
    expect_false(
      identical(inspect_row(rows[i, ]), rows$code[i]),
      label = paste(
        rows$id[i],
        "now meets its expectation: the upstream fix has landed, mark it active"
      )
    )
  }
})

# §7: a row must be decided at its layer or earlier. L0 decides no later
# row, and it must not report a different code for one either.
test_that("L0 reports no code that contradicts a later layer's row", {
  v <- read_corpus("verdict-vectors.tsv")
  rows <- v[v$layer != "L0" & v$status == "active", ]
  expect_gt(nrow(rows), 0L)
  for (i in seq_len(nrow(rows))) {
    got <- inspect_row(rows[i, ])
    expect_true(
      got == "-" || (rows$verdict[i] == "refuse" && got == rows$code[i]),
      label = paste(rows$id[i], rows$input[i], "gives", got, "at L0")
    )
  }
})

test_that("every active parse vector meets its expectation, host by value", {
  p <- read_corpus("parse-vectors.tsv")
  rows <- p[p$status == "active", ]
  expect_gt(nrow(rows), 0L)
  for (i in seq_len(nrow(rows))) {
    label <- paste(rows$id[i], rows$input[i])
    got <- parse_row(rows$input[i])
    expect_identical(got$outcome, rows$expect[i], label = label)
    if (rows$expect[i] == "agree") {
      # INV-1, INV-2: the host the guard acts on is the host the transport
      # dials, and the one rurl read.
      expect_true(
        same_host_value(got$host, unescape_field(rows$curl_host[i])),
        label = paste(label, "guard host equals libcurl's host")
      )
      expect_true(
        same_host_value(got$host, unescape_field(rows$rurl_host[i])),
        label = paste(label, "guard host equals rurl's host")
      )
    }
  }
})

test_that("pending parse vectors keep their marker and still differ", {
  p <- read_corpus("parse-vectors.tsv")
  rows <- p[startsWith(p$status, "pending:"), ]
  expect_identical(rows$id, c("P0060", "P0061", "P0062"))
  expect_true(all(rows$status == "pending:RURL-vicyvlvh"))
  for (i in seq_len(nrow(rows))) {
    expect_false(
      identical(parse_row(rows$input[i])$outcome, rows$expect[i]),
      label = paste(
        rows$id[i],
        "now meets its expectation: the upstream fix has landed, mark it active"
      )
    )
  }
})
