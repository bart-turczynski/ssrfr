# Rewrites tests/testthat/fixtures/corpus-manifest.tsv: the data-row count and
# MD5 of every conformance corpus file (ssrfr-v1.md §7.2). Run it in the commit
# that changes a corpus file, from the repository root:
#   Rscript scripts/corpus-manifest.R
#
# MD5 guards against accidental edits and truncation, which is the threat here;
# tools::sha256sum() needs R 4.5.0, above the package's R (>= 4.0.0) floor
# (r-binding.md §7, Corpora).

corpus_dir <- file.path("tests", "testthat", "fixtures")
corpus_files <- c("verdict-vectors.tsv", "parse-vectors.tsv", "requirements.tsv")

rows <- vapply(corpus_files, function(f) {
  lines <- readLines(file.path(corpus_dir, f), encoding = "UTF-8", warn = FALSE)
  length(lines) - 1L
}, integer(1))
md5 <- unname(tools::md5sum(file.path(corpus_dir, corpus_files)))

manifest <- data.frame(file = corpus_files, rows = rows, md5 = md5)
write.table(manifest, file.path(corpus_dir, "corpus-manifest.tsv"),
            sep = "\t", quote = FALSE, row.names = FALSE, eol = "\n")
print(manifest, row.names = FALSE)
