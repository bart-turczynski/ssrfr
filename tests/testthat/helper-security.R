# Disposition machinery for the OSS Index dependency audit in
# test-security.R. The allow-list lives here rather than in the test file
# because more than one test block reads it -- the offline well-formedness
# check and the network audit itself.
#
# WHY THESE ROWS. The contract this file implements is "every reported
# advisory has a current, explicit disposition", replacing "the scan reports
# nothing" (SEOR-fkvlzltx). ssrfr imports `curl` directly, and its hard
# dependency closure reports six advisories, all against curl 8.1.0, CRAN's
# current release: four measured 2026-10-18 with live OSS Index credentials,
# two more dispositioned 2026-10-23. These are the rows below; each says why
# the advisory does not reach a fetch made through ssrfr. Rows are added only
# for advisories the audit reports today: rule B fails a row that is not
# currently reported, so an anticipatory row is stale on arrival.
#
# Each row's reason cites its CVE's section in seor's
# design/oss-index-advisories.md, which holds the libcurl facts shared across
# the fleet (weakness, affected range, prerequisites, why R's curl can or
# cannot reach it), and argues only ssrfr's own route to curl: every option
# an attempt carries comes from transport_options() (R/transport.R), and
# dep_curl_transfer() (R/dependencies.R) is the one place that sets them.
#
# Three rules keep the list honest. test-security.R enforces them:
#
#   A  UNEXPECTED  an advisory reported and not allow-listed FAILS. This is
#                  the gate still doing its job.
#   B  STALE       an allow-listed advisory NO LONGER reported FAILS. An
#                  allow-list may not over-permit; a row that has outlived its
#                  justification is deleted, not left to widen the exemption
#                  silently.
#   C  DRIFT       past its review date, or audited at a package version later
#                  than `version_seen`, a row WARNS. Deliberately not a
#                  failure: a calendar date that turns every push red is how a
#                  gate teaches people to reach for --no-verify.
#
# Adding a row is a decision, not a formality. Rule B is what keeps it one.
#
# The reference implementation is seor's.

oss_index_allowlist <- list(
  list(
    id = "CVE-2026-18924",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "libcurl facts: seor design/oss-index-advisories.md#cve-2026-18924.",
      "Beyond R's curl having no push callback, ssrfr's transport pins",
      "http_version to HTTP/1.1 and sets forbid_reuse (R/transport.R), and",
      "each attempt runs alone in a pool with multiplex = FALSE",
      "(R/dependencies.R), so there is no shared HTTP/2 connection to push",
      "on. Re-check those two files before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-3783",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "libcurl facts: seor design/oss-index-advisories.md#cve-2026-3783.",
      "ssrfr's transport sets netrc = 0 and followlocation = 0",
      "(R/transport.R), so libcurl neither reads .netrc nor follows a",
      "redirect; ssrfr's own redirect hop (redirect_plan(), R/redirect.R)",
      "drops Authorization on any cross-origin hop. Re-check those two files",
      "before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-86410",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "libcurl facts: seor design/oss-index-advisories.md#cve-2026-86410.",
      "The flaw is in the curl command-line tool. ssrfr drives libcurl",
      "through R's curl (R/dependencies.R) and never runs the tool; its",
      "transport also limits protocols and redir_protocols to http,https and",
      "sets followlocation = 0 (R/transport.R), so no transfer is SFTP or",
      "SCP. Re-check with a search of R/ for system2()/processx calls to curl",
      "before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-87865",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "libcurl facts: seor design/oss-index-advisories.md#cve-2026-87865.",
      "The SSH key callback cannot be set from R. Independently, ssrfr's",
      "transport limits protocols and redir_protocols to http,https",
      "(R/transport.R), so libcurl never opens an SFTP or SCP transfer, and",
      "ssrfr sets no SSH option. Re-check R/transport.R before renewing this",
      "row."
    )
  ),
  list(
    id = "CVE-2026-86414",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "libcurl facts: seor design/oss-index-advisories.md#cve-2026-86414.",
      "ssrfr can hand libcurl origin credentials: URL userinfo, when a",
      "policy sets allow_userinfo, goes out as Basic auth (httpauth = 1).",
      "But its transport sets proxy = \"\" and noproxy = \"*\" and netrc = 0",
      "(R/transport.R), so no attempt goes through a proxy whatever the",
      "environment says, and no caller can set another curl option.",
      "Re-check R/transport.R before renewing this row."
    )
  ),
  list(
    id = "CVE-2026-87864",
    package = "curl",
    version_seen = "8.1.0",
    review = as.Date("2026-12-01"),
    reason = paste(
      "libcurl facts: seor design/oss-index-advisories.md#cve-2026-87864.",
      "ssrfr's transport limits protocols and redir_protocols to http,https",
      "(R/transport.R), so libcurl never opens the IMAP transfer an APPEND",
      "needs; it sets neither upload nor crlf, and no caller can set another",
      "curl option. Re-check R/transport.R before renewing this row."
    )
  )
)

# The fields every allow-list row carries, in the order they are documented.
oss_index_allowlist_fields <- c(
  "id",
  "package",
  "version_seen",
  "review",
  "reason"
)

# Problems with a set of allow-list rows, as a character vector; empty when the
# set is well formed. Written as a function returning findings rather than as a
# block of expectations so that it can be exercised against fixtures -- with no
# live rows, a loop of expectations over `oss_index_allowlist` would assert
# nothing at all and still report as a passing test.
oss_index_allowlist_violations <- function(rows) {
  out <- character()

  parses_as_version <- function(x) {
    tryCatch(
      {
        package_version(x)
        TRUE
      },
      error = function(e) FALSE,
      warning = function(w) FALSE
    )
  }

  for (i in seq_along(rows)) {
    row <- rows[[i]]
    label <- sprintf("row %d", i)

    absent <- setdiff(oss_index_allowlist_fields, names(row))
    unknown <- setdiff(names(row), oss_index_allowlist_fields)
    if (length(absent) > 0) {
      out <- c(
        out,
        sprintf("%s: missing field(s): %s", label, toString(absent))
      )
    }
    if (length(unknown) > 0) {
      out <- c(
        out,
        sprintf("%s: unknown field(s): %s", label, toString(unknown))
      )
    }
    if (length(absent) > 0) {
      next
    }

    label <- sprintf("row %d (%s)", i, paste(row$id, collapse = " "))
    if (
      !is.character(row$id) ||
        length(row$id) != 1L ||
        !grepl("^CVE-[0-9]{4}-[0-9]+$", row$id)
    ) {
      out <- c(out, sprintf("%s: `id` is not a single CVE identifier", label))
    }
    if (
      !is.character(row$package) ||
        length(row$package) != 1L ||
        !nzchar(row$package)
    ) {
      out <- c(
        out,
        sprintf("%s: `package` is not a single package name", label)
      )
    }
    if (
      !is.character(row$version_seen) ||
        length(row$version_seen) != 1L ||
        !parses_as_version(row$version_seen)
    ) {
      out <- c(
        out,
        sprintf("%s: `version_seen` is not a parseable version", label)
      )
    }
    if (!inherits(row$review, "Date") || length(row$review) != 1L) {
      out <- c(out, sprintf("%s: `review` is not a single Date", label))
    }
    # A reason long enough to be an argument rather than a placeholder.
    if (
      !is.character(row$reason) ||
        length(row$reason) != 1L ||
        nchar(row$reason) <= 80
    ) {
      out <- c(
        out,
        sprintf("%s: `reason` is missing or too short to be an argument", label)
      )
    }
  }

  ids <- vapply(
    rows,
    function(row) {
      if (is.character(row$id) && length(row$id) == 1L) {
        row$id
      } else {
        NA_character_
      }
    },
    character(1)
  )
  duplicates <- unique(ids[duplicated(ids) & !is.na(ids)])
  if (length(duplicates) > 0) {
    out <- c(
      out,
      sprintf("duplicate allow-list id(s): %s", toString(duplicates))
    )
  }

  out
}

# Flatten an oysteR::audit_description() result to one row per reported
# advisory. The `vulnerabilities` column is a list of per-package lists, empty
# for a clean package, so the zero-advisory case has to survive unlist().
oss_index_reported <- function(audit) {
  ids <- lapply(audit$vulnerabilities, function(v) {
    if (length(v) == 0) {
      return(character())
    }
    vapply(v, function(x) as.character(x$id), character(1))
  })
  data.frame(
    package = rep(as.character(audit$package), lengths(ids)),
    version = rep(as.character(audit$version), lengths(ids)),
    id = as.character(unlist(ids, use.names = FALSE))
  )
}
