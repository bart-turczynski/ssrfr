This is the first submission of ssrfr, version 1.0.0.

## R CMD check results

0 errors | 0 warnings | 1 note

The note is the incoming-feasibility one:

* This is a new submission.
* The `BugReports` suggestion, explained below.

## BugReports

`BugReports:` is `https://gitlab.com/bart-turczynski/ssrfr/-/work_items`. The
incoming check suggests an `/issues` path instead ("which should likely
be ..."). On gitlab.com, `/-/issues` answers 404 to a non-browser client,
`tools::check_url_db()` included, while `/-/work_items` answers 200. On
2026-10-23 Uwe Ligges called this NOTE a bug in the check for GitLab and
invited the `/-/work_items` form on the pslr 1.2.2 submission, which CRAN
then published
([seor ADR 0011](https://gitlab.com/bart-turczynski/seor/-/blob/main/design/adr/0011-bugreports-names-work-items.md)).
The NOTE, as R 4.6.1 words it:

```
The BugReports field in DESCRIPTION has
  https://gitlab.com/bart-turczynski/ssrfr/-/work_items
which should likely be
  https://gitlab.com/bart-turczynski/ssrfr/-/work_items/issues
instead.
```

## Test environments

* local: macOS 26.7.1 (aarch64-apple-darwin), R 4.6.1, `R CMD check --as-cran`
  with remote incoming checks
* Docker: Linux (aarch64-unknown-linux-gnu), R 4.6.1

## Downstream dependencies

None: this is a new package.
