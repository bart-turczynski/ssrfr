## BugReports

`BugReports:` is `https://gitlab.com/bart-turczynski/ssrfr/-/work_items`. The
incoming check suggests an `/issues` path instead ("which should likely
be ..."). On gitlab.com, `/-/issues` answers 404 to a non-browser client,
`tools::check_url_db()` included, while `/-/work_items` answers 200. On
2026-10-23 Uwe Ligges called this NOTE a bug in the check for GitLab and
invited the `/-/work_items` form on the pslr 1.2.2 submission, which CRAN
then published. Quote the local check's wording of the NOTE here when
submitting, and keep this paragraph in the submission comments
([seor ADR 0011](https://gitlab.com/bart-turczynski/seor/-/blob/main/design/adr/0011-bugreports-names-work-items.md)).

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new submission.

## Test environments

* local: <your OS>, R <version>
* GitHub Actions: macOS, Windows, Ubuntu (R devel, release, oldrel-1)

## Downstream dependencies

None — this is a new package.
