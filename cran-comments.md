## BugReports

`BugReports:` is `https://gitlab.com/bart-turczynski/ssrfr/-/issues`, the form
the incoming check asks for. GitLab now serves that address as a 404 to a
signed-out, non-browser client, so the URL check reports it as possibly
invalid; a browser is redirected to the tracker at `/-/work_items`. The
alternative, declaring `/-/work_items`, draws the incoming NOTE instead: a
sibling package's first 1.2.1 upload (pslr) was archived at the pretest for
it, and its resubmission with `/-/issues` was accepted, as rurl 3.0.1 and
raddr 0.1.2 were. So the field keeps `/-/issues`, and every file a person
reads points at `/-/work_items`. Expect the 404 NOTE.

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new submission.

## Test environments

* local: <your OS>, R <version>
* GitHub Actions: macOS, Windows, Ubuntu (R devel, release, oldrel-1)

## Downstream dependencies

None — this is a new package.
