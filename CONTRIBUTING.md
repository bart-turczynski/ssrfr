# Contributing

Install dependencies:

```sh
Rscript -e 'pak::local_install_deps(dependencies = TRUE)'
```

Run verification:

```sh
Rscript scripts/verify.R
python3 scripts/check-design.py
```

Source lives in `R/`, tests and cucumber feature specs live in `tests/testthat/`,
and the design — specification, ADRs, evidence — lives in `design/`. Implement
only against `[ratified]` sections of `design/specs/ssrfr-v1.md`.

Do not commit `.fp/`, secrets, dependency folders, build outputs, or generated caches.

## CRAN release checklist

Follow these steps in order for every CRAN release. `X.Y.Z` is the release
version. Before step 1, every `Imports` floor in `DESCRIPTION` (`curl`, `raddr`,
`rurl`) must already be on CRAN.

Steps 1 and 2 change files the tarball carries. Land them on `main` through a
merge request before step 4, so the tarball you check and the tarball you
submit are built from the same package files. Steps 3 and 8 touch only
`cran-comments.md` and `design/`, which `.Rbuildignore` keeps out of the
tarball, so they do not invalidate the checks before them. Land them on `main`
too before step 9, so the commit you submit and tag is on `main` and carries
both.

1. **Set the release version** in `DESCRIPTION`: `Version: X.Y.Z`, with the
   `.9000` dropped.
2. **Update the NEWS heading** in the same commit. The top `NEWS.md` heading
   becomes `# ssrfr X.Y.Z`, and every unreleased item goes under it. The verify
   gate's `news-version` stage fails unless that heading is
   `(development version)` or the `DESCRIPTION` Version, so bump the two
   together.
3. **Rewrite `cran-comments.md`** for this submission:
   - Test environments: list only the ones steps 4 to 7 actually ran (OS, R
     version, and where it ran: local, win-builder, R-hub, the GitLab
     `full-check` job). There is no GitHub Actions CI. Finish the list once
     step 7 reports, before step 9.
   - The NOTEs: say what each one is. On a first submission that is "New
     submission". R's URL check also reports the `BugReports` URL as possibly
     invalid, Status 404. `DESCRIPTION` keeps the `/-/issues` form because R's
     incoming check flags any other path, and a sibling package (pslr) was
     archived at the pretest for declaring `/-/work_items`. GitLab serves
     `/-/issues` as 404 to a signed-out client, and every file a person reads
     links `/-/work_items` instead (SEOR-ocbtrrnl). Keep the `BugReports`
     section of `cran-comments.md`, which says this; `allowed_notes` in
     `scripts/verify.R` lets exactly that 404 through, and the
     `check-bugreports` hook holds the split. Before you submit, check each
     URL again with `curl -s -o /dev/null -w '%{http_code}\n' <url>`.
4. **Run the verify gate** on the release commit: `Rscript scripts/verify.R`,
   then `Rscript scripts/check-spelling.R`. The gate runs lint, `news-version`,
   the tests with `NOT_CRAN=true` and `R CMD check --as-cran`. Its check stage
   needs HTML Tidy 5.0.0 or later (see the comment above `allowed_notes`). If
   the gate is red on a tree nobody changed, run
   `Rscript scripts/check-toolchain.R` first: it names the machine drift
   (roxygen2 against `Config/roxygen2/version`, packages built under a newer
   R) that otherwise looks like a defect (`AGENTS_LANG.md`).
5. **Check the tarball you will submit**:

   ```sh
   R CMD build .
   R CMD check --as-cran ssrfr_X.Y.Z.tar.gz
   ```

   This runs without `allowed_notes`, so read every NOTE yourself. Nothing
   beyond the notes step 3 explains should appear. Read the URL paragraph with
   extra care: the verify gate lets a URL through when its host did not
   resolve or timed out, and a dead domain looks exactly the same.
6. **Check every URL**: `urlchecker::url_check()`, online. It reports dead and
   moved links in `DESCRIPTION`, `man/`, the vignette, README and NEWS,
   including any the verify gate let through as unresolvable.
7. **Check other platforms.**
   - win-builder, all three flavors: `devtools::check_win_devel()`,
     `devtools::check_win_release()` and `devtools::check_win_oldrelease()`.
     Results arrive by email to the `DESCRIPTION` maintainer.
   - R-hub: `rhub::rc_submit(path = <tarball>, platforms = ..., confirmation = TRUE)`,
     with Windows among the platforms (see `rhub::rhub_platforms()`). R-hub
     takes one submission every five minutes.
   - The R-version matrix on Linux: start a pipeline by hand on the release
     commit (**Build > Pipelines > Run pipeline**) and run the manual
     `full-check` job.

   On Windows, R-hub gets the corpus fixtures wrong unless you prepare the
   tarball. R-hub checks the tarball out with git, and on Windows git's
   `core.autocrlf` gives the corpus files CRLF endings, so their checksums
   fail. `.gitattributes` (`* text=auto eol=lf`) prevents that, but
   `.Rbuildignore` leaves it out of the built tarball. For the R-hub Windows
   run, add `.gitattributes` to the built tarball by hand. On macOS, repack it
   with `COPYFILE_DISABLE=1 tar --no-xattrs --format ustar`, or `rc_submit()`
   cannot read its `DESCRIPTION`. The evidence is in `design/specs/r-binding.md`
   §7, "Harness notes", the R-hub paragraph. The repacked tarball is for R-hub
   only; CRAN gets the one step 5 built.
8. **Record the conformance results**: run
   `Rscript scripts/conformance-results.R` on the release candidate. It writes
   `design/evidence/<YYYY-MM-DD>-conformance-results.txt`. Commit that file
   where `design/specs/r-binding.md` says, before submission. Published results
   name the corpus version and the dependency versions (`ssrfr-v1.md` §7), and
   they are what backs a conformance claim (`ssrfr-v1.md` §15).
9. **Submit to CRAN** with `devtools::submit_cran()` and confirm through the
   link CRAN emails to the maintainer. `devtools::submit_cran()` writes
   `CRAN-SUBMISSION`, which records the submitted commit. Do not commit it.
10. Once CRAN accepts, **tag the released commit** and push the tag:
    `git tag -a vX.Y.Z <sha> -m "ssrfr X.Y.Z"`, then `git push origin vX.Y.Z`.
    Use the commit `CRAN-SUBMISSION` names, which must be on `main`:
    `git merge-base --is-ancestor vX.Y.Z main` exits 0. Then delete
    `CRAN-SUBMISSION`.
11. **Create the GitLab release** from the tag:
    `glab release create vX.Y.Z --notes-file <file>`, where the file holds that
    version's `NEWS.md` section. The GitHub repository is a read-only mirror;
    do not create a release there.
12. **Mark the spec shipped**, per `design/README.md`, only now that CRAN has
    accepted: a CRAN review can force changes, and a shipped spec is never
    updated again. Distill the durable facts into `ARCHITECTURE.md` and the
    load-bearing choices into an ADR, then set `status: shipped` in the front
    matter of `design/specs/ssrfr-v1.md`. `python3 scripts/check-design.py`
    must still pass. Land it on `main` through a merge request, its own or
    step 13's. None of these files is in the tarball, so the tag still matches
    what CRAN has.
13. **Open a post-release merge request** that:
    - bumps `DESCRIPTION` to `X.Y.Z.9000`: the release just published plus a
      fourth component, not the next patch number;
    - adds a fresh `# ssrfr (development version)` heading at the top of
      `NEWS.md`;
    - adds `https://CRAN.R-project.org/package=ssrfr` to the `DESCRIPTION`
      `URL:` field, which only exists once CRAN has accepted the package.

    Leave `cran-comments.md` alone here: it describes the submission that just
    landed, and step 3 of the next release rewrites it. `allowed_notes` already
    allows the `.9000` "Version contains large components" NOTE.
14. **Sanity check**: diff the published CRAN tarball
    (`https://cran.r-project.org/src/contrib/ssrfr_X.Y.Z.tar.gz`) against
    `R CMD build` of the tag. Only the `DESCRIPTION` fields CRAN adds should
    differ.
