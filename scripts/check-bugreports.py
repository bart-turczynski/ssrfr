# check-bugreports v1 (ssrfr adaptation of pslr's scripts/check-bugreports.py,
# itself from pagerankr's by way of rurl's)
"""BugReports / tracker-link split gate.

WHY THIS EXISTS. CRAN runs two checks over a GitLab `BugReports:` URL and
they contradict each other. `tools::check_url_db()` fetches the address;
GitLab moved issue reporting to a work-items UI, so the classic `.../-/issues`
path 404s for a signed-out client (the client CRAN's check uses) while
`.../-/work_items` serves 200. `tools:::.check_package_CRAN_incoming()` fetches
nothing: it string-tests the path for `/issues` and flags anything else,
`/-/work_items` included, with a "should likely be .../issues" remark. No URL
satisfies both.

The fleet rule (SEOR-ocbtrrnl): the first pslr 1.2.1 upload declared
`/-/work_items` in `DESCRIPTION` and was archived at the CRAN pretest; its
resubmission with `/-/issues` was accepted. So the field the incoming check
string-tests keeps the `/-/issues` form, `cran-comments.md` explains the 404,
`scripts/verify.R`'s `allowed_notes` lets exactly that 404 through, and every
file a person clicks through points at `/-/work_items`.

WHAT IT CHECKS.

1. `DESCRIPTION`'s `BugReports:` ends in `/-/issues`, optionally `/new`,
   optionally a trailing slash, and does not name `/-/work_items`.
2. A roxygen `"_PACKAGE"` page (`man/*-package.Rd`), when one exists, carries
   a "Report bugs at" link IDENTICAL to `DESCRIPTION`'s `BugReports:`: roxygen2
   generates it from that field. ssrfr has no such page today.
3. Every human-facing file that carries the tracker link (SECURITY.md) names
   `/-/work_items` and no `/-/issues` form.
4. No other human-facing surface carries a `/-/issues` link. These name no
   tracker URL today, so the old form is forbidden without the new one being
   required.

NOT CHECKED, ON PURPOSE. `NEWS.md` and `cran-comments.md` are records of what
was announced or submitted, and `cran-comments.md` must quote the `/-/issues`
form to explain it. Nothing here touches the network: `R CMD check --as-cran`
already fetches declared URLs, and a pre-push gate should not need one.

Stdlib only.

    python3 scripts/check-bugreports.py              # exit 1 on drift
    python3 scripts/check-bugreports.py --self-test  # positive/negative cases
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ISSUES_RE = re.compile(
    r"https://gitlab\.com/[\w.-]+/[\w.-]+/-/issues(?:/new)?/?(?=[\s)\]\"'>`]|$)"
)
WORK_ITEMS_RE = re.compile(r"https://gitlab\.com/[\w.-]+/[\w.-]+/-/work_items\b")

# DESCRIPTION's BugReports: value, in full, must match this (the shape
# tools:::.check_package_CRAN_incoming() accepts).
BUGREPORTS_SAFE_RE = re.compile(r"^https://gitlab\.com/[\w.-]+/[\w.-]+/-/issues(?:/new)?/?$")

# Files a person clicks through that carry the tracker link: each must name
# /-/work_items.
HUMAN_FACING_FILES = ("SECURITY.md",)

# Human-facing surfaces that link no tracker today: /-/issues is forbidden,
# /-/work_items is not required. Globs, relative to the repository root.
NO_ISSUES_GLOBS = (
    "README.Rmd",
    "README.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    "_pkgdown.yml",
    "vignettes/*.Rmd",
    "inst/CITATION",
)


def read_dcf(path: Path) -> dict[str, str]:
    """Flat DCF fields, joining continuation lines."""
    fields: dict[str, str] = {}
    key: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            key = None
            continue
        if line[0].isspace():
            if key is not None:
                fields[key] += " " + line.strip()
            continue
        name, sep, value = line.partition(":")
        if not sep:
            key = None
            continue
        key = name.strip()
        fields[key] = value.strip()
    return fields


def check_repo(root: Path) -> list[str]:
    """Findings for one repository; empty when the split is intact."""
    errors: list[str] = []

    description = root / "DESCRIPTION"
    if not description.exists():
        return ["DESCRIPTION is missing; nothing to check the BugReports split against"]
    bugreports = read_dcf(description).get("BugReports", "")
    if not bugreports:
        return ["DESCRIPTION has no BugReports: field; it must use the /-/issues form"]

    if not BUGREPORTS_SAFE_RE.match(bugreports):
        errors.append(
            f"DESCRIPTION BugReports: is '{bugreports}', not the /-/issues form "
            f"(optionally /new, optionally a trailing slash). CRAN's incoming "
            f"check string-tests this field; pslr's first 1.2.1 upload was "
            f"archived at pretest for declaring /-/work_items here."
        )

    for rd in sorted((root / "man").glob("*-package.Rd")):
        match = re.search(r"Report bugs at \\url\{([^}]*)\}", rd.read_text(encoding="utf-8"))
        if match is not None and match.group(1) != bugreports:
            errors.append(
                f"{rd.relative_to(root)}'s 'Report bugs at' link is "
                f"'{match.group(1)}', but DESCRIPTION's BugReports: is "
                f"'{bugreports}'. roxygen2 generates it from DESCRIPTION: re-run "
                f"devtools::document(), do not hand-edit the .Rd."
            )

    for name in HUMAN_FACING_FILES:
        path = root / name
        if not path.exists():
            errors.append(f"{name} is missing; it carries the human-facing tracker link")
            continue
        text = path.read_text(encoding="utf-8")
        if ISSUES_RE.search(text):
            errors.append(
                f"{name} links a /-/issues form, which 404s for a signed-out "
                f"client. Use /-/work_items."
            )
        if not WORK_ITEMS_RE.search(text):
            errors.append(f"{name} does not name the project's /-/work_items tracker link.")

    seen = {root / name for name in HUMAN_FACING_FILES}
    for pattern in NO_ISSUES_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            if ISSUES_RE.search(path.read_text(encoding="utf-8", errors="replace")):
                errors.append(
                    f"{path.relative_to(root)} links a /-/issues form, which "
                    f"404s for a signed-out client. Use /-/work_items."
                )

    return errors


# --- self-test ---------------------------------------------------------------


def _fixture(directory: Path, bugreports: str, files: dict[str, str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "DESCRIPTION").write_text(
        f"Package: fixture\nVersion: 0.1.0\nBugReports: {bugreports}\n",
        encoding="utf-8",
    )
    for name, content in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return directory


def self_test() -> None:
    org = "https://gitlab.com/bart-turczynski/fixture"
    issues = f"{org}/-/issues"
    work_items = f"{org}/-/work_items"
    intact = {
        "SECURITY.md": f"1. Go to [Issues]({work_items}) and click New issue.",
        "README.md": "Install from CRAN.",
        "CONTRIBUTING.md": "`BugReports:` keeps the `/-/issues` form.",
    }

    def run(tag: str, bugreports: str, files: dict[str, str]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            return check_repo(_fixture(Path(tmp) / tag, bugreports, files))

    def expect_clean(tag: str, bugreports: str, files: dict[str, str]) -> None:
        found = run(tag, bugreports, files)
        if found:
            raise SystemExit(f"self-test FAILED ({tag}): {found}")

    def expect_flagged(tag: str, needle: str, bugreports: str, files: dict[str, str]) -> None:
        found = run(tag, bugreports, files)
        if not any(needle in f for f in found):
            raise SystemExit(f"self-test FAILED ({tag}): expected {needle!r}, got {found}")

    # POSITIVE: the split as ssrfr has it, and with a generated package page.
    expect_clean("split-intact", issues, intact)
    expect_clean(
        "package-rd-agrees",
        issues,
        {**intact, "man/fixture-package.Rd": f"Report bugs at \\url{{{issues}}}\n"},
    )

    # NEGATIVE: DESCRIPTION regressed to /-/work_items (the pslr pretest case).
    expect_flagged("description-regressed", "not the /-/issues form", work_items, intact)

    # NEGATIVE: a generated package page not regenerated after a DESCRIPTION edit.
    expect_flagged(
        "package-rd-stale",
        "re-run devtools::document()",
        issues,
        {**intact, "man/fixture-package.Rd": f"Report bugs at \\url{{{work_items}}}\n"},
    )

    # NEGATIVE: SECURITY.md reverted to /-/issues, or lost the tracker link.
    expect_flagged(
        "security-reverted",
        "SECURITY.md links a /-/issues form",
        issues,
        {**intact, "SECURITY.md": f"1. Go to [Issues]({issues}/new)."},
    )
    expect_flagged(
        "security-missing-work-items",
        "does not name the project's /-/work_items",
        issues,
        {**intact, "SECURITY.md": "Report a vulnerability by e-mail."},
    )

    # NEGATIVE: a surface with no tracker link today gains a /-/issues link.
    expect_flagged(
        "vignette-issues-link",
        "vignettes/introduction.Rmd links a /-/issues form",
        issues,
        {**intact, "vignettes/introduction.Rmd": f"Report problems at <{issues}>."},
    )
    expect_flagged(
        "contributing-issues-link",
        "CONTRIBUTING.md links a /-/issues form",
        issues,
        {**intact, "CONTRIBUTING.md": f"File it at `{issues}`."},
    )

    print("check-bugreports self-test: PASS (2 positive + 6 negative cases)")


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        self_test()
        return 0

    root = Path(__file__).resolve().parent.parent
    errors = check_repo(root)
    if errors:
        print("check-bugreports failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("check-bugreports: BugReports split (DESCRIPTION vs human-facing files) is intact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
