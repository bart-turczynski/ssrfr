# check-design v1
"""Design-doc hygiene checks.

Three hard checks (exit 1 on failure):

1. ADR immutability  - an accepted ADR may not be edited, only superseded.
2. ARCHITECTURE.md coverage - every top-level source directory is named there.
3. Frontmatter - parses, and `status` is in the enum for its kind.

Plus one non-blocking warning: drafts left untouched in `_scratch/`.

Stdlib only, so it runs in R, Python, TypeScript, and extension repos alike
without adding a CI dependency. Invoke as `python3 scripts/check-design.py`.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ADR_STATUSES = {"proposed", "accepted", "superseded", "deprecated"}
SPEC_STATUSES = {"draft", "accepted", "shipped", "abandoned"}
IMMUTABLE_STATUSES = {"accepted"}

# Source directories per ecosystem, detected from marker files. Only the ones
# that actually exist are required, so a project that ships no `src/` is fine.
ECOSYSTEMS = [
    ("DESCRIPTION", ["R", "src"]),
    ("wxt.config.ts", ["entrypoints", "utils"]),
    ("pyproject.toml", ["src"]),
    ("package.json", ["src"]),
]
FALLBACK_SOURCE_DIRS = ["src", "lib"]

SCRATCH_STALE_DAYS = 3


def git(*args: str) -> str | None:
    """Run a git command, returning None if it fails (no remote, no repo, ...)."""
    # flake8-bandit flags every subprocess call. `shell=False` (the default) is
    # S603's premise, not its answer: with no shell in the picture the risk that
    # remains is argument injection, because git reads any argv element starting
    # with `-` as an option. Not every argument here is a literal - `upstream`,
    # `base` and `rel` are all parsed back out of git's own output - so the thing
    # that actually makes this safe is that none of them can lead with `-`: git
    # refuses to create a ref name that does, `base` is a SHA from merge-base,
    # and `rel` only ever reaches git embedded as f"{base}:{rel}". Keep that true
    # when adding callers. S607: `git` is resolved from PATH on purpose, so the
    # script runs wherever the checkout does - CI images, Homebrew, Nix, Windows.
    try:
        result = subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip()


def parse_frontmatter(text: str) -> dict[str, str] | None:
    """Parse a flat `key: value` YAML frontmatter block. None if absent."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return fields
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        fields[key.strip()] = value.strip()
    return None  # unterminated block


def check_frontmatter(root: Path, errors: list[str]) -> None:
    for kind, statuses in (("adr", ADR_STATUSES), ("specs", SPEC_STATUSES)):
        for path in sorted((root / "design" / kind).glob("*.md")):
            if path.name == "README.md":
                continue
            rel = path.relative_to(root)
            fields = parse_frontmatter(path.read_text(encoding="utf-8"))
            if fields is None:
                errors.append(f"{rel}: missing or unterminated YAML frontmatter")
                continue
            status = fields.get("status")
            if status is None:
                errors.append(f"{rel}: frontmatter has no `status`")
            elif status not in statuses:
                errors.append(f"{rel}: status {status!r} not in {sorted(statuses)}")
            elif status == "superseded" and not fields.get("superseded-by"):
                errors.append(
                    f"{rel}: status is superseded but `superseded-by` is unset"
                )


def check_adr_immutability(root: Path, errors: list[str]) -> None:
    """An accepted ADR may be superseded, never edited.

    Compares against the merge-base with the tracking branch. A freshly
    generated project has no remote yet, so the check no-ops rather than
    failing - there is no history to be immutable against.
    """
    upstream = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    base = git("merge-base", "HEAD", upstream) if upstream else None
    if base is None:
        return

    changed = git("diff", "--name-status", base, "HEAD", "--", "design/adr")
    if not changed:
        return

    for line in changed.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].startswith("M"):
            continue
        rel = parts[-1]
        if Path(rel).name.startswith("0000-"):
            continue  # the template itself
        before = git("show", f"{base}:{rel}")
        if before is None:
            continue
        old = parse_frontmatter(before) or {}
        path = root / rel
        new = (
            parse_frontmatter(path.read_text(encoding="utf-8")) if path.exists() else {}
        )
        old_status = old.get("status", "")
        new_status = (new or {}).get("status", "")
        if old_status in IMMUTABLE_STATUSES and new_status == old_status:
            errors.append(
                f"{rel}: accepted ADR was edited. Supersede it with a new ADR "
                f"instead, and set this one's status to `superseded`."
            )


def check_architecture_coverage(root: Path, errors: list[str]) -> None:
    architecture = root / "ARCHITECTURE.md"
    if not architecture.exists():
        errors.append("ARCHITECTURE.md is missing")
        return

    source_dirs = FALLBACK_SOURCE_DIRS
    for marker, dirs in ECOSYSTEMS:
        if (root / marker).exists():
            source_dirs = dirs
            break

    text = architecture.read_text(encoding="utf-8")
    for name in source_dirs:
        if not (root / name).is_dir():
            continue
        if name not in text:
            errors.append(f"ARCHITECTURE.md does not mention the `{name}/` directory")


def warn_stale_scratch(root: Path) -> list[str]:
    scratch = root / "_scratch"
    if not scratch.is_dir():
        return []
    cutoff = time.time() - SCRATCH_STALE_DAYS * 86400
    return sorted(
        path.relative_to(scratch).as_posix()
        for path in scratch.rglob("*")
        if path.is_file() and path.stat().st_mtime < cutoff
    )


def main() -> int:
    root_str = git("rev-parse", "--show-toplevel")
    root = Path(root_str) if root_str else Path.cwd()

    errors: list[str] = []
    check_frontmatter(root, errors)
    check_adr_immutability(root, errors)
    check_architecture_coverage(root, errors)

    stale = warn_stale_scratch(root)
    if stale:
        shown = ", ".join(stale[:5])
        more = f", +{len(stale) - 5} more" if len(stale) > 5 else ""
        print(
            f"warning: _scratch/: {len(stale)} file(s) untouched "
            f"{SCRATCH_STALE_DAYS}+ days ({shown}{more}). Graduate or delete.",
            file=sys.stderr,
        )

    if errors:
        print("check-design failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
