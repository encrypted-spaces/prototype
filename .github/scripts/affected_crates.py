#!/usr/bin/env python3
"""Build the CI test matrix for the changes between two refs.

The group -> crates mapping lives in `.github/scripts/ci_matrix.json`. Each
entry defines a matrix `group`, the `packages: -p X -p Y …` string passed to
`cargo nextest`, and an optional nextest `filter`. That file is the single
source of truth for the build matrix: the workflow consumes whatever this
script emits, so there is no static matrix in the workflow to drift out of
sync.

Algorithm (PR mode):

1. Load the matrix entries from `ci_matrix.json`.
2. Run `cargo metadata --no-deps` to discover workspace members and their
   inter-workspace dependency edges.
3. Map changed files (`git diff --name-only base..head`) onto workspace
   crates and compute the transitive reverse-dependency closure.
4. Emit a `matrix` output containing only the entries whose group was
   affected, plus a `has_work` boolean.

In `--all` mode (push to main, workflow_dispatch) every entry is emitted
without inspecting any diff, so the full matrix runs.

Outputs (to `$GITHUB_OUTPUT`, or stdout when run locally):
    matrix={"include":[ …affected entries… ]}
    has_work=true|false

Run locally for debugging:
    python3 .github/scripts/affected_crates.py --base origin/main --head HEAD
    python3 .github/scripts/affected_crates.py --all
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Paths that affect the whole workspace; a change to any of these forces every
# group to run, bypassing per-crate scoping.
SHARED_PREFIXES = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".github/workflows/",
    ".github/actions/",
    ".github/scripts/",
)


def run(cmd: list[str], cwd: Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd, text=True).strip()


def load_matrix(matrix_path: Path) -> list[dict]:
    """Load and validate the matrix entries from `ci_matrix.json`.

    Returns the raw list of entries (each a dict with at least `group` and
    `packages`). Raises with a clear message if the shape is wrong, so a
    malformed edit fails visibly in CI rather than silently producing an
    empty matrix.
    """
    try:
        entries = json.loads(matrix_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Could not read matrix definition {matrix_path}: {e}") from e
    if not isinstance(entries, list) or not entries:
        raise RuntimeError(f"{matrix_path} must be a non-empty JSON array of matrix entries.")
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("group"):
            raise RuntimeError(f"Matrix entry missing `group`: {entry!r}")
        if not packages_to_crates(entry.get("packages", "")):
            raise RuntimeError(
                f"Matrix entry `{entry['group']}` produced an empty package list "
                f"(packages field: {entry.get('packages')!r})"
            )
    return entries


def packages_to_crates(packages: str) -> list[str]:
    """Tokenize a `-p X -p Y …` string into the list of crate names."""
    tokens = (packages or "").split()
    crates: list[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i] == "-p" and i + 1 < len(tokens):
            crates.append(tokens[i + 1])
            i += 2
        else:
            i += 1
    return crates


def load_workspace(repo_root: Path) -> tuple[dict[str, Path], dict[str, set[str]]]:
    """Return (members, deps).

    members: {package_name -> package_dir (relative to repo_root)}
    deps:    {package_name -> set of workspace-internal dependency names}
    """
    raw = run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=repo_root,
    )
    meta = json.loads(raw)
    workspace_names = {pkg["name"] for pkg in meta["packages"]}
    members: dict[str, Path] = {}
    deps: dict[str, set[str]] = {}
    for pkg in meta["packages"]:
        name = pkg["name"]
        manifest = Path(pkg["manifest_path"])
        members[name] = manifest.parent.relative_to(repo_root)
        deps[name] = {
            d["name"] for d in pkg["dependencies"] if d["name"] in workspace_names
        }
    return members, deps


def transitive_reverse_closure(deps: dict[str, set[str]]) -> dict[str, set[str]]:
    """For each package, return the set of packages that (transitively) depend on it."""
    reverse: dict[str, set[str]] = {pkg: set() for pkg in deps}
    for pkg, pkg_deps in deps.items():
        for d in pkg_deps:
            if d in reverse:
                reverse[d].add(pkg)

    closure: dict[str, set[str]] = {}
    for start in deps:
        seen: set[str] = set()
        stack = list(reverse[start])
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(reverse.get(node, ()))
        closure[start] = seen
    return closure


def changed_files(base: str, head: str, repo_root: Path) -> list[Path]:
    out = run(["git", "diff", "--name-only", f"{base}..{head}"], cwd=repo_root)
    return [Path(line) for line in out.splitlines() if line]


def is_shared(path: Path) -> bool:
    s = str(path)
    return any(s == prefix.rstrip("/") or s.startswith(prefix) for prefix in SHARED_PREFIXES)


def map_to_crate(path: Path, members: dict[str, Path]) -> str | None:
    """Find the workspace crate that owns `path`, or None if no crate matches."""
    matches = [
        (name, dir_)
        for name, dir_ in members.items()
        if str(path) == str(dir_) or str(path).startswith(str(dir_) + os.sep)
    ]
    if not matches:
        return None
    # Longest prefix wins so nested members (e.g. backend/server) beat their parent (backend).
    matches.sort(key=lambda x: len(str(x[1])), reverse=True)
    return matches[0][0]


def affected_groups(
    entries: list[dict], base: str, head: str, repo_root: Path
) -> dict[str, bool]:
    """Compute, per group, whether the diff base..head touches it."""
    groups = {e["group"]: packages_to_crates(e["packages"]) for e in entries}

    members, deps = load_workspace(repo_root)
    reverse_closure = transitive_reverse_closure(deps)

    files = changed_files(base, head, repo_root)
    print(f"::group::Changed files ({base}..{head})", file=sys.stderr)
    for f in files:
        print(f"  {f}", file=sys.stderr)
    print("::endgroup::", file=sys.stderr)

    if any(is_shared(f) for f in files):
        print("Shared path changed — forcing all groups affected.", file=sys.stderr)
        affected = set(members)
    else:
        directly: set[str] = set()
        unmatched: list[Path] = []
        for f in files:
            crate = map_to_crate(f, members)
            if crate is None:
                unmatched.append(f)
            else:
                directly.add(crate)
        affected = set(directly)
        for c in directly:
            affected |= reverse_closure.get(c, set())
        if unmatched:
            print("::group::Files outside any workspace crate (no group impact)", file=sys.stderr)
            for f in unmatched:
                print(f"  {f}", file=sys.stderr)
            print("::endgroup::", file=sys.stderr)

    print("::group::Affected crates", file=sys.stderr)
    for c in sorted(affected):
        print(f"  {c}", file=sys.stderr)
    print("::endgroup::", file=sys.stderr)

    return {g: any(c in affected for c in crates) for g, crates in groups.items()}


def write_outputs(matrix_entries: list[dict]) -> None:
    matrix_json = json.dumps({"include": matrix_entries}, separators=(",", ":"))
    has_work = "true" if matrix_entries else "false"
    print("::group::Selected matrix groups", file=sys.stderr)
    print(f"  {[e['group'] for e in matrix_entries] or '(none)'}", file=sys.stderr)
    print("::endgroup::", file=sys.stderr)
    lines = [f"matrix={matrix_json}", f"has_work={has_work}"]
    out_path = os.environ.get("GITHUB_OUTPUT")
    if out_path:
        with open(out_path, "a") as f:
            f.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", help="base ref or SHA to diff against (PR mode)")
    ap.add_argument("--head", help="head ref or SHA (PR mode)")
    ap.add_argument(
        "--all",
        action="store_true",
        help="emit the full matrix without inspecting a diff (push/dispatch)",
    )
    ap.add_argument(
        "--matrix",
        type=Path,
        default=Path(".github/scripts/ci_matrix.json"),
        help="path to the JSON file defining the matrix groups",
    )
    ap.add_argument("--repo-root", default=".", type=Path)
    args = ap.parse_args()

    repo_root = args.repo_root.resolve()
    matrix_path = args.matrix
    if not matrix_path.is_absolute():
        matrix_path = repo_root / matrix_path
    entries = load_matrix(matrix_path)

    if args.all:
        write_outputs(entries)
        return 0

    if not args.base or not args.head:
        ap.error("--base and --head are required unless --all is given")

    status = affected_groups(entries, args.base, args.head, repo_root)
    print("::group::Affected groups", file=sys.stderr)
    for g, v in status.items():
        print(f"  {g}: {v}", file=sys.stderr)
    print("::endgroup::", file=sys.stderr)

    selected = [e for e in entries if status.get(e["group"])]
    write_outputs(selected)
    return 0


if __name__ == "__main__":
    sys.exit(main())
