#!/usr/bin/env python3
"""Prepare an automatic patch release from the current master checkout."""

import argparse
import datetime
import json
import os
import pathlib
import re
import subprocess
import sys

import tomllib

ROOT = pathlib.Path(
    os.environ.get("PX_RELEASE_ROOT", pathlib.Path(__file__).resolve().parents[1])
).resolve()
PYTHON_VERSION_FILE = ROOT / ".github" / "bundled-python-version"
INITIAL_BUNDLED_PYTHON = "3.13.17"


class AutoReleaseError(ValueError):
    """Automatic release metadata is inconsistent."""


def package_versions(lock: bytes) -> dict[str, tuple[str, ...]]:
    packages: dict[str, set[str]] = {}
    for package in tomllib.loads(lock.decode())["package"]:
        packages.setdefault(package["name"], set()).add(package["version"])
    return {name: tuple(sorted(versions)) for name, versions in packages.items()}


def bump_patch(version: str) -> str:
    major, minor, patch = version.split(".")
    return f"{major}.{minor}.{int(patch) + 1}"


def replace_requirement(text: str, name: str, version: str) -> str:
    pattern = rf'("{re.escape(name)}>=)[^"]+(")'
    updated, count = re.subn(pattern, rf"\g<1>{version}\2", text, count=1)
    if count != 1:
        raise AutoReleaseError(f"could not update the {name} minimum")  # noqa: TRY003
    return updated


def dependency_changes(
    old: dict[str, tuple[str, ...]], new: dict[str, tuple[str, ...]]
) -> list[str]:
    changes = []
    for name in sorted(old.keys() | new.keys()):
        before = ", ".join(old.get(name, ("not locked",)))
        after = ", ".join(new.get(name, ("removed",)))
        if before != after:
            changes.append(f"`{name}` {before} -> {after}")
    return changes


def insert_changelog(version: str, dependencies: list[str], old_python: str, new_python: str) -> None:
    path = ROOT / "docs" / "changelog.md"
    text = path.read_text()
    lines = [
        f"## v{version} — {datetime.date.today().isoformat()}",
        "",
        "### Improvements",
    ]
    if dependencies:
        lines.append("- Refreshed locked dependencies:")
        lines.extend(f"  - {change}" for change in dependencies)
    if old_python != new_python:
        lines.extend(
            [
                f"- Updated standalone binaries and Docker images from CPython {old_python}",
                f"  to the newest published CPython {new_python} patch release.",
            ]
        )
    lines.extend(["", "---", ""])
    marker = "---\n"
    if marker not in text:
        raise AutoReleaseError("could not find changelog insertion point")  # noqa: TRY003
    path.write_text(text.replace(marker, marker + "\n" + "\n".join(lines), 1))


def newest_python() -> str:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import tools; print(tools.latest_python())",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def prepare() -> dict[str, object]:
    old_lock = (ROOT / "uv.lock").read_bytes()
    old_packages = package_versions(old_lock)
    old_python = (
        PYTHON_VERSION_FILE.read_text().strip()
        if PYTHON_VERSION_FILE.exists()
        else INITIAL_BUNDLED_PYTHON
    )

    subprocess.run(["uv", "lock", "--upgrade"], cwd=ROOT, check=True)  # noqa: S607
    new_lock = (ROOT / "uv.lock").read_bytes()
    new_packages = package_versions(new_lock)
    new_python = newest_python()
    dependencies = dependency_changes(old_packages, new_packages)

    if old_lock == new_lock and old_python == new_python:
        return {
            "changed": False,
            "dependencies": [],
            "python": new_python,
        }

    pyproject_path = ROOT / "pyproject.toml"
    pyproject = pyproject_path.read_text()
    current_version = tomllib.loads(pyproject)["project"]["version"]
    version = bump_patch(current_version)
    pyproject = re.sub(
        r'(?m)^version = "[^"]+"$', f'version = "{version}"', pyproject, count=1
    )
    for dependency in ("pymcurl", "quickjs-ng"):
        resolved = new_packages.get(dependency)
        if not resolved or len(resolved) != 1:
            raise AutoReleaseError(  # noqa: TRY003
                f"expected one resolved {dependency} version"
            )
        pyproject = replace_requirement(pyproject, dependency, resolved[0])
    pyproject_path.write_text(pyproject)
    PYTHON_VERSION_FILE.write_text(new_python + "\n")
    insert_changelog(version, dependencies, old_python, new_python)

    # Refresh the project metadata recorded in the lock after changing its version
    # and dependency minimums.
    subprocess.run(["uv", "lock"], cwd=ROOT, check=True)  # noqa: S607
    return {
        "changed": True,
        "version": version,
        "branch": f"release/auto-{version}",
        "dependencies": dependencies,
        "python": new_python,
        "previous_python": old_python,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    result = prepare()
    output = json.dumps(result, indent=2)
    print(output)
    if args.output:
        args.output.write_text(output + "\n")


if __name__ == "__main__":
    main()
