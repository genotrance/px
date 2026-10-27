#!/usr/bin/env python3
"""Emit the CI job matrices for ci.yml's fast and full modes."""

import argparse
import json
import os
import sys

FAST_MARKER = "not integration and not benchmark and not largedata and not slow"

LINUX = "ubuntu-latest"
LINUX_ARM = "ubuntu-24.04-arm"
MACOS = "macos-latest"
WINDOWS = "windows-latest"

# Every entry is part of the full matrix; fast=True also puts it in the fast one.
TESTS: list[dict] = [
    {"os": LINUX, "python-version": "3.10", "fast": True},
    {"os": LINUX, "python-version": "3.11"},
    {"os": LINUX, "python-version": "3.12"},
    {"os": LINUX, "python-version": "3.13"},
    {"os": LINUX, "python-version": "3.14", "fast": True},
    {"os": LINUX, "python-version": "3.14", "event-loop": "asyncio", "fast": True},
    {"os": LINUX_ARM, "python-version": "3.10"},
    {"os": LINUX_ARM, "python-version": "3.14"},
    {"os": MACOS, "python-version": "3.10"},
    {"os": MACOS, "python-version": "3.14"},
    {"os": WINDOWS, "python-version": "3.10"},
    {"os": WINDOWS, "python-version": "3.14", "fast": True},
    {"os": WINDOWS, "python-version": "3.14", "event-loop": "asyncio", "fast": True},
]

X86_IMAGE = "quay.io/pypa/musllinux_1_2_x86_64"
ARM_IMAGE = "quay.io/pypa/musllinux_1_2_aarch64"
MUSL: list[dict] = [
    {"os": LINUX, "image": X86_IMAGE, "name": "musl-x86_64", "pyver": "310"},
    {"os": LINUX, "image": X86_IMAGE, "name": "musl-x86_64", "pyver": "314", "fast": True},
    {"os": LINUX_ARM, "image": ARM_IMAGE, "name": "musl-aarch64", "pyver": "310"},
    {"os": LINUX_ARM, "image": ARM_IMAGE, "name": "musl-aarch64", "pyver": "314"},
]

# Real Px scenario suite (tests/scenarios) against the Docker corporate-proxy
# lab: full mode only, the whole supported CPython range on both event loops.
SCENARIO: list[dict] = [
    {"os": LINUX, "python-version": pyver, "event-loop": loop}
    for pyver in ("3.10", "3.11", "3.12", "3.13", "3.14")
    for loop in ("auto", "asyncio")
]


def resolve_full(event: str, full_input: str) -> bool:
    """Decide the mode: an explicit `full` input wins, schedules are full, push/PR are fast."""
    if full_input.lower() in ("true", "false"):
        return full_input.lower() == "true"
    return event == "schedule"


def select(entries: list[dict], full: bool) -> dict:
    return {"include": [{k: v for k, v in e.items() if k != "fast"} for e in entries if full or e.get("fast")]}


def plan(event: str, full_input: str) -> dict[str, str]:
    full = resolve_full(event, full_input)
    return {
        "full": str(full).lower(),
        "marker": "" if full else FAST_MARKER,
        "tests": json.dumps(select(TESTS, full)),
        "musl": json.dumps(select(MUSL, full)),
        "scenario": json.dumps(select(SCENARIO, full)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", default=os.environ.get("EVENT_NAME", ""))
    parser.add_argument("--full", default=os.environ.get("FULL_INPUT", ""))
    args = parser.parse_args()
    outputs = plan(args.event, args.full)
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a") as f:
            f.writelines(f"{k}={v}\n" for k, v in outputs.items())
    json.dump(outputs, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
