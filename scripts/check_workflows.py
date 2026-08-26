#!/usr/bin/env python3
"""Refuse a workflow file GitHub would reject.

`release.yml` sat broken for a day. Pinning the actions to commit SHAs left one step
with two `with:` blocks:

    - uses: dtolnay/rust-toolchain@4360b525... # stable
      with:
        toolchain: stable
      with:
        targets: ${{ matrix.target }}

GitHub rejects the whole file for that, so every push recorded a 0-second failed run
with no jobs in it -- and the next `v*` tag would have produced no release at all.
Nothing caught it: the failing runs were attributed to a workflow that is not supposed
to run on a push, so they looked like noise, and `yaml.safe_load` accepts a duplicate
key happily (last one wins). A YAML parser that shrugs is exactly the wrong oracle for
"would GitHub accept this".

So this one does not shrug. It rejects a duplicate key at any depth, which is the defect
that actually happened, and then checks the few structural rules whose violation also
costs a whole file: a job with no `runs-on` or no `steps`, and a step that has neither
`run` nor `uses` or has both.

    python scripts/check_workflows.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


class NoDuplicates(yaml.SafeLoader):
    """A SafeLoader that treats a repeated mapping key as an error, not an overwrite."""


def _no_duplicate_keys(loader: yaml.Loader, node: yaml.Node, deep: bool = False):
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            mark = key_node.start_mark
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"duplicate key {key!r} -- GitHub rejects the file",
                mark,
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


NoDuplicates.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys
)


def check(path: Path) -> list[str]:
    try:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=NoDuplicates)
    except yaml.YAMLError as e:
        return [f"{path.name}: {str(e).strip()}"]

    bad: list[str] = []
    if not isinstance(doc, dict):
        return [f"{path.name}: not a mapping"]

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return [f"{path.name}: no jobs"]

    for name, job in jobs.items():
        if not isinstance(job, dict):
            bad.append(f"{path.name}: job {name}: not a mapping")
            continue
        if "uses" in job:
            continue  # a reusable-workflow call has neither runs-on nor steps
        if "runs-on" not in job:
            bad.append(f"{path.name}: job {name}: no runs-on")
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            bad.append(f"{path.name}: job {name}: no steps")
            continue
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                bad.append(f"{path.name}: job {name} step {i}: not a mapping")
                continue
            has = ("run" in step, "uses" in step)
            if has == (False, False):
                bad.append(f"{path.name}: job {name} step {i}: neither run nor uses")
            elif has == (True, True):
                bad.append(f"{path.name}: job {name} step {i}: both run and uses")
    return bad


def main() -> int:
    if not WORKFLOWS.is_dir():
        print(f"error: no {WORKFLOWS}", file=sys.stderr)
        return 2
    files = sorted(
        p for p in WORKFLOWS.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file()
    )
    if not files:
        # A guard that checked nothing must never look like a guard that found nothing.
        print("error: no workflow files found; refusing to report a pass", file=sys.stderr)
        return 2

    findings: list[str] = []
    for f in files:
        findings += check(f)
    for line in findings:
        print(line)
    if findings:
        print()
        print(f"{len(findings)} problem(s); GitHub would reject at least one of these files.")
        return 1
    print(f"workflows OK ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
