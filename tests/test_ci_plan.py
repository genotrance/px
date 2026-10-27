import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

STEP = next(
    s
    for s in yaml.safe_load((Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml").read_text())["jobs"][
        "plan"
    ]["steps"]
    if s.get("id") == "plan"
)


def plan(tmp_path, event, full_input=""):
    out = tmp_path / "out"
    env = {**os.environ, **{k: v for k, v in STEP["env"].items() if k.isupper() and "$" not in v}}
    env.update(EVENT_NAME=event, FULL_INPUT=full_input, GITHUB_OUTPUT=str(out))
    subprocess.run(["bash", "-c", STEP["run"]], env=env, check=True)  # noqa: S603, S607
    return dict(line.split("=", 1) for line in out.read_text().splitlines())


@pytest.mark.skipif(not (shutil.which("bash") and shutil.which("jq")), reason="needs bash and jq")
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the CI plan runs on Ubuntu; bash/jq/GITHUB_OUTPUT are not portable on Windows",
)
@pytest.mark.parametrize(
    ("event", "full_input", "full"),
    [
        ("push", "", False),
        ("pull_request", "", False),
        ("schedule", "", True),
        ("workflow_dispatch", "true", True),
        ("workflow_dispatch", "false", False),
        ("workflow_call", "true", True),
    ],
)
def test_lanes(tmp_path, event, full_input, full):
    out = plan(tmp_path, event, full_input)
    assert out["full"] == str(full).lower()
    assert (out["marker"] == "") is full
    assert [len(json.loads(out[k])["include"]) for k in ("tests", "musl", "scenario")] == (
        [13, 4, 10] if full else [5, 1, 0]
    )
