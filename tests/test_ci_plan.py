import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOW = yaml.safe_load((Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml").read_text())
STEP = next(s for s in WORKFLOW["jobs"]["plan"]["steps"] if s.get("id") == "plan")


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


def test_windows_scenario_keeps_wsl_lab_alive_for_the_https_burst():
    steps = {step["name"]: step for step in WORKFLOW["jobs"]["scenario-windows"]["steps"] if "name" in step}
    keep_alive = steps["Keep the WSL2 corporate proxy lab host alive"]
    health_check = steps["Confirm the WSL2 corporate proxy lab is healthy before the HTTPS burst"]
    stop_keep_alive = steps["Stop the WSL2 keep-alive process"]

    assert keep_alive["shell"] == "pwsh"
    assert "--exec" in keep_alive["run"]
    assert "'sleep', 'infinity'" in keep_alive["run"]
    assert "-NoNewWindow" not in keep_alive["run"]
    assert "uv run --locked python -c" in health_check["run"]
    assert 'auth="NTLM"' in health_check["run"]
    assert "set_proxy" in health_check["run"]
    assert "curl.exe" not in health_check["run"]
    assert "not a Px failure" in health_check["run"]
    assert "Get-Process" in health_check["run"]
    assert "for ($attempt = 1; $attempt -le 15; $attempt++)" in health_check["run"]
    assert "service docker start" in health_check["run"]
    assert "docker ps -a" in health_check["run"]
    assert "Write-Host" in health_check["run"]
    assert stop_keep_alive["if"] == "always()"
    assert "Stop-Process" in stop_keep_alive["run"]


def test_windows_scenario_bounds_a_frozen_wsl_setup():
    # actions/runner-images#14938: only a job-level timeout ends a frozen runner
    job = WORKFLOW["jobs"]["scenario-windows"]
    names = [step.get("name") for step in job["steps"]]
    setup = job["steps"][names.index("Set up WSL2")]

    assert job["timeout-minutes"] == 15
    assert setup["timeout-minutes"] == 5
    assert names.index("Log the runner image before WSL2 setup") < names.index("Set up WSL2")
