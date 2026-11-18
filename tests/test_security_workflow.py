import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).parents[1]
GITHUB = ROOT / ".github"
FILES = sorted([*(GITHUB / "workflows").glob("*.yml"), *(GITHUB / "actions").glob("*/action.yml")])
SECURITY = yaml.safe_load((GITHUB / "workflows" / "security.yml").read_text())
CODEQL = yaml.safe_load((GITHUB / "workflows" / "codeql.yml").read_text())
USES = re.compile(r"^\s*(?:- )?uses:\s*(\S+)(?:\s+#\s*(\S+))?", re.MULTILINE)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^v\d+(\.\d+)*$")


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_external_action_is_pinned_by_sha_with_a_version_comment(path):
    for ref, comment in USES.findall(path.read_text()):
        if ref.startswith("./"):
            continue
        assert PINNED.match(ref), f"{path.name}: {ref} is not pinned by full commit SHA"
        assert VERSION_COMMENT.match(comment), f"{path.name}: {ref} lacks a trailing '# vX.Y.Z' comment"


@pytest.mark.parametrize("path", sorted((GITHUB / "workflows").glob("*.yml")), ids=lambda p: p.name)
def test_workflows_declare_least_privilege_permissions_and_no_untrusted_triggers(path):
    workflow = yaml.safe_load(path.read_text())
    triggers = workflow.get("on", workflow.get(True))

    assert "permissions" in workflow, f"{path.name} needs top-level permissions"
    assert "pull_request_target" not in triggers
    assert workflow["permissions"] in ({}, {"contents": "read"}) or path.name == "auto-release.yml"


def test_security_workflow_triggers():
    triggers = SECURITY.get("on", SECURITY.get(True))

    assert set(triggers) == {"pull_request", "push"}
    assert triggers["push"]["branches"] == ["devel", "master"]
    assert SECURITY["permissions"] == {"contents": "read"}
    for job in SECURITY["jobs"].values():
        assert "permissions" not in job


def test_security_workflow_jobs_and_thresholds():
    jobs = SECURITY["jobs"]
    text = (GITHUB / "workflows" / "security.yml").read_text()

    assert set(jobs) == {"zizmor", "actionlint", "dependency-review", "gitleaks", "bandit"}
    assert jobs["dependency-review"]["if"] == "github.event_name == 'pull_request'"
    assert "--min-severity=high" in text
    assert "fail-on-severity: high" in text
    assert "--severity-level high --confidence-level high" in text
    for job in jobs.values():
        checkouts = [s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")]
        assert checkouts
        assert all(s["with"]["persist-credentials"] is False for s in checkouts)


def test_codeql_workflow_uses_advanced_setup_for_fork_pull_requests():
    triggers = CODEQL.get("on", CODEQL.get(True))
    assert set(CODEQL["jobs"]) == {"analyze"}
    job = CODEQL["jobs"]["analyze"]
    steps = job["steps"]
    init = next(step for step in steps if step.get("uses", "").startswith("github/codeql-action/init@"))

    assert set(triggers) == {"pull_request", "push", "schedule"}
    assert triggers["push"]["branches"] == ["devel", "master"]
    assert len(triggers["schedule"]) == 1
    assert "cron" in triggers["schedule"][0]
    assert "pull_request_target" not in triggers
    assert "workflow_run" not in triggers
    assert CODEQL["permissions"] == {"contents": "read"}
    assert CODEQL["concurrency"]["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"
    assert set(job["permissions"]) == {"contents", "security-events"}
    assert job["permissions"] == {"contents": "read", "security-events": "write"}
    assert job["name"] == "Analyze (python)"
    assert job["timeout-minutes"] > 0
    assert init["with"] == {
        "languages": "python",
        "build-mode": "none",
        "queries": "security-extended",
    }
    assert any(step.get("uses", "").startswith("github/codeql-action/analyze@") for step in steps)
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["persist-credentials"] is False


def test_security_tools_are_pinned_to_exact_versions():
    env = SECURITY["env"]

    for name in ("ZIZMOR", "ACTIONLINT", "GITLEAKS", "BANDIT"):
        assert re.fullmatch(r"\d+\.\d+\.\d+", env[f"{name}_VERSION"])
    for name in ("ACTIONLINT", "GITLEAKS"):
        assert re.fullmatch(r"[0-9a-f]{64}", env[f"{name}_SHA256"])


def test_gitleaks_allowlist_is_narrow_and_commented():
    config = (ROOT / ".gitleaks.toml").read_text()

    assert "useDefault = true" in config
    assert 'condition = "AND"' in config
    assert config.count("[[allowlists]]") == config.count("description =")
    assert "paths = [" in config
    assert "regexes = [" in config


def test_build_yml_master_release_is_latest_not_prerelease():
    build = yaml.safe_load((GITHUB / "workflows" / "build.yml").read_text())
    release_job = build["jobs"]["release"]
    create_release_step = next(
        step for step in release_job["steps"]
        if "Create release" in step.get("name", "")
    )

    with_params = create_release_step.get("with", {})
    assert with_params.get("prerelease") is False, "Master releases must have prerelease: false"
    assert with_params.get("make_latest") is True, "Master releases must have make_latest: true"
