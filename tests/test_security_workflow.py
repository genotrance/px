import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).parents[1]
GITHUB = ROOT / ".github"
FILES = sorted([*(GITHUB / "workflows").glob("*.yml"), *(GITHUB / "actions").glob("*/action.yml")])
SECURITY = yaml.safe_load((GITHUB / "workflows" / "security.yml").read_text())
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
