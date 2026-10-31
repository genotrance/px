from pathlib import Path

SCRIPT = Path(__file__).parent / "scenarios" / "env" / "scenario-env.sh"


def test_scenario_env_installs_mcurl_candidate_wheel():
    text = SCRIPT.read_text()
    for needle in (
        "MCURL_WHEELS",
        'cp "$wheels/." "client:$wheels/"',
        '-e "MCURL_WHEELS=$wheels"',
        "--reinstall-package pymcurl",
        "--no-index",
        '"pymcurl==$version"',
    ):
        assert needle in text, needle
    assert text.index("uv sync --locked") < text.index("--reinstall-package pymcurl")
    assert "MCURL_SRC" not in text and "PX_REQUIRE_MCURL_FIX" not in text
