import json

from jev_guard import scan_path
from jev_guard.cli import main
from jev_guard.formats import to_sarif

FIX = "tests/fixtures/vulnerable_agent.py"


def test_sarif_is_valid_shape():
    findings = scan_path(FIX)
    doc = json.loads(to_sarif(findings, "0.3.0"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "jev-guard"
    assert run["tool"]["driver"]["rules"]
    assert len(run["results"]) == len(findings)
    r = run["results"][0]
    assert r["ruleId"].startswith("JG")
    assert r["level"] in {"error", "warning", "note"}
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_cli_sarif_to_file(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    code = main(["scan", FIX, "--format", "sarif", "-o", str(out), "--fail-on", "CRITICAL"])
    assert code == 0
    doc = json.loads(out.read_text())
    assert doc["runs"][0]["tool"]["driver"]["name"] == "jev-guard"


def test_cli_fail_on_high_exits_nonzero(capsys):
    assert main(["scan", FIX, "--no-color"]) == 1
    assert main(["scan", "tests/fixtures/safe_agent.py", "--no-color"]) == 0
