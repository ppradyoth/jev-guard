from pathlib import Path

import pytest

from jev_guard import Severity, scan_path, scan_source

FIXTURES = Path(__file__).parent / "fixtures"


def codes(findings):
    return {f.code for f in findings}


def test_vulnerable_agent_flags_all_rules():
    findings = scan_path(FIXTURES / "vulnerable_agent.py")
    assert {"JG001", "JG003", "JG004", "JG005"} <= codes(findings)


def test_unguarded_dangerous_tool_is_critical():
    findings = scan_path(FIXTURES / "unguarded_agent.py")
    assert "JG002" in codes(findings)
    assert any(f.severity is Severity.CRITICAL for f in findings)


def test_safe_agent_has_no_high_findings():
    findings = scan_path(FIXTURES / "safe_agent.py")
    assert {"JG001", "JG002", "JG003", "JG004"}.isdisjoint(codes(findings))


def test_non_jev_file_ignored():
    assert scan_path(FIXTURES / "unrelated.py") == []


def test_threshold_kwarg_suppresses_jg001():
    src = (
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'], block_threshold=0.2)\n"
    )
    assert "JG001" not in codes(scan_source(src, "x.py"))


def test_directory_scan_aggregates():
    findings = scan_path(FIXTURES)
    assert "JG001" in codes(findings)
    assert "JG002" in codes(findings)


def test_syntax_error_does_not_crash():
    assert scan_source("def (:\n", "broken.py") == []


@pytest.mark.parametrize("tool", ["bash", "sql_query", "python_repl", "send_email"])
def test_dangerous_tool_names(tool):
    src = (
        "from langchain.agents import create_agent\n"
        "import langchain_typesafe\n"
        f"agent = create_agent('m', tools=['{tool}'])\n"
    )
    assert "JG002" in codes(scan_source(src, "x.py"))
