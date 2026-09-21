from jev_guard import Config, Severity, scan_source


def test_disable_rule():
    cfg = Config(disabled=frozenset({"JG001"}))
    src = (
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'])\n"
    )
    assert "JG001" not in {f.code for f in scan_source(src, "x.py", cfg)}


def test_severity_override():
    cfg = Config(severity_overrides={"JG004": Severity.CRITICAL})
    src = (
        "from langchain_typesafe import TypeSafeClassifier\n"
        "c = TypeSafeClassifier(threshold=0.2)\n"
        "c.invoke({'state': user_input, 'questions': {}})\n"
    )
    jg004 = [f for f in scan_source(src, "x.py", cfg) if f.code == "JG004"]
    assert jg004 and jg004[0].severity is Severity.CRITICAL


def test_extra_dangerous_tool():
    cfg = Config(extra_dangerous_tools=frozenset({"wire_transfer"}))
    src = (
        "from langchain.agents import create_agent\n"
        "import langchain_typesafe\n"
        "agent = create_agent('m', tools=['wire_transfer'])\n"
    )
    assert "JG002" in {f.code for f in scan_source(src, "x.py", cfg)}


def test_config_load_from_toml(tmp_path):
    (tmp_path / ".jev-guard.toml").write_text(
        "[jev-guard]\ndisable = ['JG005']\n"
    )
    target = tmp_path / "a.py"
    target.write_text(
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'], block_threshold=0.2)\n"
    )
    from jev_guard import scan_path
    assert "JG005" not in {f.code for f in scan_path(target)}
