from jev_guard import scan_source


def codes(src):
    return {f.code for f in scan_source(src, "x.py")}


def test_dangerous_tool_via_variable():
    src = (
        "from langchain.agents import create_agent\n"
        "import langchain_typesafe\n"
        "tools = ['bash']\n"
        "agent = create_agent('m', tools=tools)\n"
    )
    assert "JG002" in codes(src)


def test_untrusted_state_via_variable_chain():
    src = (
        "from langchain_typesafe import TypeSafeClassifier\n"
        "c = TypeSafeClassifier(threshold=0.2)\n"
        "raw = user_message\n"
        "s = raw\n"
        "c.invoke({'state': s, 'questions': {}})\n"
    )
    assert "JG004" in codes(src)


def test_clean_state_not_flagged():
    src = (
        "from langchain_typesafe import TypeSafeClassifier\n"
        "c = TypeSafeClassifier(threshold=0.2)\n"
        "s = 'a static safe string'\n"
        "c.invoke({'state': s, 'questions': {}})\n"
    )
    assert "JG004" not in codes(src)


def test_jg006_high_block_threshold():
    src = (
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'], block_threshold=0.95)\n"
    )
    assert "JG006" in codes(src)
    assert "JG001" not in codes(src)


def test_jg006_low_escalate_confidence():
    src = (
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'], escalate_below=0.1)\n"
    )
    assert "JG006" in codes(src)


def test_jg007_untrusted_in_instructions():
    src = (
        "from langchain_typesafe import Noul\n"
        "q = Noul(instructions=f'Is this dangerous: {user_input}')\n"
    )
    assert "JG007" in codes(src)


def test_inline_suppression():
    src = (
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'])  # jev-guard: ignore JG001\n"
    )
    c = codes(src)
    assert "JG001" not in c
    assert "JG005" in c


def test_inline_suppression_all():
    src = (
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'])  # jev-guard: ignore\n"
    )
    assert codes(src) == set()
