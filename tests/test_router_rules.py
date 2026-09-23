from jev_guard import scan_path, scan_source

FX = "tests/fixtures"


def codes(src):
    return {f.code for f in scan_source(src, "x.py")}


def test_jg008_forced_choice_no_abstain():
    assert "JG008" in {f.code for f in scan_path(f"{FX}/forced_choice.py")}


def test_jg008_not_flagged_with_abstain_option():
    assert "JG008" not in {f.code for f in scan_path(f"{FX}/safe_choice.py")}


def test_jg009_terminal_judge_no_escalation():
    # vulnerable_agent gates bash and only returns block/allow
    assert "JG009" in {f.code for f in scan_path(f"{FX}/vulnerable_agent.py")}


def test_jg009_not_flagged_when_escalation_present():
    # safe_agent returns "escalate" on low confidence
    assert "JG009" not in {f.code for f in scan_path(f"{FX}/safe_agent.py")}


def test_jg008_dict_form_choice():
    src = (
        "import langchain_typesafe\n"
        "q = {'type': 'choice', 'instructions': 'pick', "
        "'criteria': {'approve': None, 'deny': None}}\n"
    )
    assert "JG008" in codes(src)


def test_jg009_inline_abstain_option_counts_as_escalation():
    src = (
        "from langchain_typesafe.experimental.middleware import AutoModeMiddleware\n"
        "g = AutoModeMiddleware(tools=['bash'], block_threshold=0.2, escalate_below=0.8)\n"
        "def h():\n    return review_queue()\n"
    )
    assert "JG009" not in codes(src)
