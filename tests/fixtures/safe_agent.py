from langchain_typesafe import Noul, TypeSafeClassifier
from langchain_typesafe.experimental.middleware import AutoModeMiddleware

guardrail = AutoModeMiddleware(tools=["bash"], block_threshold=0.2)

classifier = TypeSafeClassifier(min_confidence=0.85)


def route(sanitized_state: str):
    resp = classifier.invoke({
        "state": sanitized_state,
        "questions": {"danger": Noul(instructions="Is this dangerous?")},
    })
    decision = resp.nouls["danger"]
    if decision.confidence < 0.85:
        return "escalate"
    return "block" if decision.noul > 0.2 else "allow"
