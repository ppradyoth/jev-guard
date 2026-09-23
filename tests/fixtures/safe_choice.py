from langchain_typesafe import Choice, TypeSafeClassifier

classifier = TypeSafeClassifier(min_confidence=0.9)

q = Choice(
    instructions="Which action should the agent take?",
    options=["update_record", "create_record", "none_escalate_to_human"],
)


def route(state):
    d = classifier.invoke({"state": state, "questions": {"q": q}})
    if d.confidence < 0.9:
        return "escalate"
    return "act"
