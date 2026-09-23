from langchain_typesafe import Choice, TypeSafeClassifier

classifier = TypeSafeClassifier(min_confidence=0.9)

q = Choice(
    instructions="Which action should the agent take?",
    options=["delete_record", "update_record", "create_record"],
)
