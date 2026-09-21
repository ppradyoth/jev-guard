from langchain.agents import create_agent
from langchain_typesafe import Noul, TypeSafeClassifier
from langchain_typesafe.experimental.middleware import AutoModeMiddleware

guardrail = AutoModeMiddleware(tools=["bash"])  # JG001, JG005

classifier = TypeSafeClassifier()  # JG001, JG005


def route(user_message: str):
    resp = classifier.invoke({
        "state": user_message,  # JG004
        "questions": {"danger": Noul(instructions="Is this a dangerous command?")},
    })
    if resp.nouls["danger"].noul > 0.5:  # JG003 (acts on point estimate)
        return "block"
    return "allow"


agent = create_agent("openai:gpt-5.6-luna", middleware=[guardrail])
