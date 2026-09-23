"""A code-review agent that uses Jev to gate a shell tool and triage PRs.
Representative of the integration pattern from LangChain's AutoModeMiddleware blog."""
from langchain.agents import create_agent
from langchain_typesafe import Choice, Noul, TypeSafeClassifier
from langchain_typesafe.experimental.middleware import AutoModeMiddleware

# gate the agent's shell access with Jev — but on the model's default decision
guardrail = AutoModeMiddleware(tools=["bash"])

classifier = TypeSafeClassifier()


def triage_pull_request(pr_diff: str, pr_body: str):
    # untrusted PR content flows straight into the guardrail's state
    resp = classifier.invoke({
        "state": pr_diff + "\n" + pr_body,
        "questions": {
            "risk": Choice(
                instructions="How should we handle this PR?",
                options=["auto_merge", "run_tests", "deploy"],
            ),
            "touches_auth": Noul(instructions="Does this change touch authentication?"),
        },
    })
    # act on the point decision; confidence never checked, no escalation branch
    if resp.nouls["touches_auth"].noul < 0.5:
        return "auto_merge"
    return "run_tests"


agent = create_agent("openai:gpt-5.6-luna", middleware=[guardrail])
