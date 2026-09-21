from langchain.agents import create_agent
from langchain_typesafe import TypeSafeClassifier

classifier = TypeSafeClassifier(threshold=0.9)

agent = create_agent("openai:sol", tools=["bash", "sql_query"])  # JG002
