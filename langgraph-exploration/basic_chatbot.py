from typing import Annotated
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_ollama import ChatOllama
from typing_extensions import TypedDict

model = "qwen3:14b"
llm = ChatOllama(
    model=model,
    temperature=0.8,
    num_predict=-2,
    num_ctx=8192,
)


class State(TypedDict):
    messages: Annotated[list, add_messages]


def chatbot(state: State):
    messages = llm.invoke(state["messages"])
    return {"messages": [messages]}


graph_builder = StateGraph(State)
graph_builder.add_node("chatbot", chatbot)
graph_builder.add_edge(START, "chatbot")
graph_builder.add_edge("chatbot", END)

graph = graph_builder.compile()

user_input = input("Enter your message: ")
initial_messages = {
    "messages": [
        {
            "role": "system",
            "content": "You are a cybersecurity expert with over 10 years of experience in digital forensics and incident response.",
        },
        {"role": "user", "content": user_input},
    ]
}
state = graph.invoke(initial_messages)

print(state["messages"][-1].content)
