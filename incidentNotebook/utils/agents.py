from typing import Annotated, List
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field
from typing_extensions import TypedDict


class SQLStatementList(BaseModel):
    sql_statements: List[str] = Field(
        ..., description="A list of valid SQL statements, each as a string."
    )


class IOCExtractionState(TypedDict):
    messages: Annotated[list, add_messages]
    llm: ChatOllama
    host_ioc_sql_stmts: list[str] | None
    network_ioc_sql_stmts: list[str] | None
    timeline_sql_stmts: list[str] | None
    result: dict[str, list[str]] | None


def host_ioc_agent(state: IOCExtractionState):
    """
    Agent for extracting host IOCs as SQL statements.
    The LLM will generate INSERT statements that match the host_ioc table schema.
    """
    last_message = state["messages"][-1]
    llm = state["llm"]
    messages = [
        {
            "role": "system",
            "content": """You are a cybersecurity analyst and SQL expert.
       Your task is to extract only **host-based indicators of compromise (IOCs)** from the incident narrative provided.
        **Do NOT include any network-related IOCs** such as IP addresses, domains, or URLs.

        The target table has the following columns:
        - case_id (str): identifier linking to the parent case (e.g., 'CAS-1234-XY')
        - submitted_by (str)
        - date_added (UTC ISO format preferred)
        - source (str): where the IOC was obtained from (e.g., 'CrowdStrike', 'Sysmon')
        - status (str): such as 'Confirmed', 'Suspected', 'Benign'
        - indicator_id (str): must be unique
        - indicator_type (str): e.g., 'file', 'process', 'registry'
        - indicator (str): e.g., 'mimikatz.exe'
        - full_path (str): e.g., 'C:\\Windows\\Temp\\mimi.exe'
        - sha256, sha1, md5 (str): hashes if available
        - type_purpose (str): e.g., 'Credential Dumping'
        - size_bytes (int): file size in bytes
        - notes (text): any multiline analyst comments

        Respond ONLY with a list of SQL INSERT statements, formatted like:

        INSERT INTO host_ioc (case_id, submitted_by, source, status, indicator_id, indicator_type, indicator, full_path, sha256, sha1, md5, type_purpose, size_bytes, notes)
        VALUES ('CAS-1234-XY', 'analyst1', 'Sysmon', 'Confirmed', 'IOC-001', 'file', 'mimikatz.exe', 'C:\\Windows\\Temp\\mimikatz.exe', '...', '...', '...', 'Credential Dumping', 124000, 'Identified from lateral movement tool use');

        If there are NO host-based IOCs in the narrative, return an **empty list**: `[]`
        Avoid any explanation or comments.
        """,
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(SQLStatementList).invoke(messages)
    print(f"Host IOC SQL Statements: {response.sql_statements}")
    return {"host_ioc_sql_stmts": response.sql_statements}


def network_ioc_agent(state: IOCExtractionState):
    """
    Agent for extracting only network-based IOCs as SQL statements.
    The LLM will ignore non-network IOCs and return an empty list if none are found.
    """
    last_message = state["messages"][-1]
    llm = state["llm"]

    messages = [
        {
            "role": "system",
            "content": """You are a cybersecurity analyst and SQL expert.
                Your task is to extract only network-based indicators of compromise (IOCs) from the provided incident description.
                Exclude any host-based indicators such as file names, registry paths, executables, or processes.

                You must generate valid SQL INSERT statements for the `network_ioc` table only.

                Table columns:
                - case_id (str)
                - submitted_by (str)
                - date_added (datetime in ISO 8601 format)
                - source (str)
                - status (str)
                - indicator_id (str, unique)
                - indicator_type (str): e.g., 'IP address', 'domain', 'URL'
                - indicator (str)
                - initial_lead (str)
                - details_comments (str)
                - earliest_evidence_utc (datetime in ISO 8601 format)
                - attack_alignment (str)
                - notes (text)

                Only respond with a list of SQL INSERT statements. Example:

                INSERT INTO network_ioc (case_id, submitted_by, source, status, indicator_id, indicator_type, indicator, initial_lead, details_comments, earliest_evidence_utc, attack_alignment, notes)
                VALUES ('CAS-1234-XY', 'analyst1', 'Firewall', 'Confirmed', 'IOC-001', 'IP address', '45.77.33.12', 'Detected via beaconing', 'Matches threat intel feed', '2023-10-01T03:12:00Z', 'Command and Control', 'Related to beaconing activity');

                If the incident contains no network-based IOCs, respond with an empty list: []
                Do not include any commentary, explanations, or unrelated IOCs.
                """,
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(SQLStatementList).invoke(messages)
    print(f"Network IOC SQL Statements: {response.sql_statements}")
    return {"network_ioc_sql_stmts": response.sql_statements}


def timeline_ioc_agent(state: IOCExtractionState):
    """
    Agent for extracting timeline-based IOCs as SQL INSERT statements.
    The LLM will generate entries based on the 'timeline' table schema.
    """
    last_message = state["messages"][-1]
    llm = state["llm"]
    messages = [
        {
            "role": "system",
            "content": """You are a cybersecurity analyst and SQL expert.
        Based on an incident narrative, generate SQL INSERT statements that populate the 'timeline' table.

        Use this column structure:
        - case_id (str): identifier linking to the case (e.g., 'CAS-1234-XY')
        - submitted_by (str)
        - date_added (ISO datetime in UTC)
        - status_tag (str): e.g., 'Confirmed', 'Suspicious', 'Benign'
        - system_name (str): e.g., 'HOST-123'
        - timestamp_utc (ISO datetime): when the activity occurred
        - timestamp_type (str): e.g., 'Creation Time', 'Execution Time'
        - activity (str): observed behavior (e.g., 'psexec launched', 'mimikatz used')
        - evidence_source (str): e.g., 'MFT', 'Sysmon', 'CrowdStrike'
        - details_comments (text): context or observations
        - attack_alignment (str): MITRE tactic (e.g., 'Persistence', 'Credential Access')
        - size_bytes (int): size of file or payload if applicable
        - hash (str): file or artifact hash
        - notes (text): analyst comments

        Example format:

        INSERT INTO timeline (case_id, submitted_by, date_added, status_tag, system_name, timestamp_utc, timestamp_type, activity, evidence_source, details_comments, attack_alignment, size_bytes, hash, notes)
        VALUES ('CAS-1234-XY', 'analyst1', '2024-10-01T10:00:00Z', 'Confirmed', 'CORP-WEB-02', '2024-09-30T22:15:30Z', 'Execution Time', 'Mimikatz run from temp directory', 'Sysmon', 'Observed credential dumping behavior', 'Credential Access', 204800, 'abc123...', 'Detected during post-breach investigation');

        Only output a list of valid SQL INSERT statements. No explanations or extra text.
        """,
        },
        {"role": "user", "content": last_message.content},
    ]

    response = llm.with_structured_output(SQLStatementList).invoke(messages)
    return {"timeline_sql_stmts": response.sql_statements}


def ioc_result_aggregator(state: IOCExtractionState):
    """
    Aggregates the results from the three IOC extraction agents.
    """
    host_ioc_sql_stmts = state["host_ioc_sql_stmts"]
    network_ioc_sql_stmts = state["network_ioc_sql_stmts"]
    timeline_sql_stmts = state["timeline_sql_stmts"]

    # Combine all SQL statements into a single result
    combined_result = {
        "host_ioc_sql_stmts": host_ioc_sql_stmts,
        "network_ioc_sql_stmts": network_ioc_sql_stmts,
        "timeline_sql_stmts": timeline_sql_stmts,
    }
    return {"result": combined_result}


def ioc_extraction_graph_builder(state):
    # Adding the Graph Nodes
    graph_builder = StateGraph(state)
    graph_builder.add_node("host_ioc_extractor", host_ioc_agent)
    graph_builder.add_node("network_ioc_extractor", network_ioc_agent)
    graph_builder.add_node("timeline_ioc_extractor", timeline_ioc_agent)
    graph_builder.add_node("ioc_result_aggregator", ioc_result_aggregator)

    # Setting up the workflow
    graph_builder.add_edge(START, "host_ioc_extractor")
    graph_builder.add_edge(START, "network_ioc_extractor")
    graph_builder.add_edge(START, "timeline_ioc_extractor")
    graph_builder.add_edge("host_ioc_extractor", "ioc_result_aggregator")
    graph_builder.add_edge("network_ioc_extractor", "ioc_result_aggregator")
    graph_builder.add_edge("timeline_ioc_extractor", "ioc_result_aggregator")
    graph_builder.add_edge("ioc_result_aggregator", END)

    # Compile the graph
    graph = graph_builder.compile()

    return graph


def ioc_extraction_agent_workflow(
    llm_model: str, case_id: str, incident_description: str
):
    """
    Workflow for IOC extraction agent.
    """
    # Initialize the LLM
    llm = ChatOllama(
        model=llm_model,
        temperature=0.8,
        num_predict=-2,
        num_ctx=8192,
    )
    initial_message = {
        "role": "user",
        "content": f"""
        You are a cybersecurity analyst. Given the following incident description, extract host and network IOCs and generate SQL INSERT statements for the database.

        Case ID: {case_id}
        Incident Description: {incident_description}
        """,
    }
    graph = ioc_extraction_graph_builder(IOCExtractionState)
    state = {
        "messages": [initial_message],
        "llm": llm,
        "host_ioc_sql_stmts": None,
        "network_ioc_sql_stmts": None,
        "timeline_sql_stmts": None,
    }
    state = graph.invoke(state)
    result = state["result"]
    return result
