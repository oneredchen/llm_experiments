# GEMINI.md

## Project Overview

This project, "Incident Notebook," is a web-based application built with Streamlit designed for cybersecurity incident response. Its primary function is to parse natural language descriptions of security incidents, extract key Indicators of Compromise (IOCs), and store them in a structured format.

The application leverages a locally running Large Language Model (LLM) through Ollama to perform the IOC extraction. The extracted data is categorized into three types:
-   **Host-based IOCs:** (e.g., file names, registry keys)
-   **Network-based IOCs:** (e.g., IP addresses, domains)
-   **Timeline Events:** (e.g., a chronological sequence of actions)

This extracted information is then saved as SQL `INSERT` statements into a local SQLite database (`incident_notebook.db`).

**Key Technologies:**
-   **Frontend:** Streamlit
-   **Backend/Orchestration:** Langchain, LangGraph
-   **LLM Integration:** Ollama
-   **Database:** SQLite with SQLAlchemy for ORM
-   **Package Management:** uv

**Architecture:**
-   `app.py`: The main entry point for the Streamlit application. It handles the UI, state management, and orchestrates the calls to the backend.
-   `utils/agents.py`: Contains the core logic for the IOC extraction workflow. It defines a multi-agent system using LangGraph where different agents are responsible for identifying and formatting different types of IOCs.
-   `utils/database.py`: Defines the SQLite database schema using SQLAlchemy ORM and provides helper functions for database initialization, data loading, and executing SQL statements.
-   `cases/`: This directory contains sample text files, likely used as templates or examples of incident descriptions.

## Building and Running

The project uses `uv` for dependency management and execution.

1.  **Prerequisites:**
    *   Install and run [Ollama](https://ollama.com/).
    *   Pull an LLM model (e.g., `ollama pull mistral`).
    *   Install [uv](https://github.com/astral-sh/uv).

2.  **Install Dependencies:**
    Synchronize the project environment using `uv`.
    ```bash
    uv sync
    ```

3.  **Run the Application:**
    Execute the following command from the project root directory:
    ```bash
    uv run streamlit run app.py
    ```

## Development Conventions

-   **Package Management:** All Python dependencies are listed in `pyproject.toml` and managed with `uv`.
-   **Agentic Workflow:** The core logic is built as a stateful graph using LangGraph. The workflow starts with a triage agent that determines which specialized extraction agents (host, network, timeline) to run.
-   **Database:** The database schema is defined in `utils/database.py` using SQLAlchemy. All database operations should go through the functions provided in this file. The application is designed to create the database file (`db/incident_notebook.db`) if it doesn't exist.
-   **Configuration:** The LLM model to be used is selectable from the Streamlit UI.
-   **Logging:** The application uses the standard Python `logging` module.
-   **Error Handling:** The traceback provided indicates a potential issue with the LangGraph implementation where multiple agents might be trying to update the same key in the state, which is not allowed by default. This suggests that development on the agent interaction logic is ongoing.
