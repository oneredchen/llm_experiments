# Incident Notebook: AI-Powered IOC Extraction

A web-based notebook for cybersecurity incident response that uses a local Large Language Model (LLM) to automatically extract and structure Indicators of Compromise (IOCs) from raw incident text.

## Table of Contents

- [About The Project](#about-the-project)
- [Features](#features)
- [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Development](#development)

## About The Project

This application helps streamline the initial phases of an incident response by parsing natural language descriptions of security events. It leverages a locally-running LLM (via Ollama) to identify and categorize key information, which it then saves as structured SQL `INSERT` statements into a local SQLite database.

This approach allows an analyst to quickly move from unstructured notes to a structured timeline and list of indicators, saving valuable time during an investigation.

## Features

-   **Natural Language Processing**: Paste raw incident notes and let the LLM do the heavy lifting.
-   **Structured IOC Extraction**: Automatically identifies and categorizes three types of data:
    -   **Host-based IOCs**: File names, hashes, registry keys, etc.
    -   **Network-based IOCs**: IP addresses, domains, URLs, etc.
    -   **Timeline Events**: A chronological sequence of actions.
-   **Automated Refinement**: Includes a review-and-refine loop where an evaluator agent assesses the extracted IOCs and provides feedback to the extractor, improving the quality of the final output.
-   **Local First**: Runs entirely on your local machine, ensuring data privacy and security.
-   **Simple UI**: Built with Streamlit for a clean and interactive user experience.
-   **Extensible**: The agentic workflow, built with LangGraph, can be easily modified to support new IOC types or extraction logic.

## Built With

-   [Streamlit](https://streamlit.io/) - Frontend Framework
-   [Langchain](https://www.langchain.com/) & [LangGraph](https://langchain-ai.github.io/langgraph/) - LLM Orchestration
-   [Ollama](https://ollama.com/) - Local LLM Hosting
-   [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
-   [uv](https://github.com/astral-sh/uv) - Package Management

## Getting Started

Follow these steps to get the application running on your local machine.

### Prerequisites

1.  **Install and Run Ollama**:
    -   Download and install [Ollama](https://ollama.com/) for your operating system.
    -   Ensure the Ollama application is running.

2.  **Pull an LLM Model**:
    -   This application is tested with `mistral`, but other models may work.
    -   ```bash
      ollama pull mistral
      ```

3.  **Install uv**:
    -   The project uses `uv` for fast dependency management.
    -   ```bash
      curl -Ls https://astral.sh/uv/install.sh | sh
      ```

### Installation

1.  **Clone the repository** (if you haven't already):
    ```bash
    git clone <repository-url>
    cd incident-notebook
    ```

2.  **Install Dependencies**:
    -   `uv` will create a virtual environment and install all required packages from `pyproject.toml`.
    -   ```bash
      uv sync
      ```

## Usage

1.  **Run the Application**:
    -   Execute the following command from the project root directory:
    -   ```bash
      uv run streamlit run app.py
      ```

2.  **Using the App**:
    -   Open your web browser to the URL provided by Streamlit (usually `http://localhost:8501`).
    -   Select an LLM model from the sidebar.
    -   Choose a sample case or paste your own incident description into the text area.
    -   Click "Extract IOCs" to begin the analysis.
    -   The extracted IOCs will be displayed in the main panel and saved to the `incident_notebook.db` SQLite file in the `db/` directory.

## Project Structure

```
├── app.py                  # Main Streamlit application entry point
├── utils/
│   ├── ioc_extraction_workflow.py # Core IOC extraction logic and LangGraph agent definitions
│   └── database.py         # SQLAlchemy schema and database helper functions
├── cases/                  # Sample incident description text files
├── db/
│   └── incident_notebook.db # SQLite database file (created on first run)
├── pyproject.toml          # Project metadata and dependencies for uv
└── README.md               # This file
```

## Development

-   **Package Management**: All Python dependencies are managed with `uv` and defined in `pyproject.toml`.
-   **Agentic Workflow**: The core extraction logic is a stateful graph built with LangGraph. The workflow begins with a parallel triage process to check for host and network IOCs. Each extractor then enters a refinement loop where an evaluator agent reviews the output and provides feedback, allowing the extractor to improve the results over a maximum of three iterations. See `utils/ioc_extraction_workflow.py` to understand the multi-agent system.
-   **Database**: The schema is defined in `utils/database.py`. Any changes to the database models should be made there.
-   **Logging**: The application uses the standard Python `logging` module. Logs are output to the console and to `incident_notebook.log`.