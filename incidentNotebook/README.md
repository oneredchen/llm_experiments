# Incident Notebook: AI-Powered IOC Extraction

A web-based notebook for cybersecurity incident response that uses a local Large Language Model (LLM) to automatically extract and structure Indicators of Compromise (IOCs) from raw incident text.

Now features a dual-architecture design with a **FastAPI backend** for programmatic access and a **Streamlit frontend** for interactive use.

## Table of Contents

- [About The Project](#about-the-project)
- [Features](#features)
- [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [Running the Backend (API)](#running-the-backend-api)
  - [Running the Frontend (UI)](#running-the-frontend-ui)
- [API Documentation](#api-documentation)
- [Testing](#testing)
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
-   **Dual Interface**:
    -   **REST API**: Built with FastAPI for integration with other tools.
    -   **Web UI**: Built with Streamlit for a clean and interactive user experience.
-   **Extensible**: The agentic workflow, built with LangGraph, can be easily modified to support new IOC types or extraction logic.

## Built With

-   [FastAPI](https://fastapi.tiangolo.com/) - Backend Framework
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
    -   `uv` will create a virtual environment and verify all required packages.
    -   ```bash
      uv sync
      ```

## Usage



### Easy Start

You can run both the backend and frontend with a single command:
```bash
./start_app.sh
```

### Running the Application (Backend API)

The backend provides the core logic and database access.

From the project root:
```bash
uv run uvicorn backend.main:app --port 8000 --reload
```
The API will be available at `http://localhost:8000`.



## API Documentation

-   **Swagger UI**: `http://localhost:8000/docs`
-   **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints

-   `GET /cases`: List all incident cases.
-   `POST /cases`: Create a new case.
-   `POST /cases/{case_id}/extract`: Trigger the IOC extraction workflow for a case.
-   `GET /cases/{case_id}/data`: Retrieve extracted IOCs and timeline events.

## Testing

To run the API verification script:
```bash
uv run python tests/test_api_refactor.py
```

To run the end-to-end workflow evaluation:
```bash
uv run python tests/test_workflow.py
```

## Project Structure

```
├── backend/                # FastAPI application
│   ├── main.py             # API entry point
│   ├── models.py           # Pydantic data models
│   └── routers/            # API endpoints
├── frontend/               # Streamlit application
├── tests/                  # Test scripts
├── utils/                  # Shared logic & Database
└── README.md               # Documentation
```

## Development

-   **Package Management**: All Python dependencies are managed with `uv` and defined in `pyproject.toml`.
-   **Agentic Workflow**: The core extraction logic is a stateful graph built with LangGraph. See `utils/ioc_extraction_workflow.py`.
-   **Database**: The schema is defined in `utils/database.py`.