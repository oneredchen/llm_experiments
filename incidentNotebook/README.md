# Incident Notebook: AI-Powered IOC Extraction

A web-based notebook for cybersecurity incident response that uses a local Large Language Model (LLM) to automatically extract and structure Indicators of Compromise (IOCs) from raw incident text.

Features a dual-architecture design with a **FastAPI backend** for programmatic access and a **Next.js frontend** for interactive use. The LLM layer is provider-independent: it talks to **any OpenAI-v1-compatible server** (Ollama, LM Studio, vLLM, llama.cpp, hosted providers) via [Pydantic AI](https://ai.pydantic.dev/).

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

This application helps streamline the initial phases of an incident response by parsing natural language descriptions of security events. It uses an OpenAI-compatible LLM server to identify and categorize key information, which it saves as structured records in a local SQLite database.

This approach allows an analyst to quickly move from unstructured notes to a structured timeline and list of indicators, saving valuable time during an investigation.

## Features

-   **Natural Language Processing**: Paste raw incident notes and let the LLM do the heavy lifting.
-   **Structured IOC Extraction**: Automatically identifies and categorizes three types of data:
    -   **Host-based IOCs**: File names, hashes, registry keys, etc.
    -   **Network-based IOCs**: IP addresses, domains, URLs, etc.
    -   **Timeline Events**: A chronological sequence of actions.
-   **Automated Refinement**: Includes a review-and-refine loop where an evaluator agent assesses the extracted IOCs and provides feedback to the extractor, improving the quality of the final output.
-   **Provider Independent**: Works with any OpenAI-compatible endpoint — switch between Ollama, LM Studio, vLLM, or a hosted provider by editing one environment variable.
-   **Local First**: Runs entirely on your local machine, ensuring data privacy and security.
-   **Dual Interface**:
    -   **REST API**: Built with FastAPI for integration with other tools.
    -   **Modern Web UI**: Built with **Next.js 14, TypeScript, and ShadCN UI** for a premium, responsive experience.
-   **Extensible**: The agentic workflow can be easily modified to support new IOC types or extraction logic.

## Built With

-   [FastAPI](https://fastapi.tiangolo.com/) - Backend Framework
-   [Next.js](https://nextjs.org/) - Frontend Framework (App Router)
-   [ShadCN UI](https://ui.shadcn.com/) - Component Library
-   [Tailwind CSS](https://tailwindcss.com/) - Styling
-   [Pydantic AI](https://ai.pydantic.dev/) - Agent framework with typed structured outputs
-   [LangGraph](https://langchain-ai.github.io/langgraph/) - Workflow orchestration
-   [Ollama](https://ollama.com/) - Local LLM Hosting (or any other OpenAI-compatible server)
-   [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM
-   [uv](https://github.com/astral-sh/uv) - Package Management

## Getting Started

Follow these steps to get the application running on your local machine.

### Prerequisites

1.  **Run an OpenAI-compatible LLM server** — any server that implements `POST /v1/chat/completions` and `GET /v1/models` works:
    -   [Ollama](https://ollama.com/): `ollama pull mistral` (or `gemma3:27b`, `qwen3:30b`, `llama3.1:8b`, …), base URL `http://localhost:11434/v1`.
    -   [LM Studio](https://lmstudio.ai/): start the local server, base URL `http://localhost:1234/v1`.
    -   [vLLM](https://docs.vllm.ai/): `vllm serve <model>`, base URL `http://localhost:8000/v1`.

2.  **Configure the context length server-side** (important): the app sends long incident descriptions and expects ~8k tokens of context. The OpenAI API has no per-request context parameter, so set it where the model is served — for Ollama use `OLLAMA_CONTEXT_LENGTH=8192` (or a Modelfile `num_ctx`); LM Studio/vLLM configure context at model load. If unset, long inputs may be silently truncated.

3.  **Install Node.js**:
    -   Required for the Next.js frontend.

4.  **Install uv**:
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

2.  **Install Backend Dependencies**:
    -   `uv` will create a virtual environment and verify all required packages.
    -   ```bash
      uv sync
      ```

3.  **Configure the LLM connection**:
    -   Copy `.env.template` to `.env` and set:
      | Variable | Default | Description |
      |---|---|---|
      | `LLM_BASE_URL` | `http://localhost:11434/v1` | Base URL of your OpenAI-compatible server (note the `/v1` suffix). |
      | `LLM_API_KEY` | `local` | API key; local servers accept any non-empty value. |
      | `LLM_OUTPUT_MODE` | `native` | Structured-output mode: `native` (OpenAI `json_schema` response format) or `prompted` (fallback for servers/models that reject `json_schema`). |

4.  **Install Frontend Dependencies**:
    ```bash
    cd frontend
    npm install
    cd ..
    ```

## Usage

### Running the Backend (API)

The backend provides the core logic and database access.

From the project root:
```bash
uv run uvicorn backend.main:app --port 8000 --reload
```
The API will be available at `http://localhost:8000`.

### Running the Frontend (UI)

From the `frontend` directory:
```bash
cd frontend
npm run dev
```
Access the application at `http://localhost:3000`.

## API Documentation

-   **Swagger UI**: `http://localhost:8000/docs`
-   **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints

-   `GET /cases`: List all incident cases.
-   `POST /cases`: Create a new case.
-   `POST /cases/{case_id}/extract`: Trigger the IOC extraction workflow for a case.
-   `GET /cases/{case_id}/data`: Retrieve extracted IOCs and timeline events.

## Testing

To run the offline test suite (no LLM server required — the workflow runs on scripted fake models via Pydantic AI's `FunctionModel`):
```bash
uv run pytest
```

To run the API verification script (requires the backend running on port 8000):
```bash
uv run python tests/test_api_refactor.py
```

To run the end-to-end workflow evaluation against your configured LLM server over the 20 sample incidents in `cases/`:
```bash
uv run python tests/test_workflow.py
```

## Project Structure

```
├── backend/                # FastAPI application
│   ├── main.py             # API entry point
│   ├── models.py           # Pydantic API data models
│   ├── routers/            # API endpoints
│   └── utils/              # Shared logic & database
│       ├── agents.py       # Pydantic AI agents (triage / extract / evaluate)
│       ├── llm.py          # LLM server configuration & model factory
│       ├── ioc_extraction_workflow.py  # LangGraph orchestration
│       └── database.py     # SQLAlchemy schema & helpers
├── frontend/               # Next.js + ShadCN application
├── tests/                  # Test scripts
└── README.md               # Documentation
```

## Development

-   **Package Management**: All Python dependencies are managed with `uv` and defined in `pyproject.toml`.
-   **Agentic Workflow**: The core extraction logic is a stateful LangGraph workflow (triage → parallel host/network/timeline extraction with an evaluate-and-refine loop). See `backend/utils/ioc_extraction_workflow.py`; all LLM calls go through the Pydantic AI agents in `backend/utils/agents.py`.
-   **Database**: The schema is defined in `backend/utils/database.py`.
