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
    -   **Modern Web UI**: Built with **Next.js 14, TypeScript, and ShadCN UI** for a premium, responsive experience.
-   **Extensible**: The agentic workflow can be easily modified to support new IOC types or extraction logic.

## Built With

-   [FastAPI](https://fastapi.tiangolo.com/) - Backend Framework
-   [Next.js](https://nextjs.org/) - Frontend Framework (App Router)
-   [ShadCN UI](https://ui.shadcn.com/) - Component Library
-   [Tailwind CSS](https://tailwindcss.com/) - Styling
-   [Ollama Python Client](https://github.com/ollama/ollama-python) - LLM Interaction
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
    -   For best results with the new frontend, ensure you have `gemini-2.0-flash-exp` or similar if using the default selection, or select `mistral` in the UI.

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

3.  **Install Frontend Dependencies**:
    ```bash
    cd frontend-next
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

From the `frontend-next` directory:
```bash
cd frontend-next
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
├── frontend-next/          # Next.js + ShadCN application

├── tests/                  # Test scripts
├── utils/                  # Shared logic & Database
└── README.md               # Documentation
```

## Development

-   **Package Management**: All Python dependencies are managed with `uv` and defined in `pyproject.toml`.
-   **Agentic Workflow**: The core extraction logic is a stateful workflow implemented in Python. See `utils/ioc_extraction_workflow.py`.
-   **Database**: The schema is defined in `utils/database.py`.