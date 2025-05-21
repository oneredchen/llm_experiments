# Incident Notebook (IOC Extraction App)

This is a Streamlit-based incident response notebook that uses a locally running LLM (via Ollama) to extract host, network, and timeline IOCs from natural language incident descriptions and store them in a SQLite database.

---

## Getting Started

### 1. Install [Ollama](https://ollama.com/)

Follow instructions for your platform to install Ollama and start the local LLM runtime.

### 2. Install [uv](https://github.com/astral-sh/uv)

This app uses `uv`, a Python package manager and runner.

```bash
curl -Ls https://astral.sh/uv/install.sh | sh
```

### 3. Pull a Language Model

You can use any LLM supported by Ollama. For example:

```bash
ollama pull mistral
```

### 4. Set Up the Environment

Synchronize dependencies using `uv`.

```bash
uv sync
```

### 5. Run the App

```bash
uv run streamlit run app.py
```

---

## What It Does

- Accepts free-text incident descriptions.
- Uses an LLM to extract:
  - Host-based IOCs (e.g., file names, registry keys)
  - Network-based IOCs (e.g., IPs, domains)
  - Timeline events (e.g., attacker behavior over time)
- Stores extracted data as SQL `INSERT` statements into a local SQLite database.

---

## Notes

- Make sure Ollama is running and the model you selected is downloaded before launching the app.
- Extracted IOCs are saved to the database immediately after LLM processing.
