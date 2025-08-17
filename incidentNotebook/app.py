import ollama
from utils.agents import ioc_extraction_agent_workflow
from utils.database import load_database, create_case, execute_insert_sql
import streamlit as st

# =========================
# Setup & Utilities
# =========================

def setup_page() -> None:
    """Initial Streamlit page setup and session defaults."""
    st.set_page_config(page_title="Incident Notebook")
    if "ioc_extracted" not in st.session_state:
        st.session_state.ioc_extracted = False


def load_datasets() -> dict:
    """Load all datasets from the database layer."""
    return load_database()


# =========================
# Sidebar: Case Management
# =========================

def build_case_sidebar(cases_df):
    """Render the sidebar for case selection / creation and return selected case_id (or None)."""
    st.sidebar.title("Case Management")

    # Map cases to labels like "<id>: <name>"
    case_labels = [f"{row['case_id']}: {row['name']}" for _, row in cases_df.iterrows()] if not cases_df.empty else []
    case_map = {label: row["case_id"] for label, row in zip(case_labels, cases_df.to_dict("records"))} if case_labels else {}

    if case_labels:
        selected_label = st.sidebar.selectbox("Select an Existing Case", case_labels)
        selected_case = case_map[selected_label]
    else:
        selected_label = None
        selected_case = None
        st.sidebar.warning("No existing cases found. Please create a new case.")

    # New case creation controls
    new_case_name = st.sidebar.text_input("New Case Name")
    create_case_btn = st.sidebar.button("Create New Case")

    if create_case_btn:
        if new_case_name:
            new_case_id = create_case(new_case_name)
            st.sidebar.success(f"New case created: {new_case_id} - {new_case_name}")
            selected_case = new_case_id
            st.rerun()
        else:
            st.sidebar.error("Case Name is required.")

    return selected_case


# =========================
# Model Selection
# =========================

def select_llm_model():
    """List available Ollama models and return the selected model name (or None)."""
    list_of_models = ollama.list()["models"]
    model_names = [model["model"] for model in list_of_models]
    llm_model = st.selectbox(
        "Which LLM Model do you want to use for the Notebook?",
        model_names,
        index=None,
        placeholder="Select LLM Model...",
    )
    return llm_model


# =========================
# Data Views
# =========================

def render_data_tabs(databases: dict) -> None:
    """Render Timeline / Host / Network tabs from current database snapshots."""
    timeline_tab, host_tab, network_tab = st.tabs(["Timeline", "Host", "Network"])

    with timeline_tab:
        st.write("## Timeline")
        timeline_df = databases.get("timeline")
        st.dataframe(timeline_df, hide_index=True)

    with host_tab:
        st.write("## Host IOCs")
        host_ioc_df = databases.get("host_ioc")
        st.dataframe(host_ioc_df, hide_index=True)

    with network_tab:
        st.write("## Network IOCs")
        network_ioc_df = databases.get("network_ioc")
        st.dataframe(network_ioc_df, hide_index=True)


# =========================
# IOC Extraction
# =========================

def run_ioc_extraction(llm_model: str, selected_case: str, incident_description: str) -> None:
    """Execute IOC extraction workflow and write results to the DB."""
    with st.spinner("Extracting IOCs..."):
        result = ioc_extraction_agent_workflow(
            llm_model=llm_model,
            case_id=selected_case,
            incident_description=incident_description,
        )

        for stmt in result.get("host_ioc_sql_stmts", []):
            execute_insert_sql(stmt, "host_ioc")

        for stmt in result.get("network_ioc_sql_stmts", []):
            execute_insert_sql(stmt, "network_ioc")

        for stmt in result.get("timeline_sql_stmts", []):
            execute_insert_sql(stmt, "timeline")

        st.success("IOCs extracted successfully!")


# =========================
# Main App Flow
# =========================

setup_page()

# Load datasets
databases = load_datasets()
cases_df = databases["cases"]

# Header
st.write("# Incident Notebook")

# Sidebar case selection
selected_case = build_case_sidebar(cases_df)

# Model selection
llm_model = select_llm_model()

# Main body only active when model & case are selected
if llm_model and selected_case:
    incident_description = st.text_area("Incident Description")
    extract_iocs_btn = st.button("Extract IOCs")

    # Data tabs
    render_data_tabs(databases)

    # Extraction flow
    if extract_iocs_btn:
        st.session_state.ioc_extracted = True
        st.session_state.incident_description = incident_description

    if st.session_state.ioc_extracted and selected_case and llm_model:
        run_ioc_extraction(llm_model, selected_case, incident_description)
        st.session_state.ioc_extracted = False

