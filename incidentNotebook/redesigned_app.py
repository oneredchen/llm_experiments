import ollama
from utils.agents import ioc_extraction_agent_workflow
from utils.database import load_database, create_case, execute_insert_sql
import streamlit as st
import logging
from logging_config import setup_logging

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# =========================
# Setup & Utilities
# =========================

def setup_page() -> None:
    """Initial Streamlit page setup and session defaults."""
    st.set_page_config(page_title="Incident Notebook", layout="wide")
    if "ioc_extracted" not in st.session_state:
        st.session_state.ioc_extracted = False

def load_datasets() -> dict:
    """Load all datasets from the database layer."""
    logger.info("Loading datasets.")
    return load_database()

# =========================
# Sidebar: Case Management
# =========================

def build_case_sidebar(cases_df):
    """Render the sidebar for case selection / creation and return selected case_id (or None)."""
    st.sidebar.title("Incident Cases")
    st.sidebar.markdown("---")

    # Map cases to labels like "<id>: <name>"
    case_labels = [f"{row['case_id']}: {row['name']}" for _, row in cases_df.iterrows()] if not cases_df.empty else []
    case_map = {label: row["case_id"] for label, row in zip(case_labels, cases_df.to_dict("records"))} if case_labels else {}

    st.sidebar.subheader("Select Existing Case")
    if case_labels:
        selected_label = st.sidebar.selectbox("Select a case", case_labels)
        selected_case = case_map[selected_label]
        logger.info(f"Selected case: {selected_case}")
    else:
        selected_case = None
        st.sidebar.info("No cases found. Please create one below.")

    st.sidebar.markdown("---")
    st.sidebar.subheader("Create New Case")
    new_case_name = st.sidebar.text_input("Enter a new case name")
    if st.sidebar.button("Create Case"):
        if new_case_name:
            new_case_id = create_case(new_case_name)
            logger.info(f"Created new case: {new_case_id} - {new_case_name}")
            st.sidebar.success(f"Case '{new_case_name}' created with ID: {new_case_id}")
            st.rerun()
        else:
            st.sidebar.error("Case name cannot be empty.")
    
    return selected_case

# =========================
# Model Selection
# =========================

def select_llm_model():
    """List available Ollama models and return the selected model name (or None)."""
    try:
        list_of_models = ollama.list()["models"]
        model_names = [model["model"] for model in list_of_models]
        llm_model = st.selectbox(
            "Select an LLM Model for IOC Extraction",
            model_names,
            index=None,
            placeholder="Choose a model...",
        )
        if llm_model:
            logger.info(f"Selected LLM model: {llm_model}")
        return llm_model
    except Exception as e:
        logger.error(f"Could not load Ollama models: {e}")
        st.error(f"Could not load Ollama models: {e}")
        return None

# =========================
# Data Views
# =========================

def render_data_tabs(databases: dict) -> None:
    """Render Timeline / Host / Network tabs from current database snapshots."""
    st.header("Extracted Indicators of Compromise (IOCs)")
    timeline_tab, host_tab, network_tab = st.tabs(["Timeline", "Host IOCs", "Network IOCs"])

    with timeline_tab:
        st.dataframe(databases.get("timeline"), use_container_width=True, hide_index=True)

    with host_tab:
        st.dataframe(databases.get("host_ioc"), use_container_width=True, hide_index=True)

    with network_tab:
        st.dataframe(databases.get("network_ioc"), use_container_width=True, hide_index=True)

# =========================
# IOC Extraction
# =========================

def run_ioc_extraction(llm_model: str, selected_case: str, incident_description: str) -> None:
    """Execute IOC extraction workflow and write results to the DB."""
    logger.info(f"Starting IOC extraction for case: {selected_case}")
    with st.spinner("Analyzing incident description and extracting IOCs..."):
        result = ioc_extraction_agent_workflow(
            llm_model=llm_model,
            case_id=selected_case,
            incident_description=incident_description,
        )

        # Insert extracted data into the database
        for stmt in result.get("host_ioc_sql_stmts", []):
            execute_insert_sql(stmt, "host_ioc")
        for stmt in result.get("network_ioc_sql_stmts", []):
            execute_insert_sql(stmt, "network_ioc")
        for stmt in result.get("timeline_sql_stmts", []):
            execute_insert_sql(stmt, "timeline")

        logger.info(f"IOC extraction complete for case: {selected_case}")
        st.success("IOC extraction complete!")
        st.balloons()

# =========================
# Main App Flow
# =========================

setup_page()

# Load data
databases = load_datasets()
cases_df = databases["cases"]

# Page title
st.title("Incident Response Notebook")
st.markdown("---")

# Sidebar for case management
selected_case = build_case_sidebar(cases_df)

if not selected_case:
    st.warning("Please select or create a case to begin.")
    st.stop()

st.header(f"Working on Case: {selected_case}")

# Main content area
col1, col2 = st.columns(2)

with col1:
    st.subheader("LLM Configuration")
    llm_model = select_llm_model()

with col2:
    st.subheader("Incident Details")
    incident_description = st.text_area("Provide a detailed description of the incident:", height=200)

if st.button("Extract IOCs", type="primary"):
    if not llm_model:
        st.error("Please select an LLM model.")
    elif not incident_description:
        st.error("Please provide an incident description.")
    else:
        st.session_state.ioc_extracted = True
        st.session_state.incident_description = incident_description

if st.session_state.ioc_extracted:
    run_ioc_extraction(llm_model, selected_case, st.session_state.incident_description)
    st.session_state.ioc_extracted = False
    # Rerun to update the data tabs
    st.rerun()

# Display data tabs
render_data_tabs(databases)
