import ollama
from utils.agents import ioc_extraction_agent_workflow
from utils.database import load_database, create_case, execute_insert_sql
import streamlit as st

# Datasets
databases = load_database()
cases_df = databases["cases"]

# Streamlit Setup
st.set_page_config(page_title="Incident Notebook")

# Sidebar for case selection or creation
st.sidebar.title("Case Management")

case_names = cases_df["case_id"].tolist()
case_labels = [f"{row['case_id']}: {row['name']}" for _, row in cases_df.iterrows()]
case_map = {
    label: row["case_id"]
    for label, row in zip(case_labels, cases_df.to_dict("records"))
}
if case_labels:
    selected_label = st.sidebar.selectbox("Select an Existing Case", case_labels)
    selected_case = case_map[selected_label]
else:
    selected_label = None
    selected_case = None
    st.sidebar.warning("No existing cases found. Please create a new case.")

# Automatic case ID generation for new case creation
new_case_name = st.sidebar.text_input("New Case Name")
create_case_btn = st.sidebar.button("Create New Case")

# Handle new case creation
if create_case_btn:
    if new_case_name:
        new_case_id = create_case(new_case_name)
        st.sidebar.success(f"New case created: {new_case_id} - {new_case_name}")
        selected_case = new_case_id
        st.rerun()
    else:
        st.sidebar.error("Case Name is required.")

# Main Body
st.write("# Incident Notebook")

# LLM Model Selection
list_of_models = ollama.list()["models"]
model_names = [model["model"] for model in list_of_models]
llm_model = st.selectbox(
    "Which LLM Model do you want to use for the Notebook?",
    model_names,
    index=None,
    placeholder="Select LLM Model...",
)

if llm_model and selected_case:
    # User Input
    incident_description = st.text_area("Incident Description")

    # Display DataFrames
    timeline_tab, host_tab, network_tab = st.tabs(["Timeline", "Host", "Network"])
    with timeline_tab:
        st.write("## Timeline")
        timeline_df = databases["timeline"]
        st.dataframe(timeline_df, hide_index=True)
    with host_tab:
        st.write("## Host IOCs")
        host_ioc_df = databases["host_ioc"]
        st.dataframe(host_ioc_df, hide_index=True)
    with network_tab:
        st.write("## Network IOCs")
        network_ioc_df = databases["network_ioc"]
        st.dataframe(network_ioc_df, hide_index=True)

    # Extracting IOCs
    if incident_description:
        with st.spinner("Extracting IOCs..."):
            # Call the IOC extraction agent workflow
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
