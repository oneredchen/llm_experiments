import streamlit as st
import ollama
import logging
from logging_config import setup_logging
from utils.agents import ioc_extraction_agent_workflow
from utils.database import load_database, create_case, execute_insert_sql

def setup_page():
    st.set_page_config(page_title="Incident Notebook", layout="wide")
    if "ioc_extracted" not in st.session_state:
        st.session_state.ioc_extracted = False

def load_data():
    return load_database()

def render_sidebar(cases_df):
    with st.sidebar:
        st.title("Incident Notebook")
        st.write("---")
        st.header("Case Management")

        case_labels = [f"{row['case_id']}: {row['name']}" for _, row in cases_df.iterrows()]
        case_map = {label: row["case_id"] for label, row in zip(case_labels, cases_df.to_dict("records"))}

        if not case_labels:
            st.warning("No existing cases found. Please create a new case.")
            selected_case = None
        else:
            selected_label = st.selectbox("Select an Existing Case", case_labels)
            selected_case = case_map[selected_label]

        with st.expander("Create New Case"):
            new_case_name = st.text_input("New Case Name")
            if st.button("Create"):
                if new_case_name:
                    new_case_id = create_case(new_case_name)
                    st.success(f"New case created: {new_case_id} - {new_case_name}")
                    st.rerun()
                else:
                    st.error("Case Name is required.")
        
        st.write("---")
            
    return selected_case

def render_main_content(databases, selected_case):
    st.title("Incident Analysis Dashboard")
    st.markdown("This dashboard provides a comprehensive overview of the incident.")

    st.write("---")

    col1, col2 = st.columns(2)
    with col1:
        list_of_models = ollama.list()["models"]
        model_names = [model["model"] for model in list_of_models]
        llm_model = st.selectbox(
            "Select LLM Model",
            model_names,
            index=None,
            placeholder="Select LLM Model...",
        )
    
    with col2:
        st.metric(label="Selected Case", value=selected_case)

    if llm_model and selected_case:
        with st.form(key="ioc_form"):
            incident_description = st.text_area("Provide a detailed description of the incident.", height=200)
            submit_button = st.form_submit_button(label="Extract IOCs")

            if submit_button:
                st.session_state.ioc_extracted = True
                st.session_state.incident_description = incident_description

        if st.session_state.ioc_extracted:
            run_ioc_extraction(llm_model, selected_case, st.session_state.incident_description)
            st.session_state.ioc_extracted = False

        st.subheader("Indicators of Compromise")
        render_data_tabs(databases)

def render_data_tabs(databases):
    timeline_df = databases.get("timeline")
    host_ioc_df = databases.get("host_ioc")
    network_ioc_df = databases.get("network_ioc")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="Timeline Events", value=len(timeline_df))
    with col2:
        st.metric(label="Host IOCs", value=len(host_ioc_df))
    with col3:
        st.metric(label="Network IOCs", value=len(network_ioc_df))

    tab1, tab2, tab3 = st.tabs(["Timeline", "Host IOCs", "Network IOCs"])
    with tab1:
        st.dataframe(timeline_df, use_container_width=True)
    with tab2:
        st.dataframe(host_ioc_df, use_container_width=True)
    with tab3:
        st.dataframe(network_ioc_df, use_container_width=True)

def run_ioc_extraction(llm_model, selected_case, incident_description):
    progress_bar = st.progress(0, text="Initializing IOC extraction...")
    
    with st.spinner("Extracting IOCs..."):
        result = ioc_extraction_agent_workflow(
            llm_model=llm_model,
            case_id=selected_case,
            incident_description=incident_description,
        )
        
        total_stmts = len(result.get("host_ioc_sql_stmts", [])) + \
                      len(result.get("network_ioc_sql_stmts", [])) + \
                      len(result.get("timeline_sql_stmts", []))
        
        completed_stmts = 0

        def update_progress(text):
            nonlocal completed_stmts
            completed_stmts += 1
            progress = completed_stmts / total_stmts
            progress_bar.progress(progress, text=text)

        for stmt in result.get("host_ioc_sql_stmts", []):
            execute_insert_sql(stmt, "host_ioc")
            update_progress(f"Inserting host IOC... {completed_stmts}/{total_stmts}")

        for stmt in result.get("network_ioc_sql_stmts", []):
            execute_insert_sql(stmt, "network_ioc")
            update_progress(f"Inserting network IOC... {completed_stmts}/{total_stmts}")

        for stmt in result.get("timeline_sql_stmts", []):
            execute_insert_sql(stmt, "timeline")
            update_progress(f"Inserting timeline event... {completed_stmts}/{total_stmts}")

    progress_bar.progress(1.0, text="IOC extraction complete!")
    st.success("IOCs extracted and saved successfully!")

def main():
    setup_logging()
    logging.info("Application started.")
    setup_page()
    databases = load_data()
    cases_df = databases["cases"]
    selected_case = render_sidebar(cases_df)
    
    if selected_case:
        render_main_content(databases, selected_case)
    else:
        st.info("Please select or create a case to begin.")

if __name__ == "__main__":
    main()
