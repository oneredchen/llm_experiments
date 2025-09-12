import streamlit as st
import pandas as pd
import ollama
import logging
from logging_config import setup_logging
from utils.ioc_extraction_workflow import ioc_extraction_agent_workflow
from utils.database import (
    load_database,
    create_case,
    delete_case,
    insert_host_iocs,
    insert_network_iocs,
    insert_timeline_events,
)


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

        case_labels = [
            f"{row['case_id']}: {row['name']}" for _, row in cases_df.iterrows()
        ]
        case_map = {
            label: row["case_id"]
            for label, row in zip(case_labels, cases_df.to_dict("records"))
        }

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

        if selected_case:
            with st.expander("Delete Case"):
                st.warning(
                    f"You are about to delete case {selected_case} and all its associated data. This action cannot be undone."
                )
                confirm_delete = st.checkbox("I understand and wish to proceed.")
                if st.button("Delete"):
                    if confirm_delete:
                        if delete_case(selected_case):
                            st.success(f"Case {selected_case} deleted successfully.")
                            st.rerun()
                        else:
                            st.error(f"Failed to delete case {selected_case}.")
                    else:
                        st.error("Please confirm deletion by checking the box.")

        st.write("---")

    return selected_case


def render_main_content(databases, selected_case):
    st.title("Incident Analysis Dashboard")
    st.markdown("This dashboard provides a comprehensive overview of the incident.")

    st.write("---")

    col1, col2 = st.columns(2)
    with col1:
        client = ollama.Client(host="http://192.168.50.21:11434")
        list_of_models = client.list()["models"]
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
            incident_description = st.text_area(
                "Provide a detailed description of the incident.", height=200
            )
            submit_button = st.form_submit_button(label="Extract IOCs")

            if submit_button:
                st.session_state.ioc_extracted = True
                st.session_state.incident_description = incident_description

        if st.session_state.get("ioc_extracted"):
            st.session_state.ioc_extracted = False
            run_ioc_extraction(
                llm_model, selected_case, st.session_state.incident_description
            )

        st.subheader("Indicators of Compromise")
        render_data_tabs(databases)

        st.subheader("Incident Timeline")
        render_html_timeline(databases.get("timeline"))


def render_html_timeline(timeline_df: pd.DataFrame, tz_label: str = "UTC"):
    """
    Render a vertical timeline using only Streamlit widgets.
    Expects columns: timestamp_utc (datetime), activity, system_name, evidence_source, status_tag
    """
    if timeline_df.empty:
        st.info("No timeline data to visualize.")
        return

    # Sort & ensure datetimes (assumed UTC)
    df = timeline_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp_utc"]):
        df["timestamp_utc"] = pd.to_datetime(
            df["timestamp_utc"], utc=True, errors="coerce"
        )
    df = df.sort_values("timestamp_utc").reset_index(drop=True)

    # Helpers to format headers and time labels
    def day_header(dt: pd.Timestamp) -> str:
        return dt.strftime("%B %-d, %Y") if hasattr(dt, "strftime") else str(dt)

    def time_label(dt: pd.Timestamp) -> str:
        # show HH:MM + TZ
        return dt.strftime("%H:%M ") + tz_label

    # Outer card-style container (Streamlit 1.29+: border=True supported)
    try:
        card = st.container(border=True)
    except TypeError:
        # Fallback for older Streamlit: plain container
        card = st.container()

    with card:
        last_day = None
        for _, row in df.iterrows():
            ts = row["timestamp_utc"]
            if pd.isna(ts):
                # Skip invalid timestamps
                continue

            day = ts.date()
            if day != last_day:
                # Day header line (small uppercase look with caption)
                st.caption(day_header(ts).upper())
                last_day = day

            # A row = [dot column, time column, content column]
            dot_col, time_col, body_col = st.columns([0.05, 0.20, 0.75])

            with dot_col:
                st.markdown("🔵")  # simple blue dot

            with time_col:
                st.caption(time_label(ts))

            with body_col:
                # Main line (activity)
                activity = row.get("activity", "")
                st.markdown(activity if activity else "—")

                # Secondary lines (dimmed info)
                details = []
                sys_name = row.get("system_name", "")
                src = row.get("evidence_source", "")
                status = row.get("status_tag", "")
                if sys_name:
                    details.append(f"**System:** {sys_name}")
                if src:
                    details.append(f"**Source:** {src}")
                if status:
                    details.append(f"**Status:** {status}")

                if details:
                    st.caption("  •  ".join(details))


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
        st.dataframe(timeline_df, use_container_width=True, hide_index=True)
    with tab2:
        st.dataframe(host_ioc_df, use_container_width=True, hide_index=True)
    with tab3:
        st.dataframe(network_ioc_df, use_container_width=True, hide_index=True)


def run_ioc_extraction(llm_model, selected_case, incident_description):
    progress_bar = st.progress(0, text="Initializing IOC extraction...")

    with st.spinner("Extracting IOCs..."):
        result = ioc_extraction_agent_workflow(
            llm_model=llm_model,
            case_id=selected_case,
            incident_description=incident_description,
        )

        host_iocs = result.get("host_ioc_objects", [])
        network_iocs = result.get("network_ioc_objects", [])
        timeline_events = result.get("timeline_objects", [])

        total_iocs = len(host_iocs) + len(network_iocs) + len(timeline_events)
        completed_iocs = 0

        def update_progress(text):
            nonlocal completed_iocs
            completed_iocs += 1
            progress = completed_iocs / total_iocs if total_iocs > 0 else 1
            progress_bar.progress(progress, text=text)

        if host_iocs:
            host_ioc_dicts = []
            for ioc in host_iocs:
                ioc_dict = ioc.model_dump()
                ioc_dict["case_id"] = selected_case
                host_ioc_dicts.append(ioc_dict)
            insert_host_iocs(host_ioc_dicts)
            update_progress(f"Inserted {len(host_iocs)} host IOCs.")

        if network_iocs:
            network_ioc_dicts = []
            for ioc in network_iocs:
                ioc_dict = ioc.model_dump()
                ioc_dict["case_id"] = selected_case
                network_ioc_dicts.append(ioc_dict)
            insert_network_iocs(network_ioc_dicts)
            update_progress(f"Inserted {len(network_iocs)} network IOCs.")

        if timeline_events:
            timeline_event_dicts = []
            for event in timeline_events:
                event_dict = event.model_dump()
                event_dict["case_id"] = selected_case
                timeline_event_dicts.append(event_dict)
            insert_timeline_events(timeline_event_dicts)
            update_progress(f"Inserted {len(timeline_events)} timeline events.")

    progress_bar.progress(1.0, text="IOC extraction complete!")
    st.success("IOCs extracted and saved successfully!")
    st.rerun()


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
