import streamlit as st
import pandas as pd
import ollama
import logging
import os
import sys
import time
import requests
from dotenv import load_dotenv

# Add the project root to sys.path to resolve 'utils' for logging
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from frontend.utils.logging_config import setup_logging

# Load .env file
load_dotenv()
ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
API_URL = os.getenv("API_URL", "http://localhost:8000")


def setup_page():
    st.set_page_config(page_title="Incident Notebook", layout="wide", page_icon="🛡️")
    if "ioc_extracted" not in st.session_state:
        st.session_state.ioc_extracted = False


def check_api_status():
    """Check if Backend API is reachable."""
    try:
        response = requests.get(f"{API_URL}/", timeout=1)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def check_ollama_status():
    """Check if Ollama is reachable."""
    try:
        response = requests.get(f"{ollama_host}/api/tags", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def load_cases():
    """Fetch cases from API."""
    try:
        response = requests.get(f"{API_URL}/cases")
        if response.status_code == 200:
            return pd.DataFrame(response.json())
        else:
            logging.error(f"Failed to load cases: {response.text}")
            return pd.DataFrame()
    except Exception as e:
        logging.error(f"Error loading cases: {e}")
        return pd.DataFrame()


def load_case_data(case_id):
    """Fetch case details (timeline, IOCs) from API."""
    try:
        response = requests.get(f"{API_URL}/cases/{case_id}/data")
        if response.status_code == 200:
            data = response.json()
            return {
                "timeline": pd.DataFrame(data.get("timeline_events", [])),
                "host_ioc": pd.DataFrame(data.get("host_iocs", [])),
                "network_ioc": pd.DataFrame(data.get("network_iocs", [])),
            }
        else:
            st.error("Failed to load case data.")
            return {}
    except Exception as e:
        st.error(f"Error fetching case data: {e}")
        return {}


def create_new_case_api(name):
    try:
        response = requests.post(f"{API_URL}/cases", json={"name": name})
        if response.status_code == 200:
            return response.json().get("case_id")
    except Exception as e:
        st.error(f"Error creating case: {e}")
    return None


def delete_case_api(case_id):
    try:
        response = requests.delete(f"{API_URL}/cases/{case_id}")
        return response.status_code == 200
    except Exception as e:
        st.error(f"Error deleting case: {e}")
        return False


def convert_df_to_csv(df):
    return df.to_csv(index=False).encode("utf-8")


def render_sidebar(cases_df):
    with st.sidebar:
        st.title("🛡️ Incident Notebook")
        st.write("---")

        # Connection Status
        api_up = check_api_status()
        if api_up:
            st.caption("🟢 Backend API Online")
        else:
            st.error("🔴 Backend API Offline")
        
        ollama_up = check_ollama_status()
        if ollama_up:
            st.caption("🟢 AI Engine Online")
        else:
            st.error("🔴 AI Engine Offline")

        st.write("---")
        st.header("Case Management")

        if cases_df.empty:
            st.warning("No existing cases found.")
            case_labels = []
            selected_case = None
        else:
            case_labels = [
                f"{row['case_id']}: {row['name']}" for _, row in cases_df.iterrows()
            ]
            case_map = {
                label: row["case_id"]
                for label, row in zip(case_labels, cases_df.to_dict("records"))
            }
            selected_label = st.selectbox("Select Case", case_labels)
            selected_case = case_map[selected_label]

        with st.expander("Create New Case"):
            new_case_name = st.text_input("New Case Name")
            if st.button("Create", type="primary"):
                if new_case_name:
                    if create_new_case_api(new_case_name):
                        st.success(f"Case '{new_case_name}' created!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Failed to create case.")
                else:
                    st.error("Case Name is required.")

        if selected_case:
            with st.expander("Delete Case", expanded=False):
                st.warning(f"Delete case {selected_case}?")
                if st.button("Confirm Delete", type="primary"):
                    if delete_case_api(selected_case):
                        st.success(f"Deleted {selected_case}")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Deletion failed.")

        st.write("---")

    return selected_case, ollama_up


def render_dashboard_metrics(timeline_df, host_ioc_df, network_ioc_df):
    """Render high-level metrics and charts."""
    st.subheader("Case Overview")
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Timeline Events", len(timeline_df) if not timeline_df.empty else 0)
    m2.metric("Host IOCs", len(host_ioc_df) if not host_ioc_df.empty else 0)
    m3.metric("Network IOCs", len(network_ioc_df) if not network_ioc_df.empty else 0)

    if not host_ioc_df.empty or not network_ioc_df.empty:
        c1, c2 = st.columns(2)
        with c1:
            if not host_ioc_df.empty:
                st.caption("Host IOC Types")
                type_counts = host_ioc_df["indicator_type"].value_counts()
                st.bar_chart(type_counts, color="#4CAF50")
        
        with c2:
            if not network_ioc_df.empty:
                st.caption("Network IOC Types")
                type_counts = network_ioc_df["indicator_type"].value_counts()
                st.bar_chart(type_counts, color="#2196F3")


def render_html_timeline(timeline_df, tz_label="UTC"):
    if timeline_df.empty:
        st.info("No timeline data to visualize.")
        return

    # Sort & ensure datetimes
    df = timeline_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp_utc"]):
        df["timestamp_utc"] = pd.to_datetime(
            df["timestamp_utc"], utc=True, errors="coerce"
        )
    df = df.sort_values("timestamp_utc").reset_index(drop=True)

    def day_header(dt):
        return dt.strftime("%B %-d, %Y") if hasattr(dt, "strftime") else str(dt)

    def time_label(dt):
        return dt.strftime("%H:%M ") + tz_label

    with st.container(border=True):
        last_day = None
        for _, row in df.iterrows():
            ts = row["timestamp_utc"]
            if pd.isna(ts): continue

            day = ts.date()
            if day != last_day:
                st.markdown(f"**{day_header(ts).upper()}**")
                st.write("---")
                last_day = day

            c1, c2, c3 = st.columns([0.1, 0.2, 0.7])
            with c1:
                st.markdown("🔹")
            with c2:
                st.caption(time_label(ts))
            with c3:
                st.markdown(f"**{row.get('activity', '')}**")
                
                details = []
                if row.get("system_name"): details.append(f"🖥️ {row['system_name']}")
                if row.get("evidence_source"): details.append(f"🔍 {row['evidence_source']}")
                if row.get("status_tag"): details.append(f"🏷️ {row['status_tag']}")
                
                if details:
                    st.caption(" | ".join(details))


def run_ioc_extraction_api(llm_model, selected_case, incident_description):
    with st.spinner("🕵️ Agent is analyzing the incident (via Backend)..."):
        try:
            payload = {
                "incident_description": incident_description,
                "llm_model": llm_model
            }
            response = requests.post(f"{API_URL}/cases/{selected_case}/extract", json=payload, timeout=300)
            
            if response.status_code == 200:
                result = response.json()
                counts = result.get("counts", {})
                st.balloons()
                st.success(f"Analysis Complete! Extracted {counts.get('host_iocs',0) + counts.get('network_iocs',0) + counts.get('timeline_events',0)} artifacts.")
                time.sleep(2)
                st.rerun()
            else:
                st.error(f"Extraction failed: {response.text}")
        except Exception as e:
            st.error(f"Error calling API: {e}")


def render_main_content(selected_case, is_ollama_up):
    st.title(f"📂 Case: {selected_case}")

    # Fetch Case Data from API
    data = load_case_data(selected_case)
    timeline_df = data.get("timeline", pd.DataFrame())
    host_ioc_df = data.get("host_ioc", pd.DataFrame())
    network_ioc_df = data.get("network_ioc", pd.DataFrame())

    # Analytics Dashboard
    render_dashboard_metrics(timeline_df, host_ioc_df, network_ioc_df)
    st.write("---")

    # Extraction Interface
    with st.expander("📝 Add Incident Text / Extract IOCs", expanded=True):
        if not is_ollama_up:
             st.warning("⚠️ AI Engine is offline. Cannot perform extraction.")
        else:
            try:
                # We still need Ollama client locally just to list models for the dropdown? 
                # OR we could expose an endpoint in backend. 
                # For now, let's keep local checks for UI convenience so frontend knows what to send.
                client = ollama.Client(host=ollama_host)
                list_of_models = client.list()["models"]
                model_names = [model["model"] for model in list_of_models]
                
                c_model, _ = st.columns([1, 2])
                with c_model:
                    llm_model = st.selectbox("Select Model", model_names, index=0)

                with st.form(key="ioc_form"):
                    incident_description = st.text_area(
                        "Paste incident notes, logs, or reports here:", 
                        height=150,
                        placeholder="e.g., At 10:00 AM, user reported suspicious activity..."
                    )
                    submit_button = st.form_submit_button(label="🚀 Extract IOCs")

                    if submit_button and incident_description:
                        # Trigger execution
                        run_ioc_extraction_api(
                            llm_model,
                            selected_case,
                            incident_description
                        )

            except Exception as e:
                st.error(f"Error connecting to Ollama: {e}")

    # Data Tabs
    st.subheader("Data & Artifacts")
    tab1, tab2, tab3 = st.tabs(["📅 Timeline", "💻 Host IOCs", "🌐 Network IOCs"])
    
    with tab1:
        c_dl, _ = st.columns([1, 4])
        with c_dl:
            if not timeline_df.empty:
                st.download_button("📥 Download CSV", convert_df_to_csv(timeline_df), "timeline.csv", "text/csv")
        render_html_timeline(timeline_df)
        st.expander("Raw Data").dataframe(timeline_df, use_container_width=True)

    with tab2:
        c_dl, _ = st.columns([1, 4])
        with c_dl:
            if not host_ioc_df.empty:
                st.download_button("📥 Download CSV", convert_df_to_csv(host_ioc_df), "host_iocs.csv", "text/csv")
        st.dataframe(host_ioc_df, use_container_width=True, hide_index=True)

    with tab3:
        c_dl, _ = st.columns([1, 4])
        with c_dl:
             if not network_ioc_df.empty:
                st.download_button("📥 Download CSV", convert_df_to_csv(network_ioc_df), "network_iocs.csv", "text/csv")
        st.dataframe(network_ioc_df, use_container_width=True, hide_index=True)


def main():
    setup_logging()
    logging.info("Frontend started.")
    setup_page()
    
    cases_df = load_cases()
    selected_case, is_ollama_up = render_sidebar(cases_df)

    if selected_case:
        render_main_content(selected_case, is_ollama_up)
    else:
        st.info("👈 Select or create a case from the sidebar to begin.")


if __name__ == "__main__":
    main()
