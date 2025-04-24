import os
from utils.database import load_database
import streamlit as st

# Datasets
databases = load_database()
cases_df = databases['cases']
timeline_df = databases['timeline']
host_ioc_df = databases['host_ioc']
network_ioc_df = databases['network_ioc']
# Streamlit Setup
st.set_page_config(page_title="Incident Notebook")

# Main Body
st.write("# Incident Notebook")

# User Input
incident_description = st.text_area("Incident Description")

# Display DataFrames

st.write("## Timeline")
st.dataframe(timeline_df)
st.write("## Host IOCs")
st.dataframe(host_ioc_df)
st.write("## Network IOCs")
st.dataframe(network_ioc_df)