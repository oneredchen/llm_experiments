import os
import ollama
import asyncio
import streamlit as st
from utils.llm_agents import (
    file_type_identifier,
    code_usage_analyzer,
    program_overview_analyzer,
)

# Constants for model and directories
INPUT_DIR = os.path.join(os.getcwd(), "input")
OUTPUT_DIR = os.path.join(os.getcwd(), "output")


# Utility Functions
def update_analysis_state():
    st.session_state["run_analysis"] = True


def identify_files(input_dir: str) -> list:
    """
    Identify and return all file paths within the input directory.

    :param input_dir: Path to the input directory.
    :return: List of full file paths.
    """
    print(f"Scanning directory: {input_dir} for files...")
    all_files = []
    for root, _, files in os.walk(input_dir):  # Recursively walk through the directory
        for file in files:
            all_files.append(os.path.join(root, file))
    print(f"Total files found: {len(all_files)}")
    return all_files


def read_files(file_paths: list) -> list:
    """
    Read the content of each file and store it in a dictionary.

    :param file_paths: List of file paths to read.
    :return: List of dictionaries containing filename and contents.
    """
    print("Reading file contents...")
    code_files = []
    for file in file_paths:
        file_content = {}
        try:
            with open(file, "r", encoding="utf-8") as f:
                file_content["filename"] = os.path.basename(file)  # Extract filename
                file_content["contents"] = f.read()
                code_files.append(file_content)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    print(f"Successfully read {len(code_files)} files.")
    return code_files


async def fileTypeTask(llm_model: str, code_contents: dict) -> dict:
    file_type_results = {}
    file_type_analysis = await file_type_identifier(llm_model, code_contents)
    file_type_results[file_type_analysis.filename] = file_type_analysis  # Store results
    response = {
        "role": "user",
        "content": f"**Filename:** {file_type_analysis.filename}, **File Type:** {file_type_analysis.file_type}, **Related Programming Language:** {file_type_analysis.related_programming_language}",
    }
    return response


async def fileFunctionTask(llm_model: str, code_contents: dict) -> dict:
    file_function_analysis = await code_usage_analyzer(llm_model, code_contents)
    response = {
        "role": "user",
        "content": f"""**Filename:** {file_function_analysis.filename}, 
        **File Type:** {file_function_analysis.file_type}, 
        **File Function:** {file_function_analysis.file_function}, 
        **Summary:** {file_function_analysis.summary}, 
        **Key Components:** {', '.join(file_function_analysis.key_components)}""",
    }
    return response


async def run_analysis(llm_model):
    # Step 1: Extract file contents
    code_files = identify_files(INPUT_DIR)
    file_contents = read_files(code_files)

    # Context list to store analysis results
    context = []

    # Step 2: Identify programming language and file type
    file_type_tasks = [fileTypeTask(llm_model, content) for content in file_contents]
    file_analysis_results = await asyncio.gather(*file_type_tasks)
    context += file_analysis_results

    # Step 3: Identify file function
    file_function_tasks = [
        fileFunctionTask(llm_model, content) for content in file_contents
    ]
    file_function_results = await asyncio.gather(*file_function_tasks)
    context += file_function_results

    # Step 4: Analyze overall program
    program_overview = await program_overview_analyzer(llm_model, context)

    # Step 5: Save results to output directory
    with open(os.path.join(OUTPUT_DIR, "Code Analysis Report.md"), "w") as f:
        f.write(program_overview)

    return program_overview


async def main():
    # Streamlit Setup
    st.set_page_config(page_title="Code Analyzer")

    if "run_analysis" not in st.session_state:
        st.session_state["run_analysis"] = False

    st.write("## LLM Model Selection")
    list_of_models = ollama.list()["models"]
    model_names = [model["model"] for model in list_of_models]
    llm_model = st.selectbox(
        "Which Ollama LLM Model do you want to use for analysis?",
        model_names,
        index=None,
        placeholder="Select LLM Model...",
    )

    st.write("## File Upload")
    uploaded_files = st.file_uploader(
        "Upload files for analysis", accept_multiple_files=True
    )

    for uploaded_file in uploaded_files:
        bytes_data = uploaded_file.read()
        file_path = os.path.join(INPUT_DIR, uploaded_file.name)

        # Save the file to the input folder
        with open(file_path, "wb") as f:
            f.write(bytes_data)

    # File Analysis
    if uploaded_files and llm_model:
        if not st.session_state["run_analysis"]:
            st.button("Run Analytics", on_click=update_analysis_state)
        else:
            with st.spinner("Performing Analysis...", show_time=True):
                response = await run_analysis(llm_model=llm_model)

            st.divider()
            st.markdown(response)

            st.download_button(
                label="Download Report",
                data=response,
                file_name="Code Analysis Report.md",
            )


if __name__ == "__main__":
    asyncio.run(main())
