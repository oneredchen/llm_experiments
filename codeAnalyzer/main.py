import os
import re
import asyncio
from ollama import AsyncClient
from pydantic import BaseModel

# Constants for model and directories
LLM_MODEL = "deepseek-r1:32b"
INPUT_DIR = os.path.join(os.getcwd(), "input")
OUTPUT_DIR = os.path.join(os.getcwd(), "output")


class FileTypeAnalysis(BaseModel):
    """Pydantic model for storing file type analysis results."""

    filename: str
    file_type: str
    related_programming_language: str


class FileFunctionAnalysis(BaseModel):
    """Pydantic model for storing file function analysis results."""

    filename: str
    file_type: str  # General classification (e.g., Python script, JSON file)
    file_function: str  # Description of the file’s purpose
    summary: str  # Concise high-level summary
    key_components: list[str]  # List of important elements in the file


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


def clean_llm_response(response_text: str) -> str:
    """
    Removes the <think>...</think> portion from the LLM response.

    :param response_text: The raw response text from the LLM.
    :return: Cleaned response text without the <think> section.
    """
    return re.sub(r"<think>.*?</think>", "", response_text, flags=re.DOTALL).strip()


async def file_type_identifier(llm_model: str, code_contents: dict) -> FileTypeAnalysis:
    """
    Identify the file type and related programming language using an LLM.

    :param llm_model: LLM model name to use.
    :param code_contents: Dictionary containing filename and contents.
    :return: FileTypeAnalysis object.
    """
    print(f"Analyzing file type for {code_contents['filename']}...")

    system_prompt = {
        "role": "system",
        "content": """You are an expert software engineer. 
        You will be given file contents to analyze and your job is to identify the following:
        1. Filename: Name of the file whose contents are being analyzed.
        2. File type: Identify the file type based on its content and name.
        3. Related Programming Language: Identify the programming language used or related to the file.
        """,
    }

    user_prompt = {
        "role": "user",
        "content": f"""Analyze the contents below to identify the file type and programming language.

        **Filename:** {code_contents['filename']}
        
        **File contents:**
        {code_contents['contents']}
        """,
    }

    message = [system_prompt, user_prompt]
    chat_completion = await AsyncClient().chat(
        model=llm_model,
        messages=message,
        options={"temperature": 0.3, "num_ctx": 2048},
        format=FileTypeAnalysis.model_json_schema(),
    )
    response = FileTypeAnalysis.model_validate_json(chat_completion.message.content)

    print(f"File type analysis complete: {response.filename} is a {response.file_type}")
    return response


async def code_usage_analyzer(
    llm_model: str, code_contents: dict
) -> FileFunctionAnalysis:
    """
    Analyze a file to determine its function and key components.

    :param llm_model: LLM model name to use.
    :param code_contents: Dictionary containing filename and contents.
    :return: FileFunctionAnalysis object.
    """
    print(f"Analyzing function for {code_contents['filename']}...")

    system_prompt = {
        "role": "system",
        "content": """You are an expert software engineer tasked with analyzing software project files.
        Your job is to identify:
        1. The filename of the file being analyzed.
        2. The type of file (e.g., Python script, JSON configuration, Markdown documentation).
        3. The function or purpose of the file within a software project.
        4. A concise summary of what the file does.
        5. The key components present in the file (e.g., important functions, dependencies, configurations).
        """,
    }

    user_prompt = {
        "role": "user",
        "content": f"""Analyze the given file and determine its function in a software project.

        Filename: {code_contents['filename']}
        
        File Contents:
        {code_contents['contents']}
        
        Based on the above, provide:
        - The type of file.
        - The function or purpose of the file.
        - A summary explaining what this file does.
        - Key components or elements found in the file.
        """,
    }

    message = [system_prompt, user_prompt]
    chat_completion = await AsyncClient().chat(
        model=llm_model,
        messages=message,
        options={"temperature": 0.3, "num_ctx": 8000},
        format=FileFunctionAnalysis.model_json_schema(),
    )
    response = FileFunctionAnalysis.model_validate_json(chat_completion.message.content)

    print(f"Function analysis complete for {response.filename}.")
    return response


async def program_overview_analyzer(llm_model: str, context: list) -> str:
    """Analyze the overall purpose of the project based on the analyzed files."""
    print("\nAnalyzing overall program purpose...")

    system_prompt = {
        "role": "system",
        "content": "You are an expert software engineer who specializes in reverse engineering and software analysis.",
    }

    # Insert the system prompt at the beginning of the context list
    context.insert(0, system_prompt)

    user_prompt = {
        "role": "user",
        "content": """Provide a detailed summary about what the program is trying to do based on the information available to you.
        Your analysis should be presented in a clear report using the markdown language.
        """,
    }

    # Append the user prompt at the end of the context list
    context.append(user_prompt)

    chat_completion = await AsyncClient().chat(
        model=llm_model,
        messages=context,
        options={"temperature": 0.3, "num_ctx": 16000},
    )
    response = chat_completion.message.content

    print("Program overview analysis complete.")
    return clean_llm_response(response)


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


async def main():
    """
    Main function to analyze files in the input directory.
    Identifies file types and functions using an LLM.
    """
    print("Starting analysis...\n")

    # Step 1: Extract file contents
    code_files = identify_files(INPUT_DIR)
    file_contents = read_files(code_files)

    # Context list to store analysis results
    context = []

    # Step 2: Identify programming language and file type
    print("\nIdentifying file types...")
    file_type_tasks = [fileTypeTask(LLM_MODEL, content) for content in file_contents]
    file_analysis_results = await asyncio.gather(*file_type_tasks)
    context += file_analysis_results

    # Step 3: Identify file function
    print("\nIdentifying file functions...")
    file_function_tasks = [
        fileFunctionTask(LLM_MODEL, content) for content in file_contents
    ]
    file_function_results = await asyncio.gather(*file_function_tasks)
    context += file_function_results

    # Step 4: Analyze overall program
    program_overview = await program_overview_analyzer(LLM_MODEL, context)
    print("\nAnalysis completed successfully.")

    # Step 5: Save results to output directory
    print("\nSaving analysis results...")
    with open(os.path.join(OUTPUT_DIR, "Code Analysis Report.md"), "w") as f:
        f.write(program_overview)

    print(f"Analysis results saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    asyncio.run(main())
