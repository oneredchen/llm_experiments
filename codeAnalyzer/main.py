import os
from ollama import chat
from pydantic import BaseModel

LLM_MODEL = "llama3.1"
INPUT_DIR = os.path.join(os.getcwd(), "input")
OUTPUT_DIR = os.path.join(os.getcwd(), "output")


class FileTypeAnalysis(BaseModel):
    filename: str
    file_type: str
    related_programming_language: str


class FileFunctionAnalysis(BaseModel):
    filename: str
    file_type: str
    file_function: str  # Description of the file’s purpose
    summary: str  # Concise high-level summary
    key_components: list[str]  # List of important elements in the file


def identify_files(input_dir: str) -> list:
    files = os.listdir(input_dir)
    all_files = []
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            all_files.append(os.path.join(root, file))
    return all_files


def read_files(file_path: list) -> list:
    code_files = []
    for file in file_path:
        file_content = {}
        with open(file, "r") as f:
            file_content["filename"] = os.path.basename(file)  # Extract filename
            file_content["contents"] = f.read()
            code_files.append(file_content)
    return code_files


def file_type_identifier(llm_model: str, code_contents: dict) -> FileFunctionAnalysis:
    system_prompt = {
        "role": "system",
        "content": """You are an expert software engineer. 
        You will be given file contents to analyze and your job is to identify the following:
        1. Filename: Name of the file whose contents are being analyzed. Eg. requirements.txt
        2. File type: Based on the filename and contents, identify the file type. Eg. text
        3. Related Programming Language: Based on the contents, identify the programming language used / related to the file. Eg. Requirements.txt file are used in Python projects
        """,
    }
    user_prompt = {
        "role": "user",
        "content": f"""Analyze the contents below to identify the file type and programming language used / related to the file.
        **Filename:** {code_contents['filename']}
        **File contents:**
        {code_contents['contents']}
        """,
    }
    message = [system_prompt, user_prompt]
    chat_completion = chat(
        llm_model,
        message,
        options={"temperature": 0.3, "num_ctx": 2048},
        format=FileTypeAnalysis.model_json_schema(),
    )
    response = FileTypeAnalysis.model_validate_json(chat_completion.message.content)
    return response


def code_usage_analyzer(llm_model: str, code_contents: dict) -> FileFunctionAnalysis:

    system_prompt = {
        "role": "system",
        "content": """You are an expert software engineer tasked with analyzing software project files.
        Your job is to identify:
        1. The filename of the file being analyzed.
        2. The type of file (e.g., Python script, JSON configuration, Markdown documentation).
        3. The function or purpose of the file within a software project.
        4. A concise summary of what the file does.
        5. The key components present in the file (e.g., important functions, dependencies, configurations).
        Provide a structured analysis of the file based on its contents.
        """,
    }

    user_prompt = {
        "role": "user",
        "content": f"""Analyze the given file and determine its function in a software project.

        Filename: {code_contents['filename']}
        
        File Contents:
        {code_contents['contents']}
        
        Based on the above, provide:
        - The type of file (e.g., Python script, JSON configuration).
        - The function or purpose of the file.
        - A summary explaining what this file does.
        - Key components or elements found in the file.
        """,
    }

    message = [system_prompt, user_prompt]
    chat_completion = chat(
        llm_model,
        message,
        options={"temperature": 0.3, "num_ctx": 8000},
        format=FileFunctionAnalysis.model_json_schema(),
    )
    response = FileFunctionAnalysis.model_validate_json(chat_completion.message.content)
    return response


def main():
    # Extracting file contents
    code_files = identify_files(INPUT_DIR)
    file_contents = read_files(code_files)

    # Context list to store analysis results
    context = []

    # Identify programming language and file type
    file_type_results = {}
    for content in file_contents:
        file_type_analysis = file_type_identifier(LLM_MODEL, content)
        file_type_results[file_type_analysis.filename] = (
            file_type_analysis  # Store results for later use
        )

        context.append(
            {
                "role": "user",
                "content": f"**Filename:** {file_type_analysis.filename}, **File Type:** {file_type_analysis.file_type}, **Related Programming Language:** {file_type_analysis.related_programming_language}",
            }
        )

    # Identify file function using code_usage_analyzer
    for content in file_contents:
        file_function_analysis = code_usage_analyzer(
            LLM_MODEL, content
        )  # Now correctly using code_usage_analyzer

        context.append(
            {
                "role": "user",
                "content": f"""**Filename:** {file_function_analysis.filename}, 
                **File Type:** {file_function_analysis.file_type}, 
                **File Function:** {file_function_analysis.file_function}, 
                **Summary:** {file_function_analysis.summary}, 
                **Key Components:** {', '.join(file_function_analysis.key_components)}""",
            }
        )

    # Print results
    for item in context:
        print(item)


if __name__ == "__main__":
    main()
