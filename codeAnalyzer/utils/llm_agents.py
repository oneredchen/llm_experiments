import re
from ollama import AsyncClient
from utils.structured_response import FileTypeAnalysis, FileFunctionAnalysis


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
