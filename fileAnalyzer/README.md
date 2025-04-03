# Code Analyzer with LLM Integration

## Overview

This project is an **AI-powered code analyzer** that scans files in a given directory, determines their type and function, and then provides an overall summary of the program. It utilizes **asynchronous Python programming** and integrates with an **LLM (Large Language Model)** for intelligent analysis. The project now features an interactive **Streamlit-based web interface** for uploading files and running the analysis.

## Features

- **Identify file types**: Detects the type of files and their associated programming language.
- **Analyze file functions**: Determines the role of each file in the project.
- **Generate a project summary**: Provides an AI-generated markdown report on the program's purpose and key components.
- **Asynchronous execution**: Uses Python's `asyncio` for concurrent processing.
- **LLM Integration**: Uses `ollama` to analyze and summarize code.
- **Streamlit Interface**: User-friendly web interface using Streamlit.

## Installation

### **Prerequisites**

Ensure you have:

- Python **3.8+** installed.
- `pip` installed.
- An LLM server running and accessible.

### **Setup Environment**

1. Clone this repository:

   ```sh
   git clone https://github.com/your-repo/code-analyzer.git
   cd code-analyzer
   ```

2. Create and activate a virtual environment:

   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage

### **1. Upload Files Through Streamlit**

Start the Streamlit app:

```sh
streamlit run app.py
```

The app will:

- Allow you to upload files through the web interface.
- Analyze the file types and functions asynchronously.
- Generate a markdown report summarizing the program.

### **2. Select LLM Model**

- The Streamlit app will list available models from the Ollama server.
- Select the model you want to use for analysis.

### **3. Run the Analysis**

- After uploading files and selecting the LLM model:
  - Click **Run Analytics**.
  - The app will display a progress spinner while analysis is performed.

### **4. View and Download the Output**

After execution, the analysis report will be saved in the `output/` directory:

```
output/Code Analysis Report.md
```

- The report will also be displayed in the Streamlit app.
- You can download the report directly from the app.

## Project Structure

```
code-analyzer/
│── input/          # Directory for input files
│── output/         # Directory for generated reports
│── app.py          # Streamlit app to run analysis
│── requirements.txt # List of dependencies
│── README.md       # Documentation
│── utils/          # Contains LLM agent functions
```

## How It Works

### **1. File Identification**

The `identify_files()` function scans the `input/` directory and collects all file paths.

### **2. File Type Analysis**

The `file_type_identifier()` function:

- Uses an LLM to classify each file type.
- Detects related programming languages.

### **3. File Function Analysis**

The `code_usage_analyzer()` function:

- Determines the role of each file in the project.
- Extracts key functionalities and dependencies.

### **4. Project Summary Generation**

The `program_overview_analyzer()` function:

- Aggregates all collected information.
- Generates a markdown report summarizing the entire program.

## License

This project is licensed under the MIT License.
