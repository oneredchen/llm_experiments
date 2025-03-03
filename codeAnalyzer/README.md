# Code Analyzer with LLM Integration

## Overview
This project is an **AI-powered code analyzer** that scans files in a given directory, determines their type and function, and then provides an overall summary of the program. It utilizes **asynchronous Python programming** and integrates with an **LLM (Large Language Model)** for intelligent analysis.

## Features
- **Identify file types**: Detects the type of files and their associated programming language.
- **Analyze file functions**: Determines the role of each file in the project.
- **Generate a project summary**: Provides an AI-generated markdown report on the program's purpose and key components.
- **Asynchronous execution**: Uses Python's `asyncio` for concurrent processing.
- **LLM Integration**: Uses `ollama` to analyze and summarize code.

## Installation
### **Prerequisites**
Ensure you have:
- Python **3.8+** installed.
- `pip` installed.
- An LLM server running and accessible.

## Usage
### **1. Prepare Input Files**
Place the files you want to analyze in the `input/` directory.

### **2. Run the Analysis**
Execute the following command:
   ```sh
   python main.py
   ```
The script will:
- Scan the `input/` directory for files.
- Analyze the file types and functions asynchronously.
- Generate a markdown report summarizing the program.

### **3. View the Output**
After execution, the analysis report will be saved in the `output/` directory:
   ```
   output/Code Analysis Report.md
   ```
Open this file to review the AI-generated project summary.

## Project Structure
```
code-analyzer/
│── input/          # Directory for input files
│── output/         # Directory for generated reports
│── main.py         # Main script to run analysis
│── requirements.txt # List of dependencies
│── README.md       # Documentation
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

