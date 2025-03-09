from pydantic import BaseModel


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
