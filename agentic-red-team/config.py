from pathlib import Path
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

CONFIG_DIR = Path(__file__).resolve().parent / "config"


class OllamaSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OLLAMA_", env_file=".env", extra="ignore"
    )
    host: str = "http://192.168.50.21:11434"
    api_key: str = ""
    model: str = "qwen3.5:35b-a3b-nvfp4"
    keep_alive: int = 1800  # seconds; 1800 = 30 minutes


class AgentSettings(BaseSettings):
    max_iterations: int = 15
    num_ctx: int = 32768
    temperature: float = 1
    max_concurrent_llm_requests: int = 8  # global cap across all articles
    tool_timeout: int = 600


class Settings(BaseModel):
    ollama: OllamaSettings = OllamaSettings()
    agent: AgentSettings = AgentSettings()


settings = Settings()
