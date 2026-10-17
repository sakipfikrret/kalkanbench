"""Configuration settings for KalkanBench execution and CLI."""

from __future__ import annotations

from pathlib import Path
from pydantic import BaseModel, Field


class KalkanConfig(BaseModel):
    """Runtime configuration for KalkanBench."""
    dataset_path: Path = Field(default_factory=lambda: Path("datasets/v1"))
    output_dir: Path = Field(default_factory=lambda: Path("reports"))
    agent_type: str = "mock-safe"
    report_formats: list[str] = Field(default_factory=lambda: ["json", "html"])
    fail_fast: bool = False
    timeout_seconds: float = 30.0
    random_seed: int = 42
    
    # Local loopback model configuration
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3:latest"
    max_model_tokens: int = 2048
