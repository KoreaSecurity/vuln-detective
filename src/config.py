"""Configuration management for VulnDetective"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from dotenv import load_dotenv


class ModelConfig(BaseModel):
    """AI Model configuration"""
    provider: str = Field(default="openai")
    default_model: str = Field(default="gpt-4-turbo-preview")
    fast_model: str = Field(default="gpt-3.5-turbo")
    advanced_model: str = Field(default="gpt-4")
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, gt=0)
    timeout: int = Field(default=300, gt=0)


class AnalysisConfig(BaseModel):
    """Analysis configuration"""
    max_file_size: int = Field(default=1048576)  # 1MB
    confidence_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    enable_static_analysis: bool = Field(default=True)
    enable_semantic_analysis: bool = Field(default=True)
    enable_pattern_detection: bool = Field(default=True)
    max_concurrent_analyses: int = Field(default=5, gt=0)


class OutputConfig(BaseModel):
    """Output configuration"""
    output_dir: Path = Field(default=Path("./output"))
    report_formats: list[str] = Field(default=["html", "json", "sarif"])
    save_intermediate_results: bool = Field(default=True)
    create_backup: bool = Field(default=False)


class Config(BaseModel):
    """Main configuration"""
    model: ModelConfig = Field(default_factory=ModelConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    api_keys: Dict[str, Optional[str]] = Field(default_factory=dict)
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    @classmethod
    def from_env(cls, env_file: Optional[Path] = None) -> "Config":
        """Load configuration from environment variables"""
        if env_file and env_file.exists():
            load_dotenv(env_file)
        else:
            load_dotenv()

        api_keys = {
            "openai": os.getenv("OPENAI_API_KEY"),
            "anthropic": os.getenv("ANTHROPIC_API_KEY"),
        }

        model_config = ModelConfig(
            default_model=os.getenv("DEFAULT_MODEL", "gpt-4-turbo-preview"),
            fast_model=os.getenv("FAST_MODEL", "gpt-3.5-turbo"),
            advanced_model=os.getenv("ADVANCED_MODEL", "gpt-4"),
        )

        analysis_config = AnalysisConfig(
            max_file_size=int(os.getenv("MAX_FILE_SIZE", "1048576")),
            confidence_threshold=float(os.getenv("CONFIDENCE_THRESHOLD", "0.7")),
        )

        output_config = OutputConfig(
            output_dir=Path(os.getenv("OUTPUT_DIR", "./output")),
            report_formats=os.getenv("REPORT_FORMAT", "html,json,sarif").split(","),
        )

        return cls(
            model=model_config,
            analysis=analysis_config,
            output=output_config,
            api_keys=api_keys,
            debug=os.getenv("DEBUG", "false").lower() == "true",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )

    def validate_api_keys(self) -> None:
        """Validate that required API keys are present"""
        if not self.api_keys.get("openai"):
            raise ValueError(
                "OpenAI API key is required. "
                "Please set OPENAI_API_KEY environment variable."
            )


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance"""
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def set_config(config: Config) -> None:
    """Set global configuration instance"""
    global _config
    _config = config
