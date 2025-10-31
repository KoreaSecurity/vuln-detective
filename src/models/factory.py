"""Model factory for creating AI model instances"""

from typing import Optional
from .base import BaseModel, ModelType
from .openai_model import OpenAIModel
from ..config import Config, get_config


class ModelFactory:
    """Factory for creating AI model instances"""

    @staticmethod
    def create_model(
        model_type: ModelType = ModelType.DEFAULT,
        config: Optional[Config] = None,
    ) -> BaseModel:
        """Create an AI model instance based on type and config"""
        if config is None:
            config = get_config()

        config.validate_api_keys()

        # Determine model name based on type
        if model_type == ModelType.FAST:
            model_name = config.model.fast_model
        elif model_type == ModelType.ADVANCED:
            model_name = config.model.advanced_model
        else:
            model_name = config.model.default_model

        # Create appropriate model based on provider
        provider = config.model.provider.lower()

        if provider == "openai":
            api_key = config.api_keys.get("openai")
            if not api_key:
                raise ValueError("OpenAI API key not found in configuration")

            return OpenAIModel(
                api_key=api_key,
                model_name=model_name,
                temperature=config.model.temperature,
            )
        else:
            raise ValueError(f"Unsupported model provider: {provider}")

    @staticmethod
    def create_fast_model(config: Optional[Config] = None) -> BaseModel:
        """Create a fast model for quick analyses"""
        return ModelFactory.create_model(ModelType.FAST, config)

    @staticmethod
    def create_default_model(config: Optional[Config] = None) -> BaseModel:
        """Create a default balanced model"""
        return ModelFactory.create_model(ModelType.DEFAULT, config)

    @staticmethod
    def create_advanced_model(config: Optional[Config] = None) -> BaseModel:
        """Create an advanced model for complex analyses"""
        return ModelFactory.create_model(ModelType.ADVANCED, config)
