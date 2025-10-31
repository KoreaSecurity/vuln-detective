"""Base AI model interface"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class ModelType(Enum):
    """AI model types based on complexity"""
    FAST = "fast"  # Quick analysis, cheaper
    DEFAULT = "default"  # Balanced
    ADVANCED = "advanced"  # Deep analysis, expensive


@dataclass
class ModelResponse:
    """Response from AI model"""
    content: str
    model: str
    usage: Dict[str, int]
    finish_reason: str
    metadata: Optional[Dict[str, Any]] = None

    @property
    def total_tokens(self) -> int:
        """Get total tokens used"""
        return self.usage.get("total_tokens", 0)


class BaseModel(ABC):
    """Base class for AI models"""

    def __init__(self, api_key: str, model_name: str, temperature: float = 0.2):
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
    ) -> ModelResponse:
        """Generate completion from prompt"""
        pass

    @abstractmethod
    async def complete_structured(
        self,
        prompt: str,
        response_format: Dict[str, Any],
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate structured completion (JSON)"""
        pass

    async def analyze_code(
        self,
        code: str,
        task: str,
        context: Optional[str] = None,
    ) -> ModelResponse:
        """Analyze code with specific task"""
        system_prompt = """You are an expert security researcher and code analyst.
Your task is to analyze code for security vulnerabilities with high precision.
Focus on finding real, exploitable vulnerabilities, not false positives."""

        user_prompt = f"""Task: {task}

Code to analyze:
```
{code}
```
"""
        if context:
            user_prompt += f"\nAdditional context:\n{context}"

        return await self.complete(
            prompt=user_prompt,
            system_prompt=system_prompt,
        )

    async def detect_vulnerabilities(
        self,
        code: str,
        language: str,
    ) -> ModelResponse:
        """Detect vulnerabilities in code"""
        task = f"""Analyze this {language} code for security vulnerabilities.

For each vulnerability found, provide:
1. Type (e.g., Buffer Overflow, SQL Injection, XSS)
2. CWE ID
3. Severity (Critical, High, Medium, Low)
4. Line number(s)
5. Description of the issue
6. Why it's exploitable
7. Recommended fix

Format your response as a structured list."""

        return await self.analyze_code(code, task)

    async def generate_exploit(
        self,
        vulnerability_info: Dict[str, Any],
    ) -> ModelResponse:
        """Generate exploit for vulnerability"""
        prompt = f"""Generate a proof-of-concept exploit for this vulnerability:

Vulnerability Type: {vulnerability_info.get('type')}
Location: {vulnerability_info.get('location')}
Description: {vulnerability_info.get('description')}

Code context:
```
{vulnerability_info.get('code')}
```

Provide:
1. Exploitation strategy
2. Step-by-step approach
3. Working exploit code
4. Required conditions
5. Expected outcome
"""
        system_prompt = """You are a security researcher creating proof-of-concept exploits.
Create working, educational exploits that demonstrate the vulnerability clearly."""

        return await self.complete(prompt, system_prompt)

    async def generate_patch(
        self,
        vulnerability_info: Dict[str, Any],
    ) -> ModelResponse:
        """Generate patch for vulnerability"""
        prompt = f"""Generate a security patch for this vulnerability:

Vulnerability Type: {vulnerability_info.get('type')}
Location: {vulnerability_info.get('location')}
Description: {vulnerability_info.get('description')}

Vulnerable code:
```
{vulnerability_info.get('code')}
```

Provide:
1. Fixed code
2. Explanation of changes
3. Why this fix works
4. Additional security measures to consider
5. Test cases to verify the fix
"""
        system_prompt = """You are a security expert creating patches.
Provide complete, production-ready fixes that fully address the vulnerability."""

        return await self.complete(prompt, system_prompt)

    def estimate_tokens(self, text: str) -> int:
        """Rough estimate of tokens in text"""
        # Simple heuristic: ~4 chars per token
        return len(text) // 4

    def truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate text to fit within token limit"""
        estimated_chars = max_tokens * 4
        if len(text) <= estimated_chars:
            return text
        return text[:estimated_chars] + "\n... (truncated)"
