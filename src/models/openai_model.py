"""OpenAI model implementation"""

import json
from typing import Optional, Dict, Any
import openai
from openai import AsyncOpenAI

from .base import BaseModel, ModelResponse


class OpenAIModel(BaseModel):
    """OpenAI GPT model implementation"""

    def __init__(
        self,
        api_key: str,
        model_name: str = "gpt-4-turbo-preview",
        temperature: float = 0.2,
    ):
        super().__init__(api_key, model_name, temperature)
        self.client = AsyncOpenAI(api_key=api_key)

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
    ) -> ModelResponse:
        """Generate completion from prompt"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        response = await self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=temperature or self.temperature,
            max_tokens=max_tokens,
        )

        choice = response.choices[0]

        return ModelResponse(
            content=choice.message.content or "",
            model=response.model,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
            finish_reason=choice.finish_reason or "stop",
            metadata={
                "id": response.id,
                "created": response.created,
            },
        )

    async def complete_structured(
        self,
        prompt: str,
        response_format: Dict[str, Any],
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate structured completion (JSON)"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # Add format instruction to prompt
        format_instruction = f"\n\nRespond ONLY with valid JSON matching this schema:\n{json.dumps(response_format, indent=2)}"
        messages.append({"role": "user", "content": prompt + format_instruction})

        response = await self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=self.temperature,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content or "{}"

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Fallback: try to extract JSON from markdown code blocks
            import re
            json_match = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            # Last resort: return empty structure
            return {}

    async def analyze_with_chain_of_thought(
        self,
        code: str,
        language: str,
    ) -> ModelResponse:
        """Analyze code using chain-of-thought prompting"""
        prompt = f"""Analyze this {language} code for security vulnerabilities using step-by-step reasoning.

Code:
```{language}
{code}
```

Follow these steps:

## Step 1: Code Understanding
- What does this code do?
- What are the inputs and outputs?
- What external resources does it interact with?

## Step 2: Attack Surface Analysis
- What are potential entry points for attackers?
- What user-controllable data exists?
- What security-sensitive operations are performed?

## Step 3: Vulnerability Detection
- Are there any memory safety issues?
- Are there any injection vulnerabilities?
- Are there any logic flaws?
- Are there any access control issues?

## Step 4: Exploitability Assessment
- How severe is each vulnerability?
- How difficult is it to exploit?
- What's the potential impact?

## Step 5: Summary
List all confirmed vulnerabilities with:
- Type and CWE ID
- Severity (Critical/High/Medium/Low)
- Line number(s)
- Brief description
- Exploitability assessment
"""
        system_prompt = """You are an expert security researcher.
Think step-by-step and be thorough in your analysis.
Only report real vulnerabilities with high confidence."""

        return await self.complete(prompt, system_prompt)

    async def verify_vulnerability(
        self,
        code: str,
        vulnerability: Dict[str, Any],
    ) -> bool:
        """Verify if a detected vulnerability is a true positive"""
        prompt = f"""Verify if this is a true vulnerability or a false positive.

Code:
```
{code}
```

Suspected vulnerability:
- Type: {vulnerability.get('type')}
- Location: Line {vulnerability.get('line')}
- Description: {vulnerability.get('description')}

Analyze:
1. Is this definitely exploitable?
2. Are there any mitigations in place?
3. Could this be a false positive? Why or why not?
4. What conditions are needed for exploitation?

Respond with: TRUE_POSITIVE or FALSE_POSITIVE, followed by reasoning.
"""
        system_prompt = "You are a careful security analyst. Be skeptical and thorough."

        response = await self.complete(prompt, system_prompt)
        return "TRUE_POSITIVE" in response.content.upper()
