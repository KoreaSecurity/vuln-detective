"""Patch generation module"""

from typing import Optional, List
from dataclasses import dataclass

from ..models.base import BaseModel
from ..models.factory import ModelFactory
from ..detectors.vulnerability_detector import Vulnerability


@dataclass
class Patch:
    """Generated patch code and documentation"""
    vulnerability: Vulnerability
    strategy: str
    original_code: str
    patched_code: str
    explanation: str
    test_cases: str
    additional_measures: str


class PatchGenerator:
    """Generate security patches for vulnerabilities"""

    def __init__(self, model: Optional[BaseModel] = None):
        self.model = model or ModelFactory.create_advanced_model()

    async def generate(self, vulnerability: Vulnerability, full_code: str) -> Optional[Patch]:
        """Generate patch for a vulnerability"""

        # Extract context around the vulnerability
        context = self._extract_context(full_code, vulnerability.line_number)

        prompt = f"""Generate a security patch for this vulnerability:

**Vulnerability Details:**
- Type: {vulnerability.vuln_type}
- CWE: {vulnerability.cwe_id}
- Severity: {vulnerability.severity.value}
- Location: Line {vulnerability.line_number}
- Description: {vulnerability.description}

**Vulnerable Code:**
```
{context}
```

**Recommendation:**
{vulnerability.recommendation}

**Task:**
Create a complete, production-ready security patch.

Provide:
1. **Patch Strategy** - Your approach to fixing this
2. **Original Code** - The vulnerable code
3. **Patched Code** - The fixed code (complete, not just diff)
4. **Explanation** - Why this fix works
5. **Test Cases** - How to verify the fix
6. **Additional Measures** - Defense-in-depth recommendations

Format as:
## Patch Strategy
[strategy]

## Original Code
```
[original]
```

## Patched Code
```
[patched]
```

## Explanation
[explanation]

## Test Cases
```
[test cases]
```

## Additional Security Measures
[additional measures]
"""

        system_prompt = """You are a security expert creating production-ready patches.
Your patches should:
- Completely fix the vulnerability
- Maintain existing functionality
- Follow coding best practices
- Be thoroughly tested
- Include proper error handling
- Consider defense-in-depth"""

        try:
            response = await self.model.complete(prompt, system_prompt)
            return self._parse_patch(response.content, vulnerability, context)
        except Exception as e:
            print(f"Error generating patch: {e}")
            return None

    def _extract_context(self, code: str, line_number: int, context_lines: int = 10) -> str:
        """Extract code context around vulnerability"""
        lines = code.split('\n')
        start = max(0, line_number - context_lines)
        end = min(len(lines), line_number + context_lines)

        context_code = '\n'.join(lines[start:end])
        return context_code

    def _parse_patch(self, response: str, vuln: Vulnerability, original: str) -> Patch:
        """Parse patch from AI response"""
        sections = {
            'strategy': '',
            'original': '',
            'patched': '',
            'explanation': '',
            'tests': '',
            'additional': ''
        }

        current_section = None
        in_code_block = False
        code_lines = []
        code_section = None

        for line in response.split('\n'):
            line_lower = line.lower().strip()

            # Detect section headers
            if '## patch strategy' in line_lower or '## strategy' in line_lower:
                current_section = 'strategy'
                continue
            elif '## original code' in line_lower or '## original' in line_lower:
                current_section = 'original'
                code_section = 'original'
                code_lines = []
                continue
            elif '## patched code' in line_lower or '## patched' in line_lower or '## fixed code' in line_lower:
                if code_lines and code_section:
                    sections[code_section] = '\n'.join(code_lines)
                current_section = 'patched'
                code_section = 'patched'
                code_lines = []
                continue
            elif '## explanation' in line_lower:
                if code_lines and code_section:
                    sections[code_section] = '\n'.join(code_lines)
                    code_lines = []
                    code_section = None
                current_section = 'explanation'
                continue
            elif '## test cases' in line_lower or '## test' in line_lower:
                current_section = 'tests'
                code_section = 'tests'
                code_lines = []
                continue
            elif '## additional' in line_lower:
                if code_lines and code_section:
                    sections[code_section] = '\n'.join(code_lines)
                    code_lines = []
                    code_section = None
                current_section = 'additional'
                continue

            # Handle code blocks
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue

            # Add content to appropriate section
            if current_section:
                if current_section in ['original', 'patched', 'tests']:
                    if in_code_block or code_section:
                        code_lines.append(line)
                else:
                    sections[current_section] += line + '\n'

        # Capture any remaining code
        if code_lines and code_section:
            sections[code_section] = '\n'.join(code_lines)

        return Patch(
            vulnerability=vuln,
            strategy=sections['strategy'].strip(),
            original_code=sections['original'].strip() or original,
            patched_code=sections['patched'].strip(),
            explanation=sections['explanation'].strip(),
            test_cases=sections['tests'].strip(),
            additional_measures=sections['additional'].strip(),
        )

    async def generate_comprehensive_patch(
        self,
        vulnerabilities: List[Vulnerability],
        full_code: str,
    ) -> List[Patch]:
        """Generate patches for multiple vulnerabilities"""
        patches = []

        for vuln in vulnerabilities:
            patch = await self.generate(vuln, full_code)
            if patch:
                patches.append(patch)

        return patches

    async def validate_patch(self, patch: Patch, full_code: str) -> bool:
        """Validate that a patch actually fixes the vulnerability"""

        prompt = f"""Validate this security patch:

**Vulnerability:**
{patch.vulnerability.description}

**Original Code:**
```
{patch.original_code}
```

**Patched Code:**
```
{patch.patched_code}
```

**Questions:**
1. Does this patch completely fix the vulnerability?
2. Does it maintain existing functionality?
3. Does it introduce any new vulnerabilities?
4. Are there any edge cases not covered?

Answer: VALID or INVALID
Then provide brief reasoning.
"""

        try:
            response = await self.model.complete(prompt)
            return "VALID" in response.content.upper() and "INVALID" not in response.content.upper()
        except Exception:
            return False
