"""
대화형 AI 어시스턴트 - VulnDetective 독창적 기능!
사용자와 대화하며 취약점을 설명하고 질문에 답변
"""

from typing import List, Optional
from ..models.base import BaseModel
from ..models.factory import ModelFactory
from ..detectors.vulnerability_detector import Vulnerability


class InteractiveAssistant:
    """대화형 AI 보안 어시스턴트"""

    def __init__(self, model: Optional[BaseModel] = None):
        self.model = model or ModelFactory.create_default_model()
        self.conversation_history = []

    async def explain_vulnerability(
        self,
        vulnerability: Vulnerability,
        user_level: str = "beginner"
    ) -> str:
        """
        취약점을 사용자 수준에 맞게 설명

        user_level: beginner, intermediate, expert
        """
        level_prompts = {
            'beginner': "초보자도 이해할 수 있도록 쉽게 설명해주세요. 비유를 사용하세요.",
            'intermediate': "프로그래밍 경험이 있는 개발자를 위해 설명해주세요.",
            'expert': "보안 전문가를 위한 상세한 기술적 설명을 제공해주세요."
        }

        prompt = f"""다음 취약점을 {level_prompts.get(user_level, level_prompts['beginner'])}

취약점 정보:
- 유형: {vulnerability.vuln_type}
- CWE: {vulnerability.cwe_id}
- 심각도: {vulnerability.severity.value}
- 위치: Line {vulnerability.line_number}

설명: {vulnerability.description}

코드:
```
{vulnerability.code_snippet}
```

다음 형식으로 설명해주세요:
1. 이 취약점이 무엇인가요?
2. 왜 위험한가요?
3. 실제 공격 시나리오는?
4. 어떻게 고쳐야 하나요?
"""

        response = await self.model.complete(
            prompt=prompt,
            system_prompt="당신은 친절한 보안 전문가입니다. 명확하고 이해하기 쉽게 설명합니다."
        )

        return response.content

    async def answer_question(
        self,
        question: str,
        vulnerabilities: List[Vulnerability],
        code: str
    ) -> str:
        """
        사용자 질문에 답변
        """
        context = f"""분석된 코드와 취약점 정보:

발견된 취약점:
"""
        for i, vuln in enumerate(vulnerabilities[:5], 1):
            context += f"\n{i}. {vuln.vuln_type} (Line {vuln.line_number}): {vuln.description}"

        context += f"\n\n코드 일부:\n```\n{code[:500]}...\n```"

        prompt = f"""{context}

사용자 질문: {question}

위 컨텍스트를 바탕으로 질문에 답변해주세요. 구체적이고 실용적인 답변을 제공하세요.
"""

        response = await self.model.complete(
            prompt=prompt,
            system_prompt="당신은 도움이 되는 보안 어시스턴트입니다."
        )

        return response.content

    async def suggest_next_steps(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """
        다음에 해야 할 조치 제안
        """
        if not vulnerabilities:
            return "✅ 취약점이 발견되지 않았습니다! 코드가 안전해 보입니다."

        critical_count = sum(1 for v in vulnerabilities if v.severity.value == 'Critical')
        high_count = sum(1 for v in vulnerabilities if v.severity.value == 'High')

        prompt = f"""다음 취약점들이 발견되었습니다:

총 {len(vulnerabilities)}개의 취약점
- Critical: {critical_count}개
- High: {high_count}개

상위 취약점:
"""
        for i, vuln in enumerate(vulnerabilities[:3], 1):
            prompt += f"{i}. {vuln.vuln_type} ({vuln.severity.value}) at line {vuln.line_number}\n"

        prompt += """
개발자가 우선적으로 해야 할 작업들을 단계별로 제안해주세요:
1. 즉시 조치 (24시간 이내)
2. 단기 조치 (1주일 이내)
3. 장기 개선 사항

각 단계별로 구체적인 액션 아이템을 제공하세요.
"""

        response = await self.model.complete(
            prompt=prompt,
            system_prompt="당신은 실용적인 조언을 제공하는 시니어 보안 엔지니어입니다."
        )

        return response.content

    async def generate_security_checklist(
        self,
        language: str,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """
        언어별 보안 체크리스트 생성
        """
        vuln_types = list(set(v.vuln_type for v in vulnerabilities))

        prompt = f"""{language} 프로젝트에서 다음 취약점들이 발견되었습니다:
{', '.join(vuln_types)}

이 프로젝트를 위한 맞춤형 보안 체크리스트를 생성해주세요:

1. 코드 리뷰 체크리스트
2. 테스트 체크리스트
3. 배포 전 체크리스트
4. 모니터링 체크리스트

각 항목은 실행 가능하고 구체적이어야 합니다.
"""

        response = await self.model.complete(
            prompt=prompt,
            system_prompt="당신은 DevSecOps 전문가입니다."
        )

        return response.content

    async def compare_with_best_practices(
        self,
        code: str,
        language: str
    ) -> str:
        """
        업계 베스트 프랙티스와 비교
        """
        prompt = f"""다음 {language} 코드를 업계 보안 베스트 프랙티스와 비교해주세요:

```{language}
{code[:1000]}
```

다음 관점에서 평가해주세요:
1. OWASP Top 10 준수도
2. 언어별 보안 가이드라인 (예: Python PEP, Java Secure Coding)
3. 산업 표준 (ISO 27001, NIST)
4. 개선 제안

각 항목에 점수(1-10)와 설명을 제공하세요.
"""

        response = await self.model.complete(
            prompt=prompt,
            system_prompt="당신은 보안 감사 전문가입니다."
        )

        return response.content
