"""
CVSS 3.1 자동 스코어링 시스템 - VulnDetective 독창적 기능!
취약점 정보를 기반으로 CVSS 점수를 자동 계산
"""

from enum import Enum
from typing import Dict
from ..detectors.vulnerability_detector import Vulnerability, VulnerabilitySeverity


class AttackVector(Enum):
    NETWORK = ("N", 0.85)
    ADJACENT = ("A", 0.62)
    LOCAL = ("L", 0.55)
    PHYSICAL = ("P", 0.2)


class AttackComplexity(Enum):
    LOW = ("L", 0.77)
    HIGH = ("H", 0.44)


class PrivilegesRequired(Enum):
    NONE = ("N", 0.85)
    LOW = ("L", 0.62)
    HIGH = ("H", 0.27)


class UserInteraction(Enum):
    NONE = ("N", 0.85)
    REQUIRED = ("R", 0.62)


class Impact(Enum):
    HIGH = ("H", 0.56)
    LOW = ("L", 0.22)
    NONE = ("N", 0.0)


class CVSSCalculator:
    """CVSS 3.1 점수 자동 계산"""

    def __init__(self):
        # 취약점 타입별 기본 메트릭
        self.vuln_metrics = {
            'SQL Injection': {
                'AV': AttackVector.NETWORK,
                'AC': AttackComplexity.LOW,
                'PR': PrivilegesRequired.NONE,
                'UI': UserInteraction.NONE,
                'C': Impact.HIGH,
                'I': Impact.HIGH,
                'A': Impact.LOW,
            },
            'Command Injection': {
                'AV': AttackVector.NETWORK,
                'AC': AttackComplexity.LOW,
                'PR': PrivilegesRequired.LOW,
                'UI': UserInteraction.NONE,
                'C': Impact.HIGH,
                'I': Impact.HIGH,
                'A': Impact.HIGH,
            },
            'Buffer Overflow': {
                'AV': AttackVector.LOCAL,
                'AC': AttackComplexity.LOW,
                'PR': PrivilegesRequired.NONE,
                'UI': UserInteraction.REQUIRED,
                'C': Impact.HIGH,
                'I': Impact.HIGH,
                'A': Impact.HIGH,
            },
            'XSS': {
                'AV': AttackVector.NETWORK,
                'AC': AttackComplexity.LOW,
                'PR': PrivilegesRequired.NONE,
                'UI': UserInteraction.REQUIRED,
                'C': Impact.LOW,
                'I': Impact.LOW,
                'A': Impact.NONE,
            },
            'Path Traversal': {
                'AV': AttackVector.NETWORK,
                'AC': AttackComplexity.LOW,
                'PR': PrivilegesRequired.NONE,
                'UI': UserInteraction.NONE,
                'C': Impact.HIGH,
                'I': Impact.NONE,
                'A': Impact.NONE,
            },
        }

    def calculate(self, vulnerability: Vulnerability) -> Dict:
        """취약점의 CVSS 점수 계산"""

        # 취약점 타입에 따른 기본 메트릭
        vuln_type = vulnerability.vuln_type
        metrics = self.vuln_metrics.get(vuln_type, {
            'AV': AttackVector.NETWORK,
            'AC': AttackComplexity.LOW,
            'PR': PrivilegesRequired.LOW,
            'UI': UserInteraction.NONE,
            'C': Impact.LOW,
            'I': Impact.LOW,
            'A': Impact.NONE,
        })

        # Exploitability Sub-Score 계산
        exploitability = (
            8.22 *
            metrics['AV'].value[1] *
            metrics['AC'].value[1] *
            metrics['PR'].value[1] *
            metrics['UI'].value[1]
        )

        # Impact Sub-Score 계산
        impact_base = 1 - (
            (1 - metrics['C'].value[1]) *
            (1 - metrics['I'].value[1]) *
            (1 - metrics['A'].value[1])
        )

        if impact_base == 0:
            impact = 0
        else:
            impact = 6.42 * impact_base

        # Base Score 계산
        if impact <= 0:
            base_score = 0
        else:
            base_score = min(10.0, (impact + exploitability))

        # 반올림
        base_score = round(base_score * 10) / 10

        # Severity 결정
        if base_score == 0:
            severity = "None"
        elif base_score < 4.0:
            severity = "Low"
        elif base_score < 7.0:
            severity = "Medium"
        elif base_score < 9.0:
            severity = "High"
        else:
            severity = "Critical"

        # CVSS Vector String 생성
        vector_string = (
            f"CVSS:3.1/"
            f"AV:{metrics['AV'].value[0]}/"
            f"AC:{metrics['AC'].value[0]}/"
            f"PR:{metrics['PR'].value[0]}/"
            f"UI:{metrics['UI'].value[0]}/"
            f"S:U/"  # Scope는 기본값 Unchanged
            f"C:{metrics['C'].value[0]}/"
            f"I:{metrics['I'].value[0]}/"
            f"A:{metrics['A'].value[0]}"
        )

        return {
            'base_score': base_score,
            'severity': severity,
            'exploitability': round(exploitability, 1),
            'impact': round(impact, 1),
            'vector_string': vector_string,
            'metrics': {
                'attack_vector': metrics['AV'].name,
                'attack_complexity': metrics['AC'].name,
                'privileges_required': metrics['PR'].name,
                'user_interaction': metrics['UI'].name,
                'confidentiality': metrics['C'].name,
                'integrity': metrics['I'].name,
                'availability': metrics['A'].name,
            }
        }

    def calculate_risk_score(self, vulnerability: Vulnerability) -> float:
        """
        종합 위험 점수 계산 (VulnDetective 독창적 메트릭)

        CVSS + 신뢰도 + 익스플로잇 가능성을 종합
        """
        cvss_data = self.calculate(vulnerability)
        base_score = cvss_data['base_score']

        # 신뢰도 가중치
        confidence_weight = vulnerability.confidence

        # 익스플로잇 키워드 분석
        exploit_keywords = ['easy', 'trivial', 'simple', 'straightforward']
        exploitability_bonus = 0
        if vulnerability.exploitability:
            text = vulnerability.exploitability.lower()
            if any(keyword in text for keyword in exploit_keywords):
                exploitability_bonus = 1.0

        # 종합 위험 점수 = CVSS * 신뢰도 + 익스플로잇 보너스
        risk_score = (base_score * confidence_weight) + exploitability_bonus

        return round(min(10.0, risk_score), 1)
