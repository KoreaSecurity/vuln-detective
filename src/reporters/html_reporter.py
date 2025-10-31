"""Advanced HTML report generator with visualizations"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from jinja2 import Template

from ..detectors.vulnerability_detector import Vulnerability
from ..generators.exploit_generator import Exploit
from ..generators.patch_generator import Patch


# 고급 HTML 템플릿 with Chart.js
ADVANCED_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnDetective Report - {{ filename }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #667eea;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #fff;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: #667eea;
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .header .subtitle {
            opacity: 0.9;
            font-size: 1.2em;
        }
        .header .badge {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 8px 16px;
            border-radius: 20px;
            margin: 10px 5px;
            font-size: 0.9em;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.2);
        }
        .stat-card .number {
            font-size: 3em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        .stat-card .label {
            color: #666;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .chart-section {
            padding: 30px;
            background: white;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin-bottom: 30px;
        }
        .section {
            padding: 30px;
            border-top: 1px solid #eee;
        }
        .section h2 {
            color: #667eea;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
            font-size: 2em;
        }
        .vulnerability {
            border-left: 5px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            background: #f9f9f9;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: all 0.3s;
        }
        .vulnerability:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateX(5px);
        }
        .vulnerability.critical { border-left-color: #dc2626; }
        .vulnerability.high { border-left-color: #ea580c; }
        .vulnerability.medium { border-left-color: #facc15; }
        .vulnerability.low { border-left-color: #3b82f6; }
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .vulnerability-title {
            font-size: 1.4em;
            font-weight: bold;
            color: #333;
        }
        .severity-badge {
            padding: 8px 20px;
            border-radius: 25px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        .severity-critical { background: #dc2626; }
        .severity-high { background: #ea580c; }
        .severity-medium { background: #facc15; color: #333; }
        .severity-low { background: #3b82f6; }
        .vulnerability-meta {
            display: flex;
            gap: 20px;
            color: #666;
            font-size: 0.95em;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        .meta-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .meta-item .icon {
            font-weight: bold;
        }
        .cvss-score {
            display: inline-block;
            padding: 5px 12px;
            background: #667eea;
            color: white;
            border-radius: 15px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .risk-score {
            display: inline-block;
            padding: 5px 12px;
            background: #dc2626;
            color: white;
            border-radius: 15px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .code-block {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 15px 0;
            font-family: 'Courier New', Consolas, monospace;
            font-size: 0.9em;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }
        .code-block pre {
            margin: 0;
        }
        .exploit, .patch {
            margin-top: 25px;
            padding: 20px;
            background: #f0f9ff;
            border-radius: 10px;
            border: 2px solid #bae6fd;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .exploit h3, .patch h3 {
            color: #0c4a6e;
            margin-bottom: 15px;
        }
        .patch {
            background: #f0fdf4;
            border-color: #bbf7d0;
        }
        .patch h3 {
            color: #14532d;
        }
        .footer {
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            color: #666;
            font-size: 0.95em;
        }
        .confidence-bar {
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }
        .confidence-fill {
            height: 100%;
            background: #667eea;
            transition: width 0.5s ease;
            border-radius: 4px;
        }
        .timeline {
            position: relative;
            padding-left: 30px;
            margin-top: 20px;
        }
        .timeline::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 3px;
            background: #667eea;
        }
        .timeline-item {
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        @media print {
            .container { box-shadow: none; }
            .vulnerability:hover { transform: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 VulnDetective Report</h1>
            <div class="subtitle">
                Advanced AI-Powered Security Analysis
            </div>
            <div style="margin-top: 20px;">
                <span class="badge">📁 {{ filename }}</span>
                <span class="badge">📅 {{ timestamp }}</span>
                <span class="badge">💻 {{ language }}</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{{ total_vulns }}</div>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #dc2626;">{{ critical_count }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color: #ea580c;">{{ high_count }}</div>
                <div class="label">High Severity</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ avg_cvss }}</div>
                <div class="label">Avg CVSS Score</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ exploits_count }}</div>
                <div class="label">Exploits Generated</div>
            </div>
            <div class="stat-card">
                <div class="number">{{ patches_count }}</div>
                <div class="label">Patches Available</div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="chart-section">
            <h2>📊 Visual Analytics</h2>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px;">
                <div>
                    <h3 style="text-align: center; margin-bottom: 15px;">Severity Distribution</h3>
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                <div>
                    <h3 style="text-align: center; margin-bottom: 15px;">Vulnerability Types</h3>
                    <div class="chart-container">
                        <canvas id="typeChart"></canvas>
                    </div>
                </div>
            </div>

            <div style="margin-bottom: 30px;">
                <h3 style="text-align: center; margin-bottom: 15px;">CVSS Score Distribution</h3>
                <div class="chart-container">
                    <canvas id="cvssChart"></canvas>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>⚠️ Detected Vulnerabilities</h2>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability {{ vuln.severity.value.lower() }}">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">{{ loop.index }}. {{ vuln.vuln_type }}</div>
                    <span class="severity-badge severity-{{ vuln.severity.value.lower() }}">
                        {{ vuln.severity.value }}
                    </span>
                </div>

                <div class="vulnerability-meta">
                    <div class="meta-item">
                        <span class="icon">📍</span>
                        <span>Line {{ vuln.line_number }}</span>
                    </div>
                    <div class="meta-item">
                        <span class="icon">🔖</span>
                        <span>{{ vuln.cwe_id }}</span>
                    </div>
                    <div class="meta-item">
                        <span class="icon">🎯</span>
                        <span>Confidence: {{ "%.0f"|format(vuln.confidence * 100) }}%</span>
                    </div>
                    {% if vuln.metadata and vuln.metadata.cvss %}
                    <div class="meta-item">
                        <span class="cvss-score">CVSS: {{ "%.1f"|format(vuln.metadata.cvss.base_score) }}</span>
                    </div>
                    {% endif %}
                    {% if vuln.metadata and vuln.metadata.risk_score %}
                    <div class="meta-item">
                        <span class="risk-score">Risk: {{ "%.1f"|format(vuln.metadata.risk_score) }}</span>
                    </div>
                    {% endif %}
                </div>

                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: {{ vuln.confidence * 100 }}%"></div>
                </div>

                <p style="margin: 15px 0;"><strong>📝 Description:</strong> {{ vuln.description }}</p>

                {% if vuln.code_snippet %}
                <p style="margin-top: 15px;"><strong>💻 Vulnerable Code:</strong></p>
                <div class="code-block"><pre>{{ vuln.code_snippet }}</pre></div>
                {% endif %}

                <p style="margin-top: 15px;"><strong>💣 Exploitability:</strong> {{ vuln.exploitability }}</p>
                <p style="margin-top: 10px;"><strong>✅ Recommendation:</strong> {{ vuln.recommendation }}</p>

                {% if vuln.metadata and vuln.metadata.cvss %}
                <details style="margin-top: 15px;">
                    <summary style="cursor: pointer; color: #667eea; font-weight: bold;">🔬 CVSS Details</summary>
                    <div style="margin-top: 10px; padding: 10px; background: #f0f9ff; border-radius: 5px;">
                        <p><strong>Vector String:</strong> {{ vuln.metadata.cvss.vector_string }}</p>
                        <p><strong>Exploitability:</strong> {{ vuln.metadata.cvss.exploitability }}</p>
                        <p><strong>Impact:</strong> {{ vuln.metadata.cvss.impact }}</p>
                        <p><strong>Attack Vector:</strong> {{ vuln.metadata.cvss.metrics.attack_vector }}</p>
                        <p><strong>Attack Complexity:</strong> {{ vuln.metadata.cvss.metrics.attack_complexity }}</p>
                    </div>
                </details>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        {% if exploits %}
        <div class="section">
            <h2>💣 Generated Exploits</h2>
            {% for exploit in exploits %}
            <div class="exploit">
                <h3>Exploit for {{ exploit.vulnerability.vuln_type }}</h3>

                <div class="timeline">
                    <div class="timeline-item">
                        <strong>📋 Strategy:</strong>
                        <p>{{ exploit.strategy }}</p>
                    </div>
                    <div class="timeline-item">
                        <strong>📦 Requirements:</strong>
                        <p>{{ exploit.requirements }}</p>
                    </div>
                    <div class="timeline-item">
                        <strong>🎯 Expected Outcome:</strong>
                        <p>{{ exploit.expected_outcome }}</p>
                    </div>
                </div>

                <p style="margin-top: 15px;"><strong>💻 Exploit Code:</strong></p>
                <div class="code-block"><pre>{{ exploit.code }}</pre></div>

                {% if exploit.notes %}
                <p style="margin-top: 15px;"><strong>📌 Notes:</strong> {{ exploit.notes }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if patches %}
        <div class="section">
            <h2>🔧 Generated Patches</h2>
            {% for patch in patches %}
            <div class="patch">
                <h3>Patch for {{ patch.vulnerability.vuln_type }}</h3>

                <p><strong>🎯 Strategy:</strong> {{ patch.strategy }}</p>

                <p style="margin-top: 15px;"><strong>❌ Original Code:</strong></p>
                <div class="code-block"><pre>{{ patch.original_code }}</pre></div>

                <p style="margin-top: 15px;"><strong>✅ Patched Code:</strong></p>
                <div class="code-block"><pre>{{ patch.patched_code }}</pre></div>

                <p style="margin-top: 15px;"><strong>📖 Explanation:</strong> {{ patch.explanation }}</p>

                {% if patch.test_cases %}
                <p style="margin-top: 15px;"><strong>🧪 Test Cases:</strong></p>
                <div class="code-block"><pre>{{ patch.test_cases }}</pre></div>
                {% endif %}

                {% if patch.additional_measures %}
                <p style="margin-top: 15px;"><strong>🛡️ Additional Security Measures:</strong> {{ patch.additional_measures }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <div class="footer">
            <p style="font-size: 1.1em; margin-bottom: 10px;">
                <strong>Generated by VulnDetective</strong> - AI-Powered Vulnerability Detection System
            </p>
            <p style="margin-bottom: 10px;">
                Featuring: GitHub URL Fetching • CVSS 3.1 Scoring • Interactive AI Assistant • Advanced Visualization
            </p>
            <p style="color: #999;">
                © 2025 VulnDetective Team | Report generated on {{ timestamp }}
            </p>
        </div>
    </div>

    <script>
        // Chart.js 차트 생성
        const severityData = {{ severity_data | tojson }};
        const typeData = {{ type_data | tojson }};
        const cvssData = {{ cvss_data | tojson }};

        // Severity Distribution Chart
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: severityData.labels,
                datasets: [{
                    data: severityData.values,
                    backgroundColor: [
                        '#dc2626',  // Critical
                        '#ea580c',  // High
                        '#facc15',  // Medium
                        '#3b82f6',  // Low
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { font: { size: 12 } }
                    }
                }
            }
        });

        // Vulnerability Types Chart
        new Chart(document.getElementById('typeChart'), {
            type: 'bar',
            data: {
                labels: typeData.labels,
                datasets: [{
                    label: 'Count',
                    data: typeData.values,
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                }
            }
        });

        // CVSS Distribution Chart
        new Chart(document.getElementById('cvssChart'), {
            type: 'line',
            data: {
                labels: cvssData.labels,
                datasets: [{
                    label: 'CVSS Score',
                    data: cvssData.values,
                    borderColor: 'rgba(102, 126, 234, 1)',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 5,
                    pointBackgroundColor: 'rgba(102, 126, 234, 1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 10
                    }
                }
            }
        });
    </script>
</body>
</html>
"""


class AdvancedHTMLReporter:
    """고급 HTML 리포터 with 차트와 시각화"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(
        self,
        file_path: str,
        code: str,
        language: str,
        vulnerabilities: List[Vulnerability],
        exploits: Optional[List[Exploit]] = None,
        patches: Optional[List[Patch]] = None,
    ) -> Path:
        """고급 HTML 리포트 생성"""

        exploits = exploits or []
        patches = patches or []

        # 통계 계산
        severity_counts = {
            'critical': sum(1 for v in vulnerabilities if v.severity.value == 'Critical'),
            'high': sum(1 for v in vulnerabilities if v.severity.value == 'High'),
            'medium': sum(1 for v in vulnerabilities if v.severity.value == 'Medium'),
            'low': sum(1 for v in vulnerabilities if v.severity.value == 'Low'),
        }

        # CVSS 평균 계산
        cvss_scores = [v.metadata.get('cvss', {}).get('base_score', 0) for v in vulnerabilities if v.metadata and 'cvss' in v.metadata]
        avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0

        # 차트 데이터 준비
        severity_data = {
            'labels': ['Critical', 'High', 'Medium', 'Low'],
            'values': [
                severity_counts['critical'],
                severity_counts['high'],
                severity_counts['medium'],
                severity_counts['low']
            ]
        }

        # 취약점 타입별 카운트
        type_counts = {}
        for v in vulnerabilities:
            type_counts[v.vuln_type] = type_counts.get(v.vuln_type, 0) + 1

        type_data = {
            'labels': list(type_counts.keys()),
            'values': list(type_counts.values())
        }

        # CVSS 스코어 분포
        cvss_data = {
            'labels': [f"Vuln {i+1}" for i in range(len(vulnerabilities))],
            'values': [v.metadata.get('cvss', {}).get('base_score', 0) if v.metadata else 0 for v in vulnerabilities]
        }

        # 템플릿 데이터
        template_data = {
            'filename': file_path,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'language': language,
            'total_vulns': len(vulnerabilities),
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'avg_cvss': avg_cvss,
            'exploits_count': len(exploits),
            'patches_count': len(patches),
            'vulnerabilities': vulnerabilities,
            'exploits': exploits,
            'patches': patches,
            'severity_data': severity_data,
            'type_data': type_data,
            'cvss_data': cvss_data,
        }

        # 렌더링
        template = Template(ADVANCED_HTML_TEMPLATE)
        html_content = template.render(**template_data)

        # 저장
        report_filename = f"report_{Path(file_path).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = self.output_dir / report_filename

        report_path.write_text(html_content, encoding='utf-8')

        # JSON 저장
        await self._save_json_report(report_path.with_suffix('.json'), template_data)

        return report_path

    async def _save_json_report(self, path: Path, data: dict):
        """JSON 형식 리포트 저장"""
        json_data = {
            'filename': data['filename'],
            'timestamp': data['timestamp'],
            'language': data['language'],
            'statistics': {
                'total_vulnerabilities': data['total_vulns'],
                'critical': data['critical_count'],
                'high': data['high_count'],
                'average_cvss': data['avg_cvss'],
                'exploits_generated': data['exploits_count'],
                'patches_generated': data['patches_count'],
            },
            'vulnerabilities': [v.to_dict() for v in data['vulnerabilities']],
        }

        path.write_text(json.dumps(json_data, indent=2), encoding='utf-8')


# 하위 호환성을 위한 별칭
HTMLReporter = AdvancedHTMLReporter
