"""VulnDetective CLI 인터페이스"""

import asyncio
import sys
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm

from .config import Config, set_config
from .detectors.vulnerability_detector import VulnerabilityDetector
from .generators.exploit_generator import ExploitGenerator
from .generators.patch_generator import PatchGenerator
from .reporters.html_reporter import AdvancedHTMLReporter
from .analyzers.code_fetcher import CodeFetcher
from .utils.cvss import CVSSCalculator
from .utils.interactive_assistant import InteractiveAssistant


console = Console()


@click.group()
@click.option('--config', type=click.Path(exists=True), help='Config file path')
@click.option('--debug/--no-debug', default=False, help='Enable debug mode')
def cli(config: Optional[str], debug: bool):
    """
    VulnDetective - AI 기반 취약점 탐지 시스템

    주요 기능:
    - GitHub/URL에서 직접 코드 다운로드
    - CVSS 3.1 자동 스코어링
    - 대화형 AI 어시스턴트
    - 고급 시각화 리포트
    """
    cfg = Config.from_env(Path(config) if config else None)
    cfg.debug = debug
    set_config(cfg)


@cli.command()
@click.argument('target')
@click.option('--language', '-l', help='Programming language')
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--generate-exploits/--no-exploits', default=False, help='Generate exploits')
@click.option('--generate-patches/--no-patches', default=True, help='Generate patches')
@click.option('--interactive/--no-interactive', default=False, help='Interactive mode with AI assistant')
def analyze(
    target: str,
    language: Optional[str],
    output: Optional[str],
    generate_exploits: bool,
    generate_patches: bool,
    interactive: bool,
):
    """
    소스코드 취약점 분석

    TARGET 종류:
    - 로컬 파일 경로: ./mycode.py
    - GitHub URL: https://github.com/user/repo/blob/main/file.py
    - Gist URL: https://gist.github.com/user/gist_id
    - 기타 URL: https://example.com/code.py
    """
    asyncio.run(_analyze(target, language, output, generate_exploits, generate_patches, interactive))


async def _analyze(
    target: str,
    language: Optional[str],
    output: Optional[str],
    generate_exploits: bool,
    generate_patches: bool,
    interactive: bool,
):
    """비동기 분석 실행용"""

    # URL에서 코드 다운로드
    if CodeFetcher.is_url(target):
        console.print(f"\n[cyan]URL에서 코드 다운로드 중...[/cyan]")
        try:
            code, filename, detected_lang = CodeFetcher.fetch(target)
            language = language or detected_lang
            console.print(f"[green]다운로드 완료: {filename}[/green]")
        except Exception as e:
            console.print(f"[red]다운로드 실패: {e}[/red]")
            sys.exit(1)
        file_path_obj = Path(filename)
    else:
        # 로컬 파일
        file_path_obj = Path(target)
        try:
            code = file_path_obj.read_text(encoding='utf-8')
            filename = file_path_obj.name
        except Exception as e:
            console.print(f"[red]파일 읽기 오류: {e}[/red]")
            sys.exit(1)

    # 언어 자동 탐지
    if not language:
        language = _detect_language(file_path_obj)

    console.print(Panel.fit(
        f"[bold cyan]VulnDetective 분석[/bold cyan]\n"
        f"대상: {target}\n"
        f"언어: {language}\n"
        f"크기: {len(code)} bytes\n"
        f"라인 수: {len(code.splitlines())}",
        border_style="cyan",
        title="[bold]분석 시작[/bold]"
    ))

    # 컴포넌트 초기화
    detector = VulnerabilityDetector()
    cvss_calculator = CVSSCalculator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        # 취약점 탐지
        task1 = progress.add_task("[cyan]취약점 탐지 중...", total=None)
        vulnerabilities = await detector.detect(code, language, str(file_path_obj))
        progress.update(task1, completed=True)

        if not vulnerabilities:
            console.print("\n[green]취약점이 발견되지 않았습니다. 코드가 안전해 보입니다.[/green]")

            if interactive:
                assistant = InteractiveAssistant()
                console.print("\n[cyan]AI 어시스턴트:[/cyan]")
                best_practices = await assistant.compare_with_best_practices(code, language)
                console.print(Panel(best_practices, title="보안 모범 사례 검토", border_style="green"))

            return

        # CVSS 자동 스코어링
        console.print("\n[cyan]CVSS 점수 계산 중...[/cyan]")
        for vuln in vulnerabilities:
            vuln.metadata = vuln.metadata or {}
            vuln.metadata['cvss'] = cvss_calculator.calculate(vuln)
            vuln.metadata['risk_score'] = cvss_calculator.calculate_risk_score(vuln)

        # 취약점 출력
        console.print(f"\n[yellow]{len(vulnerabilities)}개의 잠재적 취약점 발견:[/yellow]\n")

        table = Table(show_header=True, header_style="bold magenta", title="취약점 요약")
        table.add_column("#", style="dim", width=3)
        table.add_column("유형", min_width=15)
        table.add_column("심각도", min_width=8)
        table.add_column("라인", width=5)
        table.add_column("CVSS", width=6)
        table.add_column("위험도", width=6)
        table.add_column("신뢰도", width=10)

        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = {
                "Critical": "red",
                "High": "red",
                "Medium": "yellow",
                "Low": "blue",
                "Info": "dim"
            }.get(vuln.severity.value, "white")

            cvss_score = vuln.metadata.get('cvss', {}).get('base_score', 0)
            risk_score = vuln.metadata.get('risk_score', 0)

            table.add_row(
                str(i),
                vuln.vuln_type,
                f"[{severity_color}]{vuln.severity.value}[/{severity_color}]",
                str(vuln.line_number),
                f"[bold]{cvss_score:.1f}[/bold]",
                f"[bold red]{risk_score:.1f}[/bold red]" if risk_score >= 8 else f"{risk_score:.1f}",
                f"{vuln.confidence:.0%}"
            )

        console.print(table)

        # 익스플로잇 생성
        exploits = []
        if generate_exploits:
            task2 = progress.add_task("[cyan]익스플로잇 생성 중...", total=len(vulnerabilities))
            exploit_gen = ExploitGenerator()

            for vuln in vulnerabilities[:5]:  # 상위 5개로 제한
                exploit = await exploit_gen.generate(vuln)
                if exploit:
                    exploits.append(exploit)
                progress.advance(task2)

            console.print(f"\n[green]{len(exploits)}개의 익스플로잇 생성 완료[/green]")

        # 패치 생성
        patches = []
        if generate_patches:
            task3 = progress.add_task("[cyan]패치 생성 중...", total=len(vulnerabilities))
            patch_gen = PatchGenerator()

            for vuln in vulnerabilities:
                patch = await patch_gen.generate(vuln, code)
                if patch:
                    patches.append(patch)
                progress.advance(task3)

            console.print(f"\n[green]{len(patches)}개의 패치 생성 완료[/green]")

    # 대화형 AI 어시스턴트
    if interactive:
        console.print("\n" + "="*60)
        console.print("[bold cyan]대화형 AI 보안 어시스턴트[/bold cyan]")
        console.print("="*60 + "\n")

        assistant = InteractiveAssistant()

        # 다음 단계 자동 제안
        console.print("[cyan]다음 단계 분석 및 제안 중...[/cyan]\n")
        suggestions = await assistant.suggest_next_steps(vulnerabilities)
        console.print(Panel(suggestions, title="권장 조치사항", border_style="green"))

        # 사용자 질문 받기
        while True:
            console.print("\n[dim]옵션:[/dim]")
            console.print("  [cyan]1[/cyan] - 특정 취약점 설명")
            console.print("  [cyan]2[/cyan] - 질문하기")
            console.print("  [cyan]3[/cyan] - 보안 체크리스트 생성")
            console.print("  [cyan]q[/cyan] - 보고서 생성 계속\n")

            choice = Prompt.ask("선택", choices=["1", "2", "3", "q"], default="q")

            if choice == "q":
                break
            elif choice == "1":
                vuln_num = Prompt.ask("어떤 취약점? (1-" + str(len(vulnerabilities)) + ")")
                try:
                    vuln_idx = int(vuln_num) - 1
                    if 0 <= vuln_idx < len(vulnerabilities):
                        level = Prompt.ask("설명 레벨", choices=["beginner", "intermediate", "expert"], default="intermediate")
                        explanation = await assistant.explain_vulnerability(vulnerabilities[vuln_idx], level)
                        console.print(Panel(explanation, title=f"취약점 #{vuln_num} 설명", border_style="blue"))
                except ValueError:
                    console.print("[red]잘못된 번호입니다[/red]")
            elif choice == "2":
                question = Prompt.ask("질문 내용")
                answer = await assistant.answer_question(question, vulnerabilities, code)
                console.print(Panel(answer, title="AI 답변", border_style="blue"))
            elif choice == "3":
                checklist = await assistant.generate_security_checklist(language, vulnerabilities)
                console.print(Panel(checklist, title="보안 체크리스트", border_style="green"))

    # 보고서 생성
    output_dir = Path(output) if output else Path("./output")
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[cyan]고급 보고서 생성 중...[/cyan]")
    reporter = AdvancedHTMLReporter(output_dir)
    report_path = await reporter.generate(
        file_path=str(target),
        code=code,
        language=language,
        vulnerabilities=vulnerabilities,
        exploits=exploits,
        patches=patches,
    )

    console.print(f"\n[bold green]분석 완료![/bold green]")
    console.print(f"보고서 저장 위치: [cyan]{report_path}[/cyan]")
    console.print(f"JSON 데이터 저장 위치: [cyan]{report_path.with_suffix('.json')}[/cyan]")


@cli.command()
@click.argument('url')
def fetch(url: str):
    """
    URL에서 코드 다운로드 후 로컬 저장

    지원:
    - GitHub
    - Gist
    - Pastebin
    - 직접 URL
    """
    console.print(f"\n[cyan]다운로드 중: {url}[/cyan]")

    try:
        code, filename, language = CodeFetcher.fetch(url)

        output_path = Path(filename)
        output_path.write_text(code, encoding='utf-8')

        console.print(f"\n[green]다운로드 성공![/green]")
        console.print(f"파일: [cyan]{output_path}[/cyan]")
        console.print(f"언어: [cyan]{language}[/cyan]")
        console.print(f"크기: [cyan]{len(code)} bytes[/cyan]")

    except Exception as e:
        console.print(f"\n[red]다운로드 실패: {e}[/red]")
        sys.exit(1)


@cli.command()
def version():
    """버전 정보 표시"""
    from . import __version__, __author__

    console.print(Panel.fit(
        f"[bold cyan]VulnDetective[/bold cyan] version {__version__}\n"
        f"By {__author__}\n\n"
        f"[dim]주요 기능:[/dim]\n"
        f"  - GitHub/URL 코드 가져오기\n"
        f"  - CVSS 3.1 자동 스코어링\n"
        f"  - 대화형 AI 어시스턴트\n"
        f"  - 고급 시각화\n"
        f"  - 익스플로잇 & 패치 생성",
        border_style="cyan",
        title="[bold]정보[/bold]"
    ))


def _detect_language(file_path: Path) -> str:
    """파일 확장자에서 프로그래밍 언어 탐지용"""
    ext_map = {
        '.py': 'python',
        '.c': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.java': 'java',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.php': 'php',
    }
    return ext_map.get(file_path.suffix, 'unknown')


def main():
    """메인 진입점"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]사용자에 의해 중단됨[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]오류: {e}[/red]")
        if '--debug' in sys.argv:
            raise
        sys.exit(1)


if __name__ == '__main__':
    main()
