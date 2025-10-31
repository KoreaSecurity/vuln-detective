"""
Code Fetcher - VulnDetective의 독창적인 기능!
GitHub URL, Gist, Pastebin 등에서 직접 코드를 다운로드하여 분석
"""

import re
import requests
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse


class CodeFetcher:
    """원격 URL에서 코드를 가져오는 유틸리티"""

    @staticmethod
    def is_url(path: str) -> bool:
        """문자열이 URL인지 확인"""
        try:
            result = urlparse(path)
            return all([result.scheme, result.netloc])
        except:
            return False

    @staticmethod
    def fetch_from_github(url: str) -> Tuple[str, str, str]:
        """
        GitHub URL에서 코드 가져오기

        지원하는 형식:
        - https://github.com/user/repo/blob/main/file.py
        - https://raw.githubusercontent.com/user/repo/main/file.py
        """
        # GitHub blob URL을 raw URL로 변환
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com")
            url = url.replace("/blob/", "/")

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # 파일명 추출
            filename = Path(urlparse(url).path).name

            # 언어 추출
            ext_map = {
                '.py': 'python',
                '.c': 'c',
                '.cpp': 'cpp',
                '.java': 'java',
                '.js': 'javascript',
                '.go': 'go',
                '.rs': 'rust',
            }
            ext = Path(filename).suffix
            language = ext_map.get(ext, 'unknown')

            return response.text, filename, language

        except Exception as e:
            raise ValueError(f"Failed to fetch from GitHub: {e}")

    @staticmethod
    def fetch_from_gist(url: str) -> Tuple[str, str, str]:
        """
        GitHub Gist에서 코드 가져오기
        예: https://gist.github.com/user/gist_id
        """
        # Gist ID 추출
        match = re.search(r'gist\.github\.com/[^/]+/([a-f0-9]+)', url)
        if not match:
            raise ValueError("Invalid Gist URL")

        gist_id = match.group(1)
        api_url = f"https://api.github.com/gists/{gist_id}"

        try:
            response = requests.get(api_url, timeout=30)
            response.raise_for_status()
            data = response.json()

            # 첫 번째 파일 가져오기
            files = data.get('files', {})
            if not files:
                raise ValueError("No files in Gist")

            filename = list(files.keys())[0]
            file_data = files[filename]

            code = file_data.get('content', '')
            language = file_data.get('language', 'unknown').lower()

            return code, filename, language

        except Exception as e:
            raise ValueError(f"Failed to fetch from Gist: {e}")

    @staticmethod
    def fetch_from_pastebin(url: str) -> Tuple[str, str, str]:
        """
        Pastebin에서 코드 가져오기
        예: https://pastebin.com/abc123
        """
        # Pastebin raw URL로 변환
        paste_id = url.split('/')[-1]
        raw_url = f"https://pastebin.com/raw/{paste_id}"

        try:
            response = requests.get(raw_url, timeout=30)
            response.raise_for_status()

            return response.text, f"pastebin_{paste_id}.txt", 'unknown'

        except Exception as e:
            raise ValueError(f"Failed to fetch from Pastebin: {e}")

    @classmethod
    def fetch(cls, url: str) -> Tuple[str, str, str]:
        """
        URL에서 코드 자동 감지 및 다운로드

        Returns:
            (code, filename, language)
        """
        if not cls.is_url(url):
            raise ValueError("Not a valid URL")

        if "github.com" in url or "githubusercontent.com" in url:
            return cls.fetch_from_github(url)
        elif "gist.github.com" in url:
            return cls.fetch_from_gist(url)
        elif "pastebin.com" in url:
            return cls.fetch_from_pastebin(url)
        else:
            # 일반 URL - 직접 다운로드 시도
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                filename = Path(urlparse(url).path).name or "downloaded_code.txt"
                return response.text, filename, 'unknown'
            except Exception as e:
                raise ValueError(f"Failed to fetch from URL: {e}")
