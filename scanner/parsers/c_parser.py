# secret-scanner/scanner/parsers/c_parser.py

import re
from typing import List, Dict, Tuple  # ИСПРАВЛЕНО: добавлен Tuple

from .base import BaseParser


class CParser(BaseParser):
    """
    Парсер для C/C++, который находит строковые литералы,
    уделяя особое внимание склейке смежных литералов.
    """

    BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)
    LINE_COMMENT_RE = re.compile(r'//.*')
    ADJACENT_STRINGS_RE = re.compile(
        r'("(?:[^"\\]|\\.)*")(\s*("(?:[^"\\]|\\.)*"))+'
    )
    SINGLE_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')

    def _clean_content(self, content: str) -> str:
        content = self.BLOCK_COMMENT_RE.sub('', content)
        content = self.LINE_COMMENT_RE.sub('', content)
        return content

    def get_tokens(self, content, file_path: str) -> List[Dict]:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='replace')

        cleaned_content = self._clean_content(content)
        found_strings: Dict[int, Tuple[str, int]] = {}

        # 1. Склеиваем смежные строковые литералы: "hello" " world" -> helloworld
        for match in self.ADJACENT_STRINGS_RE.finditer(cleaned_content):
            full_match_str = match.group(0)
            glued_value = "".join(re.findall(r'"(.*?)"', full_match_str))
            start_pos = match.start()
            line_number = cleaned_content.count('\n', 0, start_pos) + 1
            found_strings[start_pos] = (glued_value, line_number)

        # 2. Одиночные строковые литералы
        for match in self.SINGLE_STRING_RE.finditer(cleaned_content):
            start_pos = match.start()
            if start_pos in found_strings:
                continue
            value = match.group(0)[1:-1]
            line_number = cleaned_content.count('\n', 0, start_pos) + 1
            found_strings[start_pos] = (value, line_number)

        tokens = [
            {"value": val, "line": line, "file": file_path}
            for pos, (val, line) in found_strings.items()
        ]

        # 3. Построчное сканирование (гарантирует покрытие всех regex-паттернов)
        for i, line in enumerate(content.splitlines()):
            tokens.append({"value": line, "line": i + 1, "file": file_path})

        return tokens