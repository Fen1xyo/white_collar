# secret-scanner/scanner/parsers/c_parser.py

import re
from typing import List, Dict
from .base import BaseParser

class CParser(BaseParser):
    """
    Парсер для C/C++, который находит строковые литералы, уделяя
    особое внимание склейке смежных литералов.
    """
    
    # Regex для удаления блочных комментариев (включая многострочные)
    BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)
    # Regex для удаления строчных комментариев
    LINE_COMMENT_RE = re.compile(r'//.*')
    
    # Regex для поиска смежных строковых литералов, разделенных пробелами/переносами строк.
    # Пример: "hello" " world"
    ADJACENT_STRINGS_RE = re.compile(r'("([^"\\]|\\.)*?")(\s*("([^"\\]|\\.)*?"))+')
    
    # Regex для поиска всех оставшихся (одиночных) строковых литералов.
    SINGLE_STRING_RE = re.compile(r'"([^"\\]|\\.)*?"')

    def _clean_content(self, content: str) -> str:
        """Удаляет все комментарии из C-кода."""
        content = self.BLOCK_COMMENT_RE.sub('', content)
        content = self.LINE_COMMENT_RE.sub('', content)
        return content

    def get_tokens(self, content: str, file_path: str) -> List[Dict]:
        """
        Основной метод, который очищает код от комментариев и извлекает все строковые литералы.
        """
        cleaned_content = self._clean_content(content)
        
        # Используем словарь для хранения найденных строк, чтобы избежать дублирования
        # при двухпроходном сканировании. Ключ - позиция начала строки в файле.
        found_strings: Dict[int, Tuple[str, int]] = {}

        # 1. Первый проход: ищем и склеиваем смежные строки
        for match in self.ADJACENT_STRINGS_RE.finditer(cleaned_content):
            full_match_str = match.group(0)
            
            # "Склеиваем" части, удаляя кавычки и пробелы между ними
            # Пример: "hello" " world" -> helloworld
            glued_value = "".join(re.findall(r'"(.*?)"', full_match_str))
            
            start_pos = match.start()
            line_number = cleaned_content.count('\n', 0, start_pos) + 1
            
            found_strings[start_pos] = (glued_value, line_number)

        # 2. Второй проход: ищем все одиночные строки
        for match in self.SINGLE_STRING_RE.finditer(cleaned_content):
            start_pos = match.start()
            # Если строка с этой позиции уже была обработана (как часть смежной), пропускаем ее
            if start_pos in found_strings:
                continue

            # Извлекаем значение без кавычек
            value = match.group(0)[1:-1]
            line_number = cleaned_content.count('\n', 0, start_pos) + 1
            found_strings[start_pos] = (value, line_number)

        # 3. Формируем итоговый список токенов
        tokens = [
            {"value": val, "line": line, "file": file_path}
            for pos, (val, line) in found_strings.items()
        ]
        
        # Для полной совместимости с RegexDetector'ом, который работает построчно,
        # добавим также и все строки файла как токены. Это создает избыточность,
        # но гарантирует, что ни один детектор не пропустит свою цель.
        for i, line in enumerate(content.splitlines()):
            tokens.append({"value": line, "line": i + 1, "file": file_path})

        return tokens
