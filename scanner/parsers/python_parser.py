# scanner/parsers/python_parser.py
import ast
import re
import sys
from typing import List, Dict, Union, Any
import chardet
from .base import BaseParser

class SecretReconstructor(ast.NodeVisitor):
    """
    Продвинутый AST Visitor, который отслеживает присваивания переменных
    и реконструирует строки, собранные из частей.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.symbol_table: Dict[str, Any] = {}  # Таблица для хранения значений переменных
        self.tokens: List[Dict] = []

    def _evaluate_node(self, node: ast.AST) -> Any:
        """Рекурсивно вычисляет значение узла AST."""
        if isinstance(node, ast.Constant):
            return node.value
        if sys.version_info < (3, 8) and isinstance(node, ast.Str):
            return node.s
        if isinstance(node, ast.Name):
            return self.symbol_table.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._evaluate_node(node.left)
            right = self._evaluate_node(node.right)
            if left is not None and right is not None:
                try:
                    return left + right
                except TypeError:
                    return None
        if isinstance(node, ast.JoinedStr): # f-string
            parts = [self._evaluate_node(v) for v in node.values]
            if all(p is not None for p in parts):
                return "".join(map(str, parts))
        if isinstance(node, ast.FormattedValue):
            return self._evaluate_node(node.value)
        return None

    def visit_Assign(self, node: ast.Assign):
        """Посещает узлы присваивания (var = value)."""
        value = self._evaluate_node(node.value)
        if value is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.symbol_table[target.id] = value
            # Добавляем реконструированное значение как токен
            self.tokens.append({"value": str(value), "line": node.lineno, "file": self.file_path})
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.tokens.append({"value": node.value, "line": node.lineno, "file": self.file_path})
        self.generic_visit(node)

    def visit_Str(self, node: ast.Str):
        if isinstance(node.s, str):
            self.tokens.append({"value": node.s, "line": node.lineno, "file": self.file_path})
        self.generic_visit(node)

    def get_tokens(self) -> List[Dict]:
        return self.tokens

class PythonParser(BaseParser):
    """ Продвинутый парсер для Python. """
    CODING_RE = re.compile(br'^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)')

    def _detect_encoding(self, raw_bytes: bytes) -> str:
        if raw_bytes.startswith(b'\xef\xbb\xbf'):
            return 'utf-8-sig'
        for line in raw_bytes.split(b'\n')[:2]:
            match = self.CODING_RE.match(line)
            if match:
                return match.group(1).decode('ascii')
        try:
            result = chardet.detect(raw_bytes)
            if result['encoding'] and result['confidence'] > 0.7:
                return result['encoding']
        except Exception:
            pass
        return 'utf-8'

    def get_tokens(self, content: Union[str, bytes], file_path: str) -> List[Dict]:
        if isinstance(content, str):
            raw_bytes = content.encode('utf-8', errors='replace')
        else:
            raw_bytes = content
        
        encoding = self._detect_encoding(raw_bytes)
        try:
            source = raw_bytes.decode(encoding, errors='replace')
        except (UnicodeDecodeError, TypeError):
            source = raw_bytes.decode('utf-8', errors='replace')

        all_tokens = []
        tree: Optional[ast.AST] = None

        # 1. Применяем "умный" AST-парсер с отслеживанием переменных.
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            pass # Игнорируем синтаксические ошибки, переходя к построчному сканированию

        if tree:
            visitor = SecretReconstructor(file_path)
            visitor.visit(tree)
            all_tokens.extend(visitor.get_tokens())

        # 2. Всегда добавляем полное построчное сканирование файла.
        # Это гарантирует, что правила, которые ищут паттерны в целых строках
        # (например, 'password = "..."'), будут работать корректно.
        all_tokens.extend(self._fallback_line_scan(source, file_path))
        
        # Удаляем дубликаты токенов, если они есть
        unique_tokens = list({(d['value'], d['line']): d for d in all_tokens}.values())
        return unique_tokens

    def _fallback_line_scan(self, source: str, file_path: str) -> List[Dict]:
        return [{"value": line, "line": i + 1, "file": file_path} for i, line in enumerate(source.splitlines())]
