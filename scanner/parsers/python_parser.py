# secret-scanner/scanner/parsers/python_parser.py
import ast
import re
import sys
from typing import List, Dict, Union, Any, Optional
import chardet
from .base import BaseParser

class SecretReconstructor(ast.NodeVisitor):
    """
    Продвинутый AST Visitor — отслеживает присваивания переменных и
    реконструирует значения, собранные из частей (конкатенация, f-строки, числа).
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.symbol_table: Dict[str, Any] = {}
        self.tokens: List[Dict] = []

    def _evaluate_node(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if sys.version_info < (3, 8):
            if isinstance(node, ast.Str):
                return node.s
            if isinstance(node, ast.Num):
                return node.n
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
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    eval_val = self._evaluate_node(value.value)
                    if eval_val is not None:
                        parts.append(str(eval_val))
            return "".join(parts)
        if isinstance(node, ast.FormattedValue):
            return self._evaluate_node(node.value)
        return None

    def visit_Assign(self, node: ast.Assign):
        value = self._evaluate_node(node.value)
        # ИСПРАВЛЕНО: Теперь обрабатываем строки и числа
        if value is not None and isinstance(value, (str, int, float)):
            str_value = str(value)
            if not str_value:
                self.generic_visit(node)
                return

            for target in node.targets:
                var_name = None
                if isinstance(target, ast.Name):
                    var_name = target.id
                elif isinstance(target, ast.Attribute):
                    var_name = target.attr

                if var_name:
                    self.symbol_table[var_name] = value
                    
                    # ИСПРАВЛЕНО: Создаем "нормализованную" строку, понятную для regex.
                    # Всегда оборачиваем итоговое значение в кавычки.
                    import json
                    fake_line = f'{var_name} = {json.dumps(str_value)}'
                    
                    self.tokens.append({
                        "value": fake_line,
                        "line": node.lineno,
                        "file": self.file_path,
                    })
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.tokens.append({
                "value": node.value,
                "line": node.lineno,
                "file": self.file_path
            })
        self.generic_visit(node)

    def visit_Str(self, node: ast.Str):
        if isinstance(node.s, str):
            self.tokens.append({
                "value": node.s,
                "line": node.lineno,
                "file": self.file_path
            })
        self.generic_visit(node)

    def get_tokens(self) -> List[Dict]:
        return self.tokens

class PythonParser(BaseParser):
    """Продвинутый парсер для Python с поддержкой AST и cp1251."""
    CODING_RE = re.compile(br'^\s*#.*?coding[:=]\s*([-\w.]+)')

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
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            print(f"Предупреждение: синтаксическая ошибка в {file_path}, используется построчный анализ. Ошибка: {e}")
            return self._fallback_line_scan(source, file_path)

        if tree:
            visitor = SecretReconstructor(file_path)
            visitor.visit(tree)
            all_tokens.extend(visitor.get_tokens())

        all_tokens.extend(self._fallback_line_scan(source, file_path))
        
        unique_tokens_map = {}
        for token in all_tokens:
            key = (token['line'], token['value'])
            if key not in unique_tokens_map:
                unique_tokens_map[key] = token
        
        return list(unique_tokens_map.values())

    def _fallback_line_scan(self, source: str, file_path: str) -> List[Dict]:
        return [
            {"value": line, "line": i + 1, "file": file_path}
            for i, line in enumerate(source.splitlines())
        ]
