# secret-scanner/scanner/parsers/python_parser.py

import ast
import re
import sys
from typing import List, Dict, Optional, Tuple, Union
import chardet
from .base import BaseParser

class ConcatFoldingVisitor(ast.NodeVisitor):
    """ AST Visitor для рекурсивного вычисления строковых выражений. """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tokens: List[Dict] = []

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            self.tokens.append({"value": node.value, "line": node.lineno, "file": self.file_path})
        self.generic_visit(node)

    def visit_Str(self, node: ast.Str):
        if isinstance(node.s, str):
            self.tokens.append({"value": node.s, "line": node.lineno, "file": self.file_path})
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        if isinstance(node.op, ast.Add):
            left_val = self._get_str_value(node.left)
            right_val = self._get_str_value(node.right)
            if left_val is not None and right_val is not None:
                self.tokens.append({"value": left_val + right_val, "line": node.lineno, "file": self.file_path})
                return
        self.generic_visit(node)

    def _get_str_value(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if hasattr(ast, 'Str') and isinstance(node, ast.Str):
            return node.s
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._get_str_value(node.left)
            right = self._get_str_value(node.right)
            if left is not None and right is not None:
                return left + right
        return None

    def get_tokens(self) -> List[Dict]:
        return self.tokens

class PythonParser(BaseParser):
    """ Продвинутый парсер для Python. """
    CURRENT_PY_VERSION = (sys.version_info.major, sys.version_info.minor)
    OLDEST_SUPPORTED_MINOR = 8
    PYTHON_VERSIONS = [
        (3, minor) for minor in range(CURRENT_PY_VERSION[1], OLDEST_SUPPORTED_MINOR - 1, -1)
    ] if CURRENT_PY_VERSION[0] == 3 and CURRENT_PY_VERSION[1] >= OLDEST_SUPPORTED_MINOR else [(3, OLDEST_SUPPORTED_MINOR)]
    
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
            return self._fallback_line_scan(raw_bytes.decode('utf-8', errors='replace'), file_path)

        tree: Optional[ast.AST] = None
        for major, minor in self.PYTHON_VERSIONS:
            try:
                tree = ast.parse(source, filename=file_path, feature_version=(major, minor))
                break
            except SyntaxError:
                continue
        
        # ИСПРАВЛЕНО: Если парсинг AST прошел успешно, возвращаем только "умные" токены.
        # Построчный анализ теперь только для fallback-сценария.
        if tree:
            visitor = ConcatFoldingVisitor(file_path)
            visitor.visit(tree)
            return visitor.get_tokens()
        else:
            # Если ни одна версия AST не подошла, переключаемся на построчный анализ
            return self._fallback_line_scan(source, file_path)

    def _fallback_line_scan(self, source: str, file_path: str) -> List[Dict]:
        return [{"value": line, "line": i + 1, "file": file_path} for i, line in enumerate(source.splitlines())]
