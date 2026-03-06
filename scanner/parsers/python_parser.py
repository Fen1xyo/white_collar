# secret-scanner/scanner/parsers/python_parser.py

import ast
import re
import sys
from typing import List, Dict, Optional, Tuple
import chardet
from .base import BaseParser

class ConcatFoldingVisitor(ast.NodeVisitor):
    """
    AST Visitor для рекурсивного вычисления строковых выражений.
    Корректно обрабатывает как `node.Constant` (Python 3.8+), так и `node.Str` (старые версии),
    а также вложенные `BinOp` вида "a" + "b" + "c".
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tokens: List[Dict] = []

    def visit_Constant(self, node: ast.Constant):
        """Посещает узел константы (для Python 3.8+)."""
        if isinstance(node.value, str):
            self.tokens.append({
                "value": node.value,
                "line": node.lineno,
                "file": self.file_path
            })
        self.generic_visit(node)

    def visit_Str(self, node: ast.Str):
        """Посещает узел строки (для обратной совместимости)."""
        if isinstance(node.s, str):
            self.tokens.append({
                "value": node.s,
                "line": node.lineno,
                "file": self.file_path
            })
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """Посещает узел бинарной операции и пытается 'склеить' строки."""
        if isinstance(node.op, ast.Add):
            left_val = self._get_str_value(node.left)
            right_val = self._get_str_value(node.right)
            
            if left_val is not None and right_val is not None:
                self.tokens.append({
                    "value": left_val + right_val,
                    "line": node.lineno,
                    "file": self.file_path
                })
                return
        
        self.generic_visit(node)

    def _get_str_value(self, node: ast.AST) -> Optional[str]:
        """Рекурсивно извлекает строковое значение из узла AST."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Str):
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
    """
    Продвинутый парсер для Python, который динамически поддерживает все
    версии синтаксиса от 3.8 до текущей версии интерпретатора.
    """
    
    # --- НАЧАЛО ИЗМЕНЕНИЙ ---
    # Динамически генерируем список версий для проверки, от самой новой к самой старой.
    # Это делает сканер устойчивым к будущим обновлениям Python.
    
    # Определяем текущую версию Python, на которой запущен сканер
    CURRENT_PY_VERSION = (sys.version_info.major, sys.version_info.minor)
    # Определяем самую старую поддерживаемую версию
    OLDEST_SUPPORTED_MINOR = 8
    
    PYTHON_VERSIONS: List[Tuple[int, int]] = []
    if CURRENT_PY_VERSION[0] == 3 and CURRENT_PY_VERSION[1] >= OLDEST_SUPPORTED_MINOR:
        # Создаем список версий в порядке убывания: от текущей до 3.8 включительно.
        # Например, для Python 3.12 результат будет: [(3, 12), (3, 11), (3, 10), (3, 9), (3, 8)]
        PYTHON_VERSIONS = [
            (3, minor) for minor in range(CURRENT_PY_VERSION[1], OLDEST_SUPPORTED_MINOR - 1, -1)
        ]
    else:
        # Если сканер запущен на слишком старом Python, используем хотя бы 3.8
        PYTHON_VERSIONS = [(3, OLDEST_SUPPORTED_MINOR)]
    # --- КОНЕЦ ИЗМЕНЕНИЙ ---

    CODING_RE = re.compile(br'^[ \t\f]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)')

    def _detect_encoding(self, raw_bytes: bytes) -> str:
        """
        Реализует многоступенчатое определение кодировки файла.
        """
        if raw_bytes.startswith(b'\xef\xbb\xbf'):
            return 'utf-8-sig'
        
        for line in raw_bytes.split(b'\n')[:2]:
            match = self.CODING_RE.match(line)
            if match:
                return match.group(1).decode('ascii')

        try:
            result = chardet.detect(raw_bytes)
            encoding = result['encoding']
            if encoding and result['confidence'] > 0.7:
                return encoding
        except Exception:
            pass

        return 'utf-8'

    def get_tokens(self, file_content: str, file_path: str) -> List[Dict]:
        """
        Основной метод парсинга, который применяет всю цепочку анализа.
        """
        try:
            with open(file_path, 'rb') as f:
                raw_bytes = f.read()
        except (IOError, FileNotFoundError):
            return []

        encoding = self._detect_encoding(raw_bytes)
        try:
            source = raw_bytes.decode(encoding, errors='replace')
        except (UnicodeDecodeError, TypeError):
            return self._fallback_line_scan(raw_bytes.decode('utf-8', errors='replace'), file_path)

        tree: Optional[ast.AST] = None
        # Пытаемся распарсить файл, начиная с самой современной версии синтаксиса
        for major, minor in self.PYTHON_VERSIONS:
            try:
                tree = ast.parse(source, filename=file_path, feature_version=(major, minor))
                break
            except SyntaxError:
                continue

        if tree is None:
            # Fallback: если ни одна версия AST не подошла, переключаемся на построчный анализ
            return self._fallback_line_scan(source, file_path)

        # Успешный парсинг: обходим AST для сбора токенов
        visitor = ConcatFoldingVisitor(file_path)
        visitor.visit(tree)
        return visitor.get_tokens()

    def _fallback_line_scan(self, source: str, file_path: str) -> List[Dict]:
        """
        Резервный механизм. Возвращает каждую строку как отдельный токен.
        """
        tokens = []
        for i, line in enumerate(source.splitlines()):
            tokens.append({"value": line, "line": i + 1, "file": file_path})
        return tokens
