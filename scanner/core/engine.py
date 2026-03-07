# secret-scanner/scanner/core/engine.py
import os
from typing import List, Dict, Any, Optional, Set
from .file_walker import FileWalker
from .finding import Finding
from ..rules.rule_loader import RuleLoader
from ..parsers.base import BaseParser
from ..parsers.python_parser import PythonParser
from ..parsers.c_parser import CParser
from ..parsers.config_parser import ConfigParser
from ..detectors.regex_detector import RegexDetector
from ..detectors.confidence_scorer import ConfidenceScorer
from ..whitelist.whitelist_manager import WhitelistManager

# Ранги для определения "важности" правила при дедупликации
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Убирает дубликаты. Если несколько правил нашли один и тот же секрет
    на одной и той же строке, оставляет только находку с наивысшей критичностью (severity).
    """
    best_findings: Dict[tuple, Finding] = {}
    # Ключ: (путь к файлу, номер строки, сам секрет)
    for f in findings:
        key = (f.file_path, f.line_number, f.secret)
        
        # Если находки для этого ключа еще нет, или новая находка "важнее" старой
        if key not in best_findings or \
           _SEVERITY_RANK.get(f.severity, 0) > _SEVERITY_RANK.get(best_findings[key].severity, 0):
            best_findings[key] = f
            
    return list(best_findings.values())


class ScanEngine:
    """
    Основной движок сканирования.
    Оркестрирует: FileWalker, парсеры, детекторы, скоринг и whitelist.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules = RuleLoader(config.get('rule_paths', [])).load_rules()
        self.file_walker = FileWalker(
            project_path=".",
            exclude_dirs=config.get('exclude_dirs', []),
            scan_extensions=config.get('scan_extensions', []),
        )
        self.parsers: Dict[str, BaseParser] = {
            '.py': PythonParser(), '.c': CParser(), '.h': CParser(), '.cpp': CParser(),
            '.env': ConfigParser(), 'makefile': ConfigParser(), '.yaml': ConfigParser(),
            '.yml': ConfigParser(), '.ini': ConfigParser(), '.cfg': ConfigParser(),
            '.conf': ConfigParser(), 'requirements.txt': ConfigParser(),
            'docker-compose.yml': ConfigParser(),
        }
        self.default_parser = ConfigParser()
        self.detectors = [RegexDetector(self.rules)]
        self.confidence_scorer = ConfidenceScorer()
        self.whitelist_manager: Optional[WhitelistManager] = None

    def _get_parser(self, file_path: str) -> BaseParser:
        filename = os.path.basename(file_path).lower()
        ext = os.path.splitext(filename)[1]
        if filename in self.parsers: return self.parsers[filename]
        if ext in self.parsers: return self.parsers[ext]
        return self.default_parser

    def run(self, project_path: str, scan_git: bool = False) -> List[Finding]:
        """Главный метод: полный цикл сканирования."""
        self.file_walker.project_path = project_path
        self.whitelist_manager = WhitelistManager(project_path)
        all_findings: Set[Finding] = set()

        if scan_git:
            print("Запущено сканирование истории Git (это может занять время)...")
            for content, file_path, commit_hash in self.file_walker.scan_git_history():
                all_findings.update(self._scan_content(content, file_path, commit_hash))
        else:
            print("Запущено сканирование файловой системы...")
            for file_path in self.file_walker.walk_files():
                try:
                    with open(file_path, 'rb') as f:
                        raw_content = f.read()
                    all_findings.update(self._scan_content(raw_content, file_path))
                except Exception as e:
                    print(f"Ошибка: не удалось обработать файл {file_path}: {e}")

        print(f"Сканирование завершено. Найдено уникальных потенциальных секретов: {len(all_findings)}.")
        
        # ИСПРАВЛЕНО: добавлен шаг дедупликации
        print("Запуск пост-обработки: дедупликация, оценка уверенности и белый список...")
        deduplicated = _deduplicate_findings(list(all_findings))
        
        scored_findings = [self.confidence_scorer.score(f) for f in deduplicated]
        final_findings = self.whitelist_manager.filter(scored_findings)
        final_findings.sort(key=lambda f: (f.file_path, f.line_number, f.rule_id))
        
        return final_findings

    def _scan_content(self, content: Any, file_path: str, commit: Optional[str] = None) -> List[Finding]:
        """Сканирует содержимое одного файла."""
        findings = []
        if isinstance(content, bytes):
            try:
                source_str = content.decode('utf-8')
            except UnicodeDecodeError:
                source_str = content.decode('latin-1', errors='replace')
        else:
            source_str = content
            
        source_lines = source_str.splitlines()
        parser = self._get_parser(file_path)
        tokens = parser.get_tokens(content, file_path)

        for token in tokens:
            for detector in self.detectors:
                new_findings = detector.detect(
                    content=token["value"], file_path=file_path,
                    line_number=token["line"], commit=commit,
                )
                if new_findings:
                    for finding in new_findings:
                        line_idx = finding.line_number - 1
                        if 0 <= line_idx < len(source_lines):
                            finding.line_content = source_lines[line_idx]
                    findings.extend(new_findings)
        return findings
