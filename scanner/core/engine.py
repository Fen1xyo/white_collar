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


class ScanEngine:
    """
    Основной движок сканирования.
    Оркестрирует все компоненты: FileWalker, парсеры, детекторы, скоринг и whitelist.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config

        # 1. Загрузка правил
        self.rules = RuleLoader(config.get('rule_paths', [])).load_rules()

        # 2. Инициализация обходчика файлов
        self.file_walker = FileWalker(
            project_path=".",  # Будет переопределен при запуске
            exclude_dirs=config.get('exclude_dirs', []),
            scan_extensions=config.get('scan_extensions', [])
        )

        # 3. Инициализация парсеров для разных типов файлов
        self.parsers: Dict[str, BaseParser] = {
            '.py':              PythonParser(),
            '.c':               CParser(),
            '.h':               CParser(),
            '.env':             ConfigParser(),
            'makefile':         ConfigParser(),
            '.yaml':            ConfigParser(),
            '.yml':             ConfigParser(),
            '.ini':             ConfigParser(),
            '.cfg':             ConfigParser(),
            '.conf':            ConfigParser(),
            'requirements.txt': ConfigParser(),
            'docker-compose.yml': ConfigParser(),
        }
        self.default_parser = ConfigParser()  # Парсер для всех остальных файлов

        # 4. Инициализация детекторов
        self.detectors = [
            RegexDetector(self.rules),
        ]

        # 5. Инициализация модулей пост-обработки
        self.confidence_scorer = ConfidenceScorer()
        self.whitelist_manager: Optional[WhitelistManager] = None

    def _get_parser(self, file_path: str) -> BaseParser:
        """Роутер: выбирает подходящий парсер для файла."""
        filename = os.path.basename(file_path).lower()
        ext = os.path.splitext(filename)[1]

        if filename in self.parsers:
            return self.parsers[filename]
        if ext in self.parsers:
            return self.parsers[ext]
        return self.default_parser

    def run(self, project_path: str, scan_git: bool = False) -> List[Finding]:
        """
        Главный метод, запускающий полный цикл сканирования.
        """
        self.file_walker.project_path = project_path
        self.whitelist_manager = WhitelistManager(project_path)

        all_findings: Set[Finding] = set()

        if scan_git:
            print("Запущено сканирование истории Git (это может занять время)...")
            for content, file_path, commit_hash in self.file_walker.scan_git_history():
                findings_in_content = self._scan_content(content, file_path, commit_hash)
                all_findings.update(findings_in_content)
        else:
            print("Запущено сканирование файловой системы...")
            for file_path in self.file_walker.walk_files():
                try:
                    with open(file_path, 'rb') as f:
                        findings_in_file = self._scan_content(f.read(), file_path)
                    all_findings.update(findings_in_file)
                except Exception as e:
                    print(f"Ошибка: не удалось прочитать или обработать файл {file_path}: {e}")

        print(f"Сканирование завершено. Найдено уникальных потенциальных секретов: {len(all_findings)}.")
        print("Запуск пост-обработки: оценка уверенности и применение белого списка...")

        scored_findings = [self.confidence_scorer.score(f) for f in all_findings]
        final_findings = self.whitelist_manager.filter(scored_findings)
        final_findings.sort(key=lambda f: (f.file_path, f.line_number, f.rule_id))
        return final_findings

    def _scan_content(
        self, content: Any, file_path: str, commit: Optional[str] = None
    ) -> List[Finding]:
        """
        Сканирует содержимое одного файла (или blob'а из Git).

        ИСПРАВЛЕНО: после получения находок от детектора подменяем finding.line_content
        на полную оригинальную строку исходного кода. Ранее туда записывался только
        «токен» из парсера (например, голое значение строкового литерала из AST),
        из-за чего ConfidenceScorer не видел имя переменной (token, key, password...)
        и не давал бонус +0.20 за ключевое слово в строке.
        """
        findings = []

        # --- Декодируем исходник для построчного контекста ---
        if isinstance(content, bytes):
            # Пробуем UTF-8; при ошибке заменяем проблемные байты
            source_str = content.decode('utf-8', errors='replace')
        else:
            source_str = content

        source_lines = source_str.splitlines()

        # --- Выбираем парсер и получаем токены ---
        parser = self._get_parser(file_path)
        tokens = parser.get_tokens(content, file_path)

        # --- Запускаем все детекторы на каждом токене ---
        for token in tokens:
            for detector in self.detectors:
                new_findings = detector.detect(
                    content=token["value"],
                    file_path=file_path,
                    line_number=token["line"],
                    commit=commit
                )
                if new_findings:
                    # КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ: заменяем line_content (который сейчас
                    # содержит значение токена) на реальную строку исходного файла.
                    # Это позволяет ConfidenceScorer анализировать контекст: имена
                    # переменных, ключевые слова, комментарии.
                    for finding in new_findings:
                        line_idx = finding.line_number - 1
                        if 0 <= line_idx < len(source_lines):
                            finding.line_content = source_lines[line_idx]
                    findings.extend(new_findings)

        return findings