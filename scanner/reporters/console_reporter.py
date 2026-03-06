# secret-scanner/scanner/reporters/console_reporter.py

from typing import List, Optional
from colorama import Fore, Style, init
from abc import ABC, abstractmethod

from ..core.finding import Finding
from ..rules.rule_loader import Rule # Импортируем для type hinting

# --- Контекст: Базовый класс и датаклассы ---

class BaseReporter(ABC):
    """Абстрактный базовый класс для всех репортеров."""
    def __init__(self, rules: List[Rule]):
        # Репортерам нужны правила, чтобы иметь доступ к описаниям и рекомендациям
        self.rules_map = {rule.id: rule for rule in rules}

    @abstractmethod
    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
        """Генерирует отчет на основе списка находок."""
        pass

# --- Полная реализация ConsoleReporter ---

class ConsoleReporter(BaseReporter):
    """Выводит подробный, цветной отчет в консоль."""

    def __init__(self, rules: List[Rule]):
        super().__init__(rules)
        init(autoreset=True) # Инициализация colorama

    SEVERITY_COLORS = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "MEDIUM": Fore.BLUE,
        "LOW": Fore.GREEN,
    }

    CONFIDENCE_TEXT = {
        "HIGH": (Fore.GREEN, "[✓ ВЫСОКАЯ]"),
        "MEDIUM": (Fore.YELLOW, "[? СРЕДНЯЯ]"),
        "LOW": (Fore.CYAN, "[~ НИЗКАЯ]"),
    }

    def _get_confidence_level(self, score: Optional[float]) -> str:
        """Преобразует числовую оценку в текстовый уровень."""
        if score is None: return "MEDIUM"
        if score >= 0.7: return "HIGH"
        if score >= 0.4: return "MEDIUM"
        return "LOW"

    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
        """Основной метод для генерации консольного отчета."""
        
        # Отфильтровываем находки, попавшие в белый список
        actual_findings = [f for f in findings if not f.whitelisted]

        if not actual_findings:
            print(Fore.GREEN + "✅ Сканирование завершено. Реальные секреты не найдены.")
            return

        print(f"\n🚨 {Style.BRIGHT}Найдено реальных угроз: {len(actual_findings)}{Style.NORMAL}")
        
        for finding in actual_findings:
            confidence_level = self._get_confidence_level(finding.confidence)
            conf_color, conf_text = self.CONFIDENCE_TEXT[confidence_level]
            sev_color = self.SEVERITY_COLORS.get(finding.severity, Fore.WHITE)
            rule = self.rules_map.get(finding.rule_id)

            print(f"\n{Fore.WHITE}{'='*80}")
            
            # --- Основная информация ---
            print(f"{Style.BRIGHT}Файл:        {Fore.CYAN}{finding.file_path}:{finding.line_number}")
            if finding.commit:
                print(f"{Style.BRIGHT}Коммит:      {Fore.MAGENTA}{finding.commit}")
            print(f"{Style.BRIGHT}Правило:     {finding.rule_name} ({finding.rule_id})")
            
            # --- Детали находки ---
            print(f"{Style.BRIGHT}Строка:      {Fore.WHITE}`{finding.line_content}`")
            print(f"{Style.BRIGHT}Секрет:      {Fore.RED}{finding.secret}")
            
            # --- Оценка и метаданные ---
            print(f"{Style.BRIGHT}Критичность: {sev_color}{finding.severity}")
            print(f"{Style.BRIGHT}Уверенность:  {conf_color}{conf_text} (Оценка: {finding.confidence})")

            # --- Рекомендации (если есть) ---
            if rule and rule.description:
                print(f"\n{Style.BRIGHT}Описание:{Style.NORMAL}\n  {rule.description}")
            if rule and rule.remediation:
                print(f"\n{Style.BRIGHT}Рекомендация по устранению:{Style.NORMAL}\n  {rule.remediation.replace(chr(10), ' ')}")
            
            print(f"{Fore.WHITE}{'='*80}")

