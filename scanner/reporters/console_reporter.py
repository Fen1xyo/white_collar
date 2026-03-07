from typing import List, Optional
from colorama import Fore, Style, init
from .base import BaseReporter
from .llm_advisor import get_fix_suggestion
from ..core.finding import Finding
from ..rules.rule import Rule

class ConsoleReporter(BaseReporter):
    def __init__(self, rules: List[Rule], use_llm: bool = False):
        super().__init__(rules)
        self.use_llm = use_llm
        init(autoreset=True)
        self.SEVERITY_COLORS = {"CRITICAL": Fore.RED, "HIGH": Fore.YELLOW, "MEDIUM": Fore.BLUE, "LOW": Fore.GREEN}
        self.CONFIDENCE_TEXT = {"HIGH": (Fore.GREEN, "[✓ ВЫСОКАЯ]"), "MEDIUM": (Fore.YELLOW, "[? СРЕДНЯЯ]"), "LOW": (Fore.CYAN, "[~ НИЗКАЯ]")}

    def _get_confidence_level(self, score: Optional[float]) -> str:
        if score is None: return "MEDIUM"
        if score >= 0.7: return "HIGH"
        if score >= 0.4: return "MEDIUM"
        return "LOW"

    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
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

            print(f"\n{Fore.WHITE}{'=' * 80}")
            print(f"{Style.BRIGHT}Файл: {Fore.CYAN}{finding.file_path}:{finding.line_number}")
            if finding.commit: print(f"{Style.BRIGHT}Коммит: {Fore.MAGENTA}{finding.commit}")
            print(f"{Style.BRIGHT}Правило: {finding.rule_name} ({finding.rule_id})")
            print(f"{Style.BRIGHT}Строка: {Fore.WHITE}`{finding.line_content}`")
            print(f"{Style.BRIGHT}Секрет: {Fore.RED}{finding.secret}")
            print(f"{Style.BRIGHT}Критичность: {sev_color}{finding.severity}")
            print(f"{Style.BRIGHT}Уверенность: {conf_color}{conf_text} (Оценка: {finding.confidence})")

            if rule and rule.description:
                print(f"\n{Style.BRIGHT}Описание:{Style.NORMAL}\n  {rule.description}")
            if rule and rule.remediation:
                print(f"\n{Style.BRIGHT}Рекомендация:{Style.NORMAL}\n  {rule.remediation.replace(chr(10), ' ')}")
            
            # --- Блок вывода LLM ---
            if self.use_llm and finding.severity in ("CRITICAL", "HIGH"):
                print(f"\n{Style.BRIGHT}🤖 Патч от LLM:{Style.NORMAL}")
                suggestion = get_fix_suggestion(finding)
                for line in suggestion.splitlines():
                    print(f"  {Fore.GREEN}{line}")
            print(f"{Fore.WHITE}{'=' * 80}")
