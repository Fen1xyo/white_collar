# secret-scanner/scanner/detectors/regex_detector.py

import re
from typing import List, Optional
# ИСПРАВЛЕНО: импортируем базовый класс, а не определяем заново
from .base import BaseDetector
from ..core.finding import Finding
from ..rules.rule import Rule

class RegexDetector(BaseDetector):
    """ Детектор, использующий регулярные выражения из загруженных правил для поиска секретов. """
    def __init__(self, rules: List[Rule]):
        self.rules = rules
        # Компилируем все регулярные выражения один раз для повышения производительности
        self.compiled_rules = []
        for rule in self.rules:
            try:
                self.compiled_rules.append({
                    "rule": rule,
                    "pattern": re.compile(rule.pattern)
                })
            except re.error as e:
                print(f"Ошибка компиляции регулярного выражения для правила '{rule.id}': {e}. Правило будет пропущено.")

    def detect(self, content: str, file_path: str, line_number: int, commit: Optional[str] = None) -> List[Finding]:
        """ Применяет все скомпилированные регулярные выражения к переданной строке контента. """
        findings: List[Finding] = []
        for compiled_rule in self.compiled_rules:
            rule = compiled_rule["rule"]
            pattern = compiled_rule["pattern"]
            try:
                matches = pattern.finditer(content)
                for match in matches:
                    secret = match.group(1) if match.groups() else match.group(0)
                    
                    if not secret:
                        continue
                        
                    finding = Finding(
                        file_path=file_path,
                        line_number=line_number,
                        commit=commit,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        secret=secret,
                        line_content=content.strip() 
                    )
                    findings.append(finding)
            except Exception as e:
                print(f"Ошибка при применении правила '{rule.id}' к файлу {file_path}:{line_number}: {e}")
        return findings
