# secret-scanner/scanner/reporters/json_reporter.py

import json
from typing import List, Dict, Any, Optional
# ИСПРАВЛЕНО: импортируем базовый класс напрямую
from .base import BaseReporter
from ..core.finding import Finding
from ..rules.rule import Rule

class JSONReporter(BaseReporter):
    """Генерирует подробный отчет в формате JSON."""
    def __init__(self, rules: List[Rule]):
        super().__init__(rules)

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Сериализует объект Finding в словарь для JSON."""
        rule = self.rules_map.get(finding.rule_id)
        return {
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "commit": finding.commit,
            "confidence": finding.confidence,
            "whitelisted": finding.whitelisted,
            "secret": finding.secret,
            "line_content": finding.line_content,
            "rule": {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "severity": finding.severity,
                "description": rule.description if rule else "N/A",
                "remediation": rule.remediation if rule else "N/A",
            }
        }

    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
        """ Основной метод для генерации JSON-отчета. """
        actual_findings_count = len([f for f in findings if not f.whitelisted])
        report = {
            "summary": {
                "total_findings": len(findings),
                "whitelisted_findings": len(findings) - actual_findings_count,
                "secrets_found": actual_findings_count,
            },
            "findings": [self._finding_to_dict(f) for f in findings]
        }
        
        report_json = json.dumps(report, indent=2, ensure_ascii=False)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_json)
                print(f"JSON отчет успешно сохранен в: {os.path.abspath(output_file)}")
            except IOError as e:
                print(f"Ошибка: Не удалось записать JSON отчет в файл {output_file}: {e}")
        else:
            print(report_json)
