# secret-scanner/scanner/reporters/html_reporter.py
import os
import json
from typing import List, Optional
from jinja2 import Environment, FileSystemLoader
from .base import BaseReporter
from ..core.finding import Finding
from ..rules.rule import Rule

class HTMLReporter(BaseReporter):
    """Генерирует наглядный, автономный отчет в формате HTML с графиками."""

    def __init__(self, rules: List[Rule]):
        super().__init__(rules)
        template_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'web', 'templates')
        if not os.path.isdir(template_dir):
            raise FileNotFoundError(f"Директория с HTML-шаблонами не найдена: {template_dir}")
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
        """
        Основной метод для генерации HTML-отчета.
        Внедряет CSS и JS для создания полностью автономного файла с графиками.
        """
        if not output_file:
            output_file = "secret_scan_report.html"

        try:
            template = self.jinja_env.get_template('report.html')
        except Exception as e:
            print(f"Ошибка: Не удалось загрузить HTML-шаблон 'report.html': {e}")
            return

        css_content = ""
        try:
            css_path = os.path.join(os.path.dirname(__file__), '..', '..', 'web', 'static', 'style.css')
            with open(css_path, 'r', encoding='utf-8') as f:
                css_content = f.read()
        except Exception as e:
            print(f"Предупреждение: не удалось прочитать CSS файл для внедрения в отчет: {e}")

        # Агрегация данных для графиков
        stats = {
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_file": {},
            "by_rule": {}
        }
        actual_findings = [f for f in findings if not f.whitelisted]

        for f in actual_findings:
            if f.severity in stats["by_severity"]:
                stats["by_severity"][f.severity] += 1
            
            stats["by_file"][f.file_path] = stats["by_file"].get(f.file_path, 0) + 1
            stats["by_rule"][f.rule_name] = stats["by_rule"].get(f.rule_name, 0) + 1

        top_files = sorted(stats["by_file"].items(), key=lambda item: item[1], reverse=True)[:10]
        stats["top_files"] = {k: v for k, v in top_files}

        top_rules = sorted(stats["by_rule"].items(), key=lambda item: item[1], reverse=True)[:5]
        stats["top_rules"] = {k: v for k, v in top_rules}

        findings_with_rules = []
        for f in findings:
            rule = self.rules_map.get(f.rule_id)
            findings_with_rules.append({"finding": f, "rule": rule})

        # ИСПРАВЛЕНО: передаем в шаблон единый объект `stats`
        html_content = template.render(
            findings_with_rules=findings_with_rules,
            title="Отчет по анализу безопасности",
            css_content=css_content,
            stats=stats
        )

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"HTML отчет успешно сохранен в: {os.path.abspath(output_file)}")
        except IOError as e:
            print(f"Ошибка: Не удалось записать HTML отчет в файл {output_file}: {e}")
