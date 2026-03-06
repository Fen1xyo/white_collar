# secret-scanner/scanner/reporters/html_reporter.py

import os
from typing import List, Optional
from jinja2 import Environment, FileSystemLoader

# --- Контекст: Импортируем общие классы ---
from .console_reporter import BaseReporter
from ..core.finding import Finding
from ..rules.rule_loader import Rule

# --- Полная реализация HTMLReporter ---

class HTMLReporter(BaseReporter):
    """Генерирует наглядный отчет в формате HTML."""

    def __init__(self, rules: List[Rule]):
        super().__init__(rules)
        
        # Определяем путь к директории с шаблонами
        # Путь: secret-scanner/scanner/reporters/ -> ../../web/templates
        template_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'web', 'templates')
        
        if not os.path.isdir(template_dir):
            raise FileNotFoundError(f"Директория с HTML-шаблонами не найдена: {template_dir}")
            
        # Настраиваем окружение Jinja2
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
        """
        Основной метод для генерации HTML-отчета.
        """
        if not output_file:
            output_file = "secret_scan_report.html"
            
        try:
            template = self.jinja_env.get_template('report.html')
        except Exception as e:
            print(f"Ошибка: Не удалось загрузить HTML-шаблон 'report.html': {e}")
            return

        # Добавляем полные данные о правилах к каждой находке для удобства в шаблоне
        findings_with_rules = []
        for f in findings:
            rule = self.rules_map.get(f.rule_id)
            findings_with_rules.append({
                "finding": f,
                "rule": rule
            })

        # Рендерим шаблон, передавая в него обработанные данные
        html_content = template.render(
            findings_with_rules=findings_with_rules,
            title="Отчет о сканировании секретов"
        )
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"HTML отчет успешно сохранен в: {os.path.abspath(output_file)}")
        except IOError as e:
            print(f"Ошибка: Не удалось записать HTML отчет в файл {output_file}: {e}")

