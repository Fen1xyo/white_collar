import os
from typing import List, Optional
from jinja2 import Environment, FileSystemLoader
from .base import BaseReporter
from .llm_advisor import get_fix_suggestion
from ..core.finding import Finding
from ..rules.rule import Rule

class HTMLReporter(BaseReporter):
    def __init__(self, rules: List[Rule], use_llm: bool = False):
        super().__init__(rules)
        self.use_llm = use_llm
        template_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'web', 'templates')
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
        if not output_file:
            output_file = "secret_scan_report.html"
            
        template = self.jinja_env.get_template('report.html')
        
        stats = {
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_file": {}, "by_rule": {},
        }
        
        actual_findings = [f for f in findings if not f.whitelisted]
        for f in actual_findings:
            if f.severity in stats["by_severity"]:
                stats["by_severity"][f.severity] += 1
            stats["by_file"][f.file_path] = stats["by_file"].get(f.file_path, 0) + 1
            stats["by_rule"][f.rule_name] = stats["by_rule"].get(f.rule_name, 0) + 1

        stats["top_files"] = dict(sorted(stats["by_file"].items(), key=lambda x: x[1], reverse=True)[:10])
        stats["top_rules"] = dict(sorted(stats["by_rule"].items(), key=lambda x: x[1], reverse=True)[:5])

        findings_with_rules = []
        for f in findings:
            rule = self.rules_map.get(f.rule_id)
            llm_suggestion = None
            if self.use_llm and not f.whitelisted and f.severity in ("CRITICAL", "HIGH"):
                print(f" 🤖 LLM анализирует: {f.file_path}:{f.line_number}...")
                llm_suggestion = get_fix_suggestion(f)
            
            findings_with_rules.append({
                "finding": f, 
                "rule": rule, 
                "llm_suggestion": llm_suggestion
            })

        html_content = template.render(
            findings_with_rules=findings_with_rules,
            title="Отчет по анализу безопасности",
            stats=stats,
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            print(f"HTML отчет сохранен: {os.path.abspath(output_file)}")
