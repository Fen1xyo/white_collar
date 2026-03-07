import argparse
import os
import sys
import yaml
from typing import List, Dict, Any

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanner.core.engine import ScanEngine
from scanner.reporters.console_reporter import ConsoleReporter
from scanner.reporters.json_reporter import JSONReporter
from scanner.reporters.html_reporter import HTMLReporter
from scanner.rules.rule_loader import RuleLoader

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Secret Scanner v2.0 — Поиск захардкоженных секретов.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("path", help="Путь к директории проекта для сканирования.")
    parser.add_argument("--report-format", choices=['console', 'json', 'html'], default='console', help="Формат отчета.")
    parser.add_argument("--output-file", help="Имя файла для сохранения отчета.")
    parser.add_argument("--min-confidence", type=float, default=0.4, help="Минимальная уверенность [0.0-1.0].")
    parser.add_argument("--no-ru-rules", action='store_true', help="Исключить правила для РФ.")
    parser.add_argument("--scan-git", action='store_true', help="Сканировать историю Git.")
    parser.add_argument("--llm", action='store_true', help="Использовать Ollama для генерации патчей.")
    
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Ошибка: Путь '{args.path}' не существует.")
        sys.exit(1)

    try:
        config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config'))
        with open(os.path.join(config_dir, 'settings.yaml'), 'r', encoding='utf-8') as f:
            config: Dict[str, Any] = yaml.safe_load(f)

        rule_paths = [os.path.join(config_dir, 'default_rules.yaml')]
        if not args.no_ru_rules:
            rule_paths.append(os.path.join(config_dir, 'ru_rules.yaml'))
        
        config['rule_paths'] = rule_paths
        config['use_llm'] = args.llm

        engine = ScanEngine(config)
        findings = engine.run(args.path, args.scan_git)

        final_findings = [f for f in findings if (f.confidence if f.confidence is not None else 0.5) >= args.min_confidence]
        rules = RuleLoader(config['rule_paths']).load_rules()
        
        use_llm = config.get('use_llm', False)
        
        reporters = {
            'console': ConsoleReporter(rules, use_llm=use_llm),
            'json': JSONReporter(rules),
            'html': HTMLReporter(rules, use_llm=use_llm),
        }
        
        reporter = reporters[args.report_format]
        reporter.generate_report(final_findings, args.output_file)

    except KeyboardInterrupt:
        print("\nСканирование прервано.")
        sys.exit(1)
    except Exception as e:
        print(f"\nКритическая ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
