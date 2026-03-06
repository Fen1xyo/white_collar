# secret-scanner/cli/main.py

import argparse
import os
import sys
import yaml
from typing import List, Dict, Any

# Добавляем корневую директорию проекта в sys.path, чтобы можно было запускать как "python cli/main.py"
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.core.engine import ScanEngine
from scanner.reporters.console_reporter import ConsoleReporter
from scanner.reporters.json_reporter import JSONReporter
from scanner.reporters.html_reporter import HTMLReporter
from scanner.rules.rule_loader import RuleLoader

def main():
    """
    Главная функция, точка входа для CLI.
    """
    parser = argparse.ArgumentParser(
        description="🔍 Secret Scanner v2.0 — Поиск захардкоженных секретов в коде и истории Git.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("path", help="Путь к директории проекта для сканирования.")
    parser.add_argument(
        "--report-format", 
        choices=['console', 'json', 'html'], 
        default='console', 
        help="Формат итогового отчета (по умолчанию: console)."
    )
    parser.add_argument(
        "--output-file", 
        help="Имя файла для сохранения отчета (для форматов json и html)."
    )
    parser.add_argument(
        "--min-confidence", 
        type=float, 
        default=0.4, 
        help="Минимальный уровень уверенности для отображения находок [0.0-1.0].\n"
             "Рекомендуемые значения:\n"
             "  0.0 - показать всё\n"
             "  0.4 - средний уровень (по умолчанию)\n"
             "  0.7 - только находки с высокой уверенностью."
    )
    parser.add_argument(
        "--no-ru-rules", 
        action='store_true', 
        help="Исключить из сканирования правила для российских сервисов."
    )
    parser.add_argument(
        "--scan-git", 
        action='store_true', 
        help="Включить полное сканирование всей истории Git-репозитория."
    )
    
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Ошибка: Указанный путь '{args.path}' не является директорией или не существует.")
        sys.exit(1)

    try:
        # 1. Загрузка глобальной конфигурации (исключения и расширения)
        config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config'))
        with open(os.path.join(config_dir, 'settings.yaml'), 'r', encoding='utf-8') as f:
            config: Dict[str, Any] = yaml.safe_load(f)

        # 2. Формирование списка файлов с правилами на основе аргументов
        rule_paths = [os.path.join(config_dir, 'default_rules.yaml')]
        if not args.no_ru_rules:
            rule_paths.append(os.path.join(config_dir, 'ru_rules.yaml'))
        config['rule_paths'] = rule_paths
        
        # 3. Инициализация движка сканирования
        engine = ScanEngine(config)

        # 4. Запуск сканирования
        findings = engine.run(args.path, args.scan_git)

        # 5. Фильтрация результатов по уровню уверенности
        # Находки без оценки confidence считаются как 0.5 (средняя)
        final_findings = [f for f in findings if (f.confidence or 0.5) >= args.min_confidence]

        # 6. Выбор и запуск репортера
        # Загружаем правила еще раз, чтобы передать их в репортер для вывода описаний
        rules = RuleLoader(config['rule_paths']).load_rules()
        reporters = {
            'console': ConsoleReporter(rules),
            'json': JSONReporter(rules),
            'html': HTMLReporter(rules)
        }
        reporter = reporters[args.report_format]
        reporter.generate_report(final_findings, args.output_file)

    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем.")
        sys.exit(1)
    except Exception as e:
        print(f"\nПроизошла критическая ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
