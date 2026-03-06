# secret-scanner/tests/test_engine.py

import os
import pytest
import yaml

# Добавляем путь, чтобы импортировать модули сканера
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.core.engine import ScanEngine

# --- Тестовое окружение ---

# Содержимое тестового файла с Python-кодом
TEST_PYTHON_CONTENT = """
API_KEY_1 = "AKIAIOSFODNN7EXAMPLE" # AWS Key
# Конкатенация
SECRET_PART_1 = "ghp_1234567890"
SECRET_PART_2 = "abcdefghijklmnopqrstuvwxyz"
GITHUB_TOKEN = SECRET_PART_1 + SECRET_PART_2
"""

# Содержимое тестового .env файла
TEST_ENV_CONTENT = "TELEGRAM_BOT_TOKEN=123456789:AAG_Abc123Def456Ghi789Jkl_mnoPQR"

# Содержимое тестовых правил
TEST_RULES_CONTENT = """
rules:
  - id: AWS_ACCESS_KEY
    name: "AWS Access Key ID"
    pattern: 'AKIA[0-9A-Z]{16}'
    severity: CRITICAL
    description: "Test desc"
    remediation: "Test rem"
  - id: GITHUB_TOKEN
    name: "GitHub Token"
    pattern: 'ghp_[a-zA-Z0-9]{36}'
    severity: CRITICAL
    description: "Test desc"
    remediation: "Test rem"
  - id: TELEGRAM_BOT_TOKEN
    name: "Telegram Bot API Token"
    pattern: '\\d{8,10}:AA[A-Za-z0-9_\\-]{33}'
    severity: CRITICAL
    description: "Test desc"
    remediation: "Test rem"
"""

@pytest.fixture
def test_project(tmp_path):
    """
    Pytest-фикстура для создания временной директории с тестовыми файлами.
    """
    project_dir = tmp_path / "test_project"
    project_dir.mkdir()
    
    # Создаем файлы с секретами
    (project_dir / "main.py").write_text(TEST_PYTHON_CONTENT)
    (project_dir / ".env").write_text(TEST_ENV_CONTENT)
    
    # Создаем директорию с конфигами
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "test_rules.yaml").write_text(TEST_RULES_CONTENT)
    
    # Создаем settings.yaml
    settings = {
        'exclude_dirs': ['.git'],
        'scan_extensions': ['.py', '.env']
    }
    (config_dir / "settings.yaml").write_text(yaml.dump(settings))
    
    return project_dir, config_dir

# --- Тесты ---

def test_scan_engine_finds_secrets(test_project):
    """
    Основной интеграционный тест: проверяет, что ScanEngine находит секреты
    в разных типах файлов.
    """
    project_dir, config_dir = test_project
    
    # 1. Настраиваем конфигурацию для движка
    with open(config_dir / "settings.yaml", 'r') as f:
        config = yaml.safe_load(f)
    config['rule_paths'] = [str(config_dir / "test_rules.yaml")]
    
    # 2. Инициализируем и запускаем движок
    engine = ScanEngine(config)
    findings = engine.run(str(project_dir), scan_git=False)
    
    # 3. Проверяем результаты
    assert len(findings) == 3, "Должно быть найдено ровно 3 секрета"
    
    # Создаем словарь для удобного доступа к находкам по ID правила
    findings_by_rule = {f.rule_id: f for f in findings}
    
    # Проверка находки в .py файле (простой случай)
    assert 'AWS_ACCESS_KEY' in findings_by_rule
    aws_finding = findings_by_rule['AWS_ACCESS_KEY']
    assert aws_finding.secret == "AKIAIOSFODNN7EXAMPLE"
    assert "main.py" in aws_finding.file_path
    
    # Проверка находки в .py файле (конкатенация)
    # Важно: наш python_parser должен был склеить строку, но детектор работает построчно.
    # Этот тест покажет, что RegexDetector находит токен в строке `GITHUB_TOKEN = ...`
    # Продвинутый тест мог бы проверять токены из AST.
    assert 'GITHUB_TOKEN' in findings_by_rule
    gh_finding = findings_by_rule['GITHUB_TOKEN']
    assert gh_finding.secret == "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    
    # Проверка находки в .env файле
    assert 'TELEGRAM_BOT_TOKEN' in findings_by_rule
    tg_finding = findings_by_rule['TELEGRAM_BOT_TOKEN']
    assert tg_finding.secret == "123456789:AAG_Abc123Def456Ghi789Jkl_mnoPQR"
    assert ".env" in tg_finding.file_path
