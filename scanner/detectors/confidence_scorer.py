# secret-scanner/scanner/detectors/confidence_scorer.py

import re
from ..core.finding import Finding

class ConfidenceScorer:
    """
    Модуль для оценки уверенности [0.0-1.0] для каждой находки.
    Реализует логику из ЧАСТИ 4.5 документа архитектуры.
    """
    
    # --- Факторы, СНИЖАЮЩИЕ уверенность (борьба с ложными срабатываниями) ---
    
    # 1. Пути, характерные для тестов и фикстур
    TEST_PATH_RE = re.compile(r'[/\\](tests?|fixtures|__tests__)[/\\]|test_.*\.py|.*_test\.py', re.I)
    
    # 2. Значения-заглушки
    EXAMPLE_VALUES_RE = re.compile(r'test|example|placeholder|dummy|your_?|fake|mock|sample|replace|changeme|xxx', re.I)
    
    # 3. Пути, характерные для документации
    DOCS_PATH_RE = re.compile(r'[/\\](docs?|examples?)[/\\]|README', re.I)

    # --- Факторы, ПОВЫШАЮЩИЕ уверенность (поиск реальных утечек) ---
    
    # 1. ID правил для очень специфичных и высоко-энтропийных токенов
    SPECIFIC_RULE_IDS = {
        'YANDEX_CLOUD_IAM_TOKEN', 'YANDEX_CLOUD_API_KEY', 'VK_API_TOKEN', 
        'TELEGRAM_BOT_TOKEN', 'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'PRIVATE_KEY'
    }
    
    # 2. Ключевые слова в строке, где найден секрет
    KEYWORD_RE = re.compile(r'(password|secret|token|key|passwd|pwd|api_key|apikey|access_token|auth_token)', re.I)

    def score(self, finding: Finding) -> Finding:
        """
        Присваивает оценку уверенности (confidence) находке, модифицируя объект Finding.
        """
        score = 0.5  # Базовая оценка

        # --- Применяем факторы СНИЖЕНИЯ ---

        # Файл находится в тестовой директории
        if self.TEST_PATH_RE.search(finding.file_path):
            score -= 0.35

        # Найденное значение похоже на плейсхолдер
        if self.EXAMPLE_VALUES_RE.search(finding.secret):
            score -= 0.30

        # Секрет слишком короткий, чтобы быть настоящим
        if len(finding.secret) < 8:
            score -= 0.20
            
        # Файл находится в директории с документацией
        if self.DOCS_PATH_RE.search(finding.file_path):
            score -= 0.25

        # --- Применяем факторы ПОВЫШЕНИЯ ---

        # Сработало очень специфичное правило (например, для токена Yandex Cloud)
        if finding.rule_id in self.SPECIFIC_RULE_IDS:
            score += 0.40
            
        # Сработал детектор высокой энтропии
        if finding.rule_id == 'HIGH_ENTROPY_STRING':
            score += 0.25
            
        # В строке рядом с секретом есть ключевое слово (password, token и т.д.)
        if self.KEYWORD_RE.search(finding.line_content):
            score += 0.20
            
        # Файл НЕ находится в тестовой директории (повышает уверенность)
        if not self.TEST_PATH_RE.search(finding.file_path):
            score += 0.10
            
        # Ограничиваем итоговую оценку диапазоном [0.0, 1.0]
        finding.confidence = max(0.0, min(1.0, round(score, 2)))
        
        return finding
