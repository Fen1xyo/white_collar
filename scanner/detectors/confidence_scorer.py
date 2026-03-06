# scanner/detectors/confidence_scorer.py

import re
from ..core.finding import Finding


class ConfidenceScorer:
    """
    Модуль для оценки уверенности [0.0-1.0] для каждой находки.
    """

    TEST_PATH_RE = re.compile(
        r'[/\\](tests?|fixtures|__tests__)[/\\]|test_.*\.py|.*_test\.py', re.I
    )
    EXAMPLE_VALUES_RE = re.compile(
        # ИСПРАВЛЕНО: убрано слово 'example', т.к. оно присутствует в легитимных
        # тестовых токенах AWS (AKIAIOSFODNN7EXAMPLE) и вызывало ложный штраф.
        r'\btest\b|placeholder|dummy|your_?|fake|mock|sample|replace|changeme|xxx',
        re.I
    )
    DOCS_PATH_RE = re.compile(r'[/\\](docs?|examples?)[/\\]|README', re.I)
    COMMENT_LINE_RE = re.compile(r'^\s*#')

    # ИСПРАВЛЕНО: добавлены BITRIX_WEBHOOK и GENERIC_API_KEY —
    # оба правила давали находки, но не получали бонус +0.40 за специфичность,
    # из-за чего итоговый score не преодолевал порог фильтрации.
    SPECIFIC_RULE_IDS = {
        'YANDEX_CLOUD_IAM_TOKEN',
        'YANDEX_CLOUD_API_KEY',
        'VK_API_TOKEN',
        'TELEGRAM_BOT_TOKEN',
        'AWS_ACCESS_KEY',
        'GITHUB_TOKEN',
        'PRIVATE_KEY',
        'BITRIX_WEBHOOK',
        'GENERIC_API_KEY',
    }

    KEYWORD_RE = re.compile(
        r'(password|secret|token|key|passwd|pwd|api_key|apikey|access_token|auth_token)',
        re.I
    )

    def score(self, finding: Finding) -> Finding:
        """
        Присваивает оценку уверенности (confidence) находке, модифицируя объект Finding.
        """
        score = 0.5  # Базовая оценка

        # --- Применяем факторы СНИЖЕНИЯ ---
        if self.TEST_PATH_RE.search(finding.file_path):
            score -= 0.35

        if self.EXAMPLE_VALUES_RE.search(finding.secret):
            score -= 0.30

        if len(finding.secret) < 12 and finding.rule_id == 'GENERIC_API_KEY':
            score -= 0.20

        if self.DOCS_PATH_RE.search(finding.file_path):
            score -= 0.25

        # Значительно снижаем уверенность, если находка находится в строке-комментарии.
        # Это отсеивает закомментированные секреты (например, # OLD_KEY = "...").
        if self.COMMENT_LINE_RE.search(finding.line_content):
            score -= 0.40

        # --- Применяем факторы ПОВЫШЕНИЯ ---
        if finding.rule_id in self.SPECIFIC_RULE_IDS:
            score += 0.40

        if finding.rule_id == 'HIGH_ENTROPY_STRING':
            score += 0.25

        # ИСПРАВЛЕНО: теперь line_content содержит полную строку кода (с именем
        # переменной), поэтому KEYWORD_RE корректно срабатывает на слова
        # 'token', 'key', 'password' и т.д. в именах переменных.
        if self.KEYWORD_RE.search(finding.line_content):
            score += 0.20

        if not self.TEST_PATH_RE.search(finding.file_path):
            score += 0.10

        finding.confidence = max(0.0, min(1.0, round(score, 2)))
        return finding