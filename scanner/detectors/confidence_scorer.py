# scanner/detectors/confidence_scorer.py
import re
from ..core.finding import Finding

class ConfidenceScorer:
    """
    Модуль для оценки уверенности [0.0-1.0] для каждой находки.
    """
    TEST_PATH_RE = re.compile(
        r'[/\\\\](tests?|fixtures|\__tests__)[/\\\\]|test_.*\.py|.*_test\.py', re.I
    )
    EXAMPLE_VALUES_RE = re.compile(
        r'\btest\b|placeholder|dummy|your_?|fake|mock|sample|replace|changeme|xxx', re.I
    )
    DOCS_PATH_RE = re.compile(r'[/\\\\](docs?|examples?)[/\\\\]|README', re.I)
    COMMENT_LINE_RE = re.compile(r'^\s*(#|//|--|/\*)')
    SPECIFIC_RULE_IDS = {
        'AWS_ACCESS_KEY', 'GITHUB_TOKEN', 'PRIVATE_KEY', 'YANDEX_CLOUD_IAM_TOKEN',
        'YANDEX_CLOUD_API_KEY', 'VK_API_TOKEN', 'TELEGRAM_BOT_TOKEN', 'BITRIX_WEBHOOK',
        'GENERIC_API_KEY', 'SELECTEL_API_TOKEN', 'VK_CLOUD_TOKEN', 'TIMEWEB_CLOUD_TOKEN',
        'BEGET_API_KEY', 'REGRU_API_KEY', 'CROC_CLOUD_TOKEN', 'SBERCLOUD_TOKEN',
        'YOOMONEY_SECRET_KEY', 'YOOKASSA_SECRET_KEY', 'TINKOFF_SECRET_KEY', 'QIWI_API_TOKEN',
        'CLOUDPAYMENTS_API_KEY', 'ROBOKASSA_MERCHANT_PASSWORD', 'SBERBANK_MERCHANT_TOKEN',
        'ALFA_BANK_TOKEN', 'PAYMASTER_SECRET', 'MODULBANK_API_KEY', 'TOCHKA_BANK_API_KEY',
        'LIQPAY_PRIVATE_KEY', 'SMSRU_API_ID', 'SMSC_CREDENTIALS', 'SMSAERO_API_KEY',
        'MTS_EXOLVE_API_KEY', 'DEVINO_API_KEY', 'YANDEX_MAPS_API_KEY', 'TWOGIS_API_KEY',
        'YANDEX_METRIKA_TOKEN', 'APPMETRICA_API_KEY', 'DADATA_API_KEY', 'DIADOC_API_KEY',
        'KONTUR_EXTERN_API_KEY', 'SBIS_API_TOKEN', 'KONTUR_FOCUS_API_KEY',
        'AMOCRM_ACCESS_TOKEN', 'RETAILCRM_API_KEY', 'PLANFIX_API_KEY', 'BITRIX24_OAUTH_TOKEN',
        'UNISENDER_API_KEY', 'SENDPULSE_SECRET', 'SENDSAY_API_KEY', 'MAILRU_API_TOKEN',
        'HEADHUNTER_API_TOKEN', 'AVITO_CLIENT_SECRET', 'CDEK_ACCOUNT_CREDENTIALS',
        'WILDBERRIES_API_KEY', 'OZON_API_KEY', 'YANDEX_MARKET_API_TOKEN', 'ESIA_TOKEN',
        'NALOG_RU_API_TOKEN', 'YANDEX_LOCKBOX_SECRET', 'CLICKHOUSE_CLOUD_KEY',
        'ISPMANAGER_API_KEY', 'SMART_TECHNOLOGIES_API', 'JIRA_CONFLUENCE_RU_TOKEN',
    }
    KEYWORD_RE = re.compile(
        r'(password|secret|token|key|passwd|pwd|api_key|apikey|access_token|auth_token'
        r'|webhook|credential|private|client_secret|bearer)', re.I
    )

    def score(self, finding: Finding) -> Finding:
        """ Присваивает оценку уверенности (confidence) находке, модифицируя объект Finding. """
        score = 0.5  # Базовая оценка

        # --- Применяем факторы СНИЖЕНИЯ ---
        if self.EXAMPLE_VALUES_RE.search(finding.secret):
            score -= 0.30
        
        if self.DOCS_PATH_RE.search(finding.file_path):
            score -= 0.25
        
        # ИСПРАВЛЕНО: Штраф за комментарии снижен, чтобы не скрывать потенциальные утечки.
        if self.COMMENT_LINE_RE.search(finding.line_content):
            score -= 0.20

        # --- Применяем факторы ПОВЫШЕНИЯ ---
        if finding.rule_id in self.SPECIFIC_RULE_IDS:
            score += 0.40
        
        if self.KEYWORD_RE.search(finding.line_content):
            score += 0.20
        
        # Небольшой бонус, если это не тестовый файл
        if not self.TEST_PATH_RE.search(finding.file_path):
            score += 0.10

        finding.confidence = max(0.0, min(1.0, round(score, 2)))
        return finding
