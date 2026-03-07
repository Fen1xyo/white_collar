# scanner/detectors/entropy_detector.py

import math
import re
from typing import List, Optional

from .base import BaseDetector
from ..core.finding import Finding

# ─────────────────────────────────────────────────────────────────────────────
# Шаг 1: определяем, содержит ли строка «секретное» ключевое слово.
# Ищем его как отдельное слово (не обязательно в начале переменной):
#   OAUTH_ID  → oauth ✓
#   DB_PASSWORD → password ✓
#   MY_API_KEY → api ✓
# ─────────────────────────────────────────────────────────────────────────────
_KEYWORD_RE = re.compile(
    r'(?i)(?<![a-z])(?:'
    r'key|secret|token|password|passwd|pwd'
    r'|auth|oauth|credential|cred|api|private|bearer|hash|salt'
    r')(?![a-z])',
)

# ─────────────────────────────────────────────────────────────────────────────
# Шаг 2: извлекаем строковые значения из строки кода.
# Ищем всё, что находится внутри одинарных или двойных кавычек, длиной >= 10.
# Не ограничиваем алфавит — ловим любые символы, кроме самой кавычки и перевода строки.
# ─────────────────────────────────────────────────────────────────────────────
_QUOTED_VALUE_RE = re.compile(
    r'(?:"([^"\r\n]{10,})"'   # двойные кавычки
    r"|'([^'\r\n]{10,})')",   # одинарные кавычки
)

# ─────────────────────────────────────────────────────────────────────────────
# Режим 2 (без явного имени переменной):
# длинная строка >= 40 символов, только «безопасный» алфавит (Base64/hex/alnum)
# ─────────────────────────────────────────────────────────────────────────────
_BARE_LONG_STRING_RE = re.compile(
    r'(?:"([A-Za-z0-9+/=_\-]{40,})"'
    r"|'([A-Za-z0-9+/=_\-]{40,})')",
)

# Символьные множества для определения типа строки
_HEX   = set('0123456789abcdefABCDEF')
_B64   = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
_ALNUM = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')

# Значения, которые явно являются заглушками
_PLACEHOLDER_RE = re.compile(
    r'(?i)\b(?:placeholder|dummy|fake|mock|sample|example|replace|changeme|test|demo)\b'
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def _qualifies_as_secret(value: str, has_keyword_context: bool) -> bool:
    """
    Проверяет, является ли строка потенциальным секретом на основе энтропии.

    Если есть контекст ключевого слова (has_keyword_context=True) — пороги мягче,
    потому что само имя переменной уже является сигналом.
    """
    length = len(value)
    if length < 10:
        return False

    # Явная заглушка → пропускаем
    if _PLACEHOLDER_RE.search(value):
        return False

    entropy = _shannon_entropy(value)

    if has_keyword_context:
        # Контекст есть → умеренные пороги
        if all(c in _HEX for c in value) and length >= 20:
            return entropy >= 2.8
        if all(c in _B64 for c in value):
            return entropy >= 3.2
        if all(c in _ALNUM for c in value):
            return entropy >= 3.0
        # Смешанные (со спецсимволами) — ещё мягче, т.к. спецсимволы сами по себе сигнал
        return entropy >= 2.5 and length >= 12
    else:
        # Нет контекста → строгие пороги
        if all(c in _HEX for c in value) and length >= 32:
            return entropy >= 3.5
        if all(c in _B64 for c in value) and length >= 40:
            return entropy >= 4.5
        return False


class EntropyDetector(BaseDetector):
    """
    Детектор на основе энтропии Шеннона.

    Работает в два шага:
      1. Проверяем, есть ли в строке кода «секретное» ключевое слово
         (key, token, oauth, password, api, auth и т.д.). Если есть — применяем
         умеренные пороги энтропии к ЛЮБОЙ строке в кавычках на этой строке.
      2. Независимо от ключевых слов ищем очень длинные высокоэнтропийные строки
         (порог строгий, чтобы избежать ложных срабатываний).

    Преимущество перед единым regex-паттерном:
      - Надёжно ловит OAUTH_ID, DB_PASSWORD, MY_API_KEY и аналогичные случаи,
        где ключевое слово находится в любом месте имени переменной.
      - Ловит значения со спецсимволами (^, &, *, ! и т.д.), которые сложно
        покрыть статическим regex-паттерном.
    """

    def detect(
        self,
        content: str,
        file_path: str,
        line_number: int,
        commit: Optional[str] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        has_keyword = bool(_KEYWORD_RE.search(content))

        if has_keyword:
            for match in _QUOTED_VALUE_RE.finditer(content):
                candidate = match.group(1) if match.group(1) is not None else match.group(2)
                if candidate in seen:
                    continue
                if _qualifies_as_secret(candidate, has_keyword_context=True):
                    seen.add(candidate)
                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_number,
                        commit=commit,
                        rule_id="HIGH_ENTROPY_STRING",
                        rule_name="High Entropy String (Secret Variable)",
                        severity="HIGH",
                        secret=candidate,
                        line_content=content.strip(),
                    ))

        for match in _BARE_LONG_STRING_RE.finditer(content):
            candidate = match.group(1) if match.group(1) is not None else match.group(2)
            if candidate in seen:
                continue
            if _qualifies_as_secret(candidate, has_keyword_context=False):
                seen.add(candidate)
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_number,
                    commit=commit,
                    rule_id="HIGH_ENTROPY_STRING",
                    rule_name="High Entropy String (Bare)",
                    severity="MEDIUM",
                    secret=candidate,
                    line_content=content.strip(),
                ))

        return findings