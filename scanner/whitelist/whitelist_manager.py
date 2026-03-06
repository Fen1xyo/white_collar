# secret-scanner/scanner/whitelist/whitelist_manager.py

import os
import hashlib
import fnmatch
from typing import List, Dict, Set
from ..core.finding import Finding

class WhitelistManager:
    """
    Управляет белым списком (.secretsignore).
    Загружает правила при инициализации и фильтрует по ним находки.
    """
    def __init__(self, project_path: str):
        self.ignore_file_path = os.path.join(project_path, '.secretsignore')
        self.rules: Dict[str, Set[str]] = {
            'path_pattern': set(),
            'value_hash': set(),
            'specific': set()
        }
        self._load_rules()

    def _load_rules(self):
        """
        Загружает и парсит правила из файла .secretsignore.
        Поддерживает комментарии и пустые строки.
        """
        if not os.path.exists(self.ignore_file_path):
            return
        
        print(f"Загрузка правил из {self.ignore_file_path}...")
        with open(self.ignore_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Пробуем новый формат "тип:значение"
                    rule_type, value = line.split(':', 1)
                    if rule_type in self.rules:
                        self.rules[rule_type].add(value)
                    else:
                        # Если тип правила неизвестен, считаем это старым форматом
                        self.rules['specific'].add(line)
                except ValueError:
                    # Если в строке нет ':', это старый формат (path:line:rule_id)
                    self.rules['specific'].add(line)

    def filter(self, findings: List[Finding]) -> List[Finding]:
        """
        Фильтрует список находок. Не удаляет их, а выставляет флаг `whitelisted = True`.
        """
        for finding in findings:
            if self._is_whitelisted(finding):
                finding.whitelisted = True
        return findings

    def _is_whitelisted(self, finding: Finding) -> bool:
        """
        Проверяет одну находку по всем загруженным правилам белого списка.
        """
        # 1. Проверка по полному совпадению (самый быстрый и специфичный)
        # Формат: path/to/file.py:42:RULE_ID
        specific_identifier = f"{finding.file_path}:{finding.line_number}:{finding.rule_id}"
        if specific_identifier in self.rules['specific']:
            return True
            
        # 2. Проверка по хешу значения секрета
        # Это позволяет игнорировать тестовый ключ во всем проекте
        if self.rules['value_hash']:
            secret_hash = hashlib.sha256(finding.secret.encode()).hexdigest()
            if secret_hash in self.rules['value_hash']:
                return True
        
        # 3. Проверка по паттерну пути файла (самый широкий)
        # Используем fnmatch для поддержки wildcards (*, ?)
        for pattern in self.rules['path_pattern']:
            if fnmatch.fnmatch(finding.file_path, pattern):
                return True
            
        return False
