# secret-scanner/scanner/parsers/config_parser.py

import re
import os
from typing import List, Dict, Any, Generator
import yaml
import configparser
from .base import BaseParser

class ConfigParser(BaseParser):
    """
    Универсальный парсер для различных форматов конфигурационных файлов.
    Использует правильный метод парсинга в зависимости от типа файла.
    """
    
    # Regex для .env и Makefile: KEY=VALUE, KEY = VALUE, KEY:=VALUE
    # Захватывает значение, учитывая опциональные кавычки.
    ENV_RE = re.compile(r'^\s*(?:export\s+)?([\w.-]+)\s*[:=]\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s#]+))')
    
    # Regex для requirements.txt: ищет URL с аутентификацией
    REQ_URL_RE = re.compile(r'https?://([^:]+:[^@]+)@')

    def get_tokens(self, content: str, file_path: str) -> List[Dict]:
        """Диспетчер: выбирает метод парсинга на основе имени файла."""
        filename = os.path.basename(file_path).lower()
        ext = os.path.splitext(filename)[1]

        parser_map = {
            '.env': self._parse_env,
            'makefile': self._parse_env, # Makefile имеет схожий синтаксис переменных
            '.yaml': self._parse_yaml,
            '.yml': self._parse_yaml,
            '.ini': self._parse_ini,
            '.cfg': self._parse_ini,
            '.conf': self._parse_ini, # Часто .conf файлы имеют .ini-синтаксис
            'requirements.txt': self._parse_requirements,
        }
        
        # Выбираем парсер для расширения или для имени файла целиком (например, 'Makefile')
        parser_func = parser_map.get(ext, parser_map.get(filename))

        if parser_func:
            try:
                return list(parser_func(content, file_path))
            except Exception as e:
                # Если специализированный парсер упал, переключаемся на простой построчный анализ
                print(f"Ошибка парсинга {file_path} как {filename}: {e}. Используется fallback.")
                return list(self._fallback_scan(content, file_path))
        
        # Если нет специального парсера, просто сканируем построчно
        return list(self._fallback_scan(content, file_path))

    def _fallback_scan(self, content: str, file_path: str) -> Generator[Dict, None, None]:
        """Резервный метод: возвращает каждую непустую строку как токен."""
        for i, line in enumerate(content.splitlines(), 1):
            if line.strip():
                yield {"value": line, "line": i, "file": file_path}

    def _parse_env(self, content: str, file_path: str) -> Generator[Dict, None, None]:
        """Парсит .env-подобные файлы."""
        for i, line in enumerate(content.splitlines(), 1):
            match = self.ENV_RE.match(line)
            if match:
                # match.group(2) - в двойных кавычках, group(3) - в одинарных, group(4) - без кавычек
                value = next((v for v in match.groups()[1:] if v is not None), None)
                if value:
                    yield {"value": value, "line": i, "file": file_path}

    def _parse_yaml(self, content: str, file_path: str) -> Generator[Dict, None, None]:
        """Рекурсивно парсит YAML-файлы, извлекая все строковые значения."""
        try:
            data = yaml.safe_load(content)
            # Номера строк в YAML точно определить сложно, поэтому сканируем и построчно
            yield from self._fallback_scan(content, file_path)
        except yaml.YAMLError:
            # Если YAML невалидный, просто сканируем его как текст
            yield from self._fallback_scan(content, file_path)

    def _parse_ini(self, content: str, file_path: str) -> Generator[Dict, None, None]:
        """Парсит .ini/.cfg файлы."""
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(content)
            for section in parser.sections():
                for key, value in parser.items(section):
                    if value:
                        # Точно определить номер строки сложно, поэтому ищем значение в тексте
                        for i, line in enumerate(content.splitlines(), 1):
                            if value in line:
                                yield {"value": value, "line": i, "file": file_path}
                                break # Нашли первое вхождение, этого достаточно
        except configparser.Error:
            yield from self._fallback_scan(content, file_path)

    def _parse_requirements(self, content: str, file_path: str) -> Generator[Dict, None, None]:
        """Ищет креды в URL в requirements.txt."""
        for i, line in enumerate(content.splitlines(), 1):
            match = self.REQ_URL_RE.search(line)
            if match:
                # Возвращаем часть user:pass
                yield {"value": match.group(1), "line": i, "file": file_path}
