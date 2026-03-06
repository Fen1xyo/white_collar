# secret-scanner/scanner/parsers/base.py
from abc import ABC, abstractmethod
from typing import List, Dict

class BaseParser(ABC):
    @abstractmethod
    def get_tokens(self, content: str, file_path: str) -> List[Dict]:
        pass
