# secret-scanner/scanner/detectors/base.py
from abc import ABC, abstractmethod
from typing import List, Optional
from ..core.finding import Finding

class BaseDetector(ABC):
    @abstractmethod
    def detect(self, content: str, file_path: str, line_number: int, commit: Optional[str] = None) -> List[Finding]:
        pass
