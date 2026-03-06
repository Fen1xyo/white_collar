# secret-scanner/scanner/reporters/base.py
from abc import ABC, abstractmethod
from typing import List, Optional
from ..core.finding import Finding
from ..rules.rule import Rule

class BaseReporter(ABC):
    def __init__(self, rules: List[Rule]):
        self.rules_map = {rule.id: rule for rule in rules}

    @abstractmethod
    def generate_report(self, findings: List[Finding], output_file: Optional[str] = None):
        pass
