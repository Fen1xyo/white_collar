# secret-scanner/scanner/rules/rule.py
from dataclasses import dataclass

@dataclass
class Rule:
    id: str
    name: str
    pattern: str
    severity: str
    description: str
    remediation: str
