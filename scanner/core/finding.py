# secret-scanner/scanner/core/finding.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    file_path: str
    line_number: int
    commit: Optional[str]
    rule_id: str
    rule_name: str
    severity: str
    secret: str
    line_content: str
    confidence: Optional[float] = None
    whitelisted: bool = False

    def __post_init__(self):
        if len(self.line_content) > 200:
            self.line_content = self.line_content[:200] + "..."
        if self.commit and len(self.commit) > 7:
            self.commit = self.commit[:7]

    def __hash__(self):
        return hash((self.file_path, self.line_number, self.rule_id, self.commit))

    def __eq__(self, other):
        if not isinstance(other, Finding): return NotImplemented
        return (self.file_path == other.file_path and
                self.line_number == other.line_number and
                self.rule_id == other.rule_id and
                self.commit == other.commit)
