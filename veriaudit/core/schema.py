"""Shared data structures for VeriAudit.

This is the foundation module. All three persons (A, B, C) depend on these types.
Any modification requires all three persons' approval.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ────────────────────────────────────────────────────────────
# Path constants — shared by all modules
# ────────────────────────────────────────────────────────────
WORKSPACE_ROOT = "./workspace"
REPOS_DIR = "./workspace/repos"
LEDGERS_DIR = "./workspace/ledgers"
EVIDENCE_DIR = "./workspace/evidence"
RESULTS_DIR = "./results"
INDEX_DB_PATH = "./workspace/index.db"
TEMP_DIR = "/tmp/veriaudit"


# ────────────────────────────────────────────────────────────
# Finding Status
# ────────────────────────────────────────────────────────────
class FindingStatus(str, Enum):
    """Finding lifecycle states.

    Transition graph:
        RAW ──────────────────→ REJECTED_STATIC
         │
         └──→ CANDIDATE ──────→ REJECTED_STATIC
                 │              → INCONCLUSIVE (↩ CANDIDATE)
                 │
                 └──→ VERIFIED_STATIC → PENDING_DYNAMIC_VALIDATION
                                            │
                                            └──→ DYNAMIC_NOT_IMPLEMENTED (terminal)
                                            └──→ INCONCLUSIVE (terminal)
    """

    RAW = "raw"
    CANDIDATE = "candidate"
    REJECTED_STATIC = "rejected_static"
    VERIFIED_STATIC = "verified_static"
    PENDING_DYNAMIC_VALIDATION = "pending_dynamic_validation"
    DYNAMIC_NOT_IMPLEMENTED = "dynamic_not_implemented"
    INCONCLUSIVE = "inconclusive"
    # Reserved for future dynamic verification implementation:
    # CONFIRMED_EXPLOITED = "confirmed_exploited"
    # UNREPRODUCIBLE = "unreproducible"
    # FALSE_POSITIVE = "false_positive"

    TRANSITIONS: Dict["FindingStatus", List["FindingStatus"]] = {
        RAW: [CANDIDATE, REJECTED_STATIC],
        CANDIDATE: [VERIFIED_STATIC, REJECTED_STATIC, INCONCLUSIVE],
        VERIFIED_STATIC: [PENDING_DYNAMIC_VALIDATION],
        PENDING_DYNAMIC_VALIDATION: [DYNAMIC_NOT_IMPLEMENTED, INCONCLUSIVE],
        REJECTED_STATIC: [],
        DYNAMIC_NOT_IMPLEMENTED: [],
        INCONCLUSIVE: [CANDIDATE],
    }

    TERMINAL: set["FindingStatus"] = {
        REJECTED_STATIC,
        DYNAMIC_NOT_IMPLEMENTED,
        INCONCLUSIVE,
    }

    @classmethod
    def is_terminal(cls, status: "FindingStatus") -> bool:
        """Return True if the status is a terminal (immutable) state."""
        return status in cls.TERMINAL

    @classmethod
    def can_transition(cls, from_status: "FindingStatus", to_status: "FindingStatus") -> bool:
        """Return True if the transition from → to is valid."""
        return to_status in cls.TRANSITIONS.get(from_status, [])

    def __str__(self) -> str:
        return self.value


# ────────────────────────────────────────────────────────────
# Finding
# ────────────────────────────────────────────────────────────
class Finding(BaseModel):
    """A single vulnerability finding.

    Core data model shared by all three persons.
    """

    finding_id: str = Field(description="Unique ID: F-xxxxxxxxxxxx (12 hex chars)")
    task_id: str = Field(description="Parent audit task ID")
    status: FindingStatus = Field(default=FindingStatus.RAW)
    source_tool: str = Field(description="Tool that produced this finding: semgrep | bandit | gitleaks")
    rule_id: str = Field(description="Tool-specific rule ID")
    file_path: str = Field(description="Path relative to repo root")
    line_start: int = Field(ge=1, description="Start line number (1-based)")
    line_end: Optional[int] = Field(default=None, ge=1, description="End line number (1-based)")
    code_snippet: Optional[str] = Field(default=None)
    message: str = Field(description="Original tool message")
    severity: str = Field(default="info", description="critical | high | medium | low | info")
    cwe: Optional[str] = Field(default=None, description="CWE identifier, e.g. CWE-89")
    confidence: str = Field(default="medium", description="high | medium | low")
    llm_analysis: Optional[str] = Field(default=None, description="LLM analysis explanation")
    call_path: List[Dict[str, Any]] = Field(default_factory=list, description="Call path entries")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Evidence entries")
    ruling: Optional[str] = Field(default=None, description="Final judge ruling")
    ruling_reason: Optional[str] = Field(default=None, description="Why the judge made this ruling")
    matched_rule_id: Optional[str] = Field(default=None, description="Which judge rule matched")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("source_tool")
    @classmethod
    def validate_source_tool(cls, v: str) -> str:
        allowed = {"semgrep", "bandit", "gitleaks", "manual"}
        if v not in allowed:
            raise ValueError(f"source_tool must be one of {allowed}, got {v!r}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {allowed}, got {v!r}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: str) -> str:
        allowed = {"high", "medium", "low"}
        if v not in allowed:
            raise ValueError(f"confidence must be one of {allowed}, got {v!r}")
        return v

    class Config:
        use_enum_values = True


# ────────────────────────────────────────────────────────────
# Audit Event (Event Ledger entry)
# ────────────────────────────────────────────────────────────
class AuditEvent(BaseModel):
    """A single entry in the append-only Event Ledger.

    Hash formula:
        hash = SHA256(prev_hash + canonical_json(payload) + timestamp + event_type)
    """

    event_id: str = Field(description="Unique ID: evt-xxxxxxxxxxxx (12 hex chars)")
    task_id: str
    finding_id: Optional[str] = Field(default=None, description="Null for non-finding events")
    seq: int = Field(ge=0, description="Global monotonically increasing sequence number")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str = Field(description="Event type: repo.cloned | analysis.raw_finding_emitted | ...")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary JSON payload")
    prev_hash: str = Field(description="SHA-256 hash of the previous event")
    hash: str = Field(description="SHA-256 hash of this event")

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash of this event.

        Implementation detail:
            hash = SHA256(prev_hash + canonical_json(payload) + timestamp.isoformat() + event_type)
        """
        import hashlib
        import json

        payload_str = json.dumps(self.payload, sort_keys=True, ensure_ascii=False)
        data = self.prev_hash + payload_str + self.timestamp.isoformat() + self.event_type
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    class Config:
        use_enum_values = True


# ────────────────────────────────────────────────────────────
# Project Profile
# ────────────────────────────────────────────────────────────
class ProjectProfile(BaseModel):
    """Repository analysis result produced by Person B's RepoParser."""

    task_id: str
    repo_url: str
    commit_sha: Optional[str] = None
    local_path: Optional[str] = None
    language: str = Field(default="unknown", description="python | php | javascript | typescript | unknown")
    frameworks: List[str] = Field(default_factory=list)
    file_count: int = Field(default=0)
    total_loc: int = Field(default=0)
    dependencies: List[str] = Field(default_factory=list)
    entry_points: List[Dict[str, Any]] = Field(
        default_factory=list,
        description='e.g. [{"file": "index.php", "type": "web_entry"}]',
    )


# ────────────────────────────────────────────────────────────
# Audit Report
# ────────────────────────────────────────────────────────────
class AuditReport(BaseModel):
    """Final audit report produced by Person C's ReportGenerator."""

    task_id: str
    project: ProjectProfile
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: str = Field(default="running", description="running | completed | failed")
    total_raw: int = 0
    total_candidates: int = 0
    total_verified_static: int = 0
    total_rejected_static: int = 0
    total_pending_dynamic: int = 0
    total_dynamic_not_implemented: int = 0
    total_inconclusive: int = 0
    findings: List["Finding"] = Field(default_factory=list)
    report_paths: Dict[str, str] = Field(
        default_factory=dict,
        description='{"html": "...", "json": "...", "markdown": "..."}',
    )

    def update_counts(self) -> None:
        """Recalculate all count fields from the findings list."""
        self.total_raw = sum(1 for f in self.findings if f.status == FindingStatus.RAW)
        self.total_candidates = sum(1 for f in self.findings if f.status == FindingStatus.CANDIDATE)
        self.total_verified_static = sum(1 for f in self.findings if f.status == FindingStatus.VERIFIED_STATIC)
        self.total_rejected_static = sum(1 for f in self.findings if f.status == FindingStatus.REJECTED_STATIC)
        self.total_pending_dynamic = sum(1 for f in self.findings if f.status == FindingStatus.PENDING_DYNAMIC_VALIDATION)
        self.total_dynamic_not_implemented = sum(1 for f in self.findings if f.status == FindingStatus.DYNAMIC_NOT_IMPLEMENTED)
        self.total_inconclusive = sum(1 for f in self.findings if f.status == FindingStatus.INCONCLUSIVE)


# ────────────────────────────────────────────────────────────
# Judge Rule
# ────────────────────────────────────────────────────────────
class JudgeRule(BaseModel):
    """A single deterministic judge rule."""

    rule_id: str = Field(description="Rule identifier, e.g. R001")
    condition: str = Field(description="Human-readable condition description")
    verdict: FindingStatus = Field(description="Target status when rule matches")
    confidence: float = Field(ge=0.0, le=1.0, description="Rule confidence score")
    priority: int = Field(ge=1, description="Lower number = higher priority")


# ────────────────────────────────────────────────────────────
# Default Judge Rules
# ────────────────────────────────────────────────────────────
DEFAULT_RULES: List[JudgeRule] = [
    JudgeRule(
        rule_id="R001",
        condition="File path or code line does not exist in repository",
        verdict=FindingStatus.REJECTED_STATIC,
        confidence=0.99,
        priority=1,
    ),
    JudgeRule(
        rule_id="R002",
        condition="Alert located in vendor/test/fixture directory with no business entry point",
        verdict=FindingStatus.REJECTED_STATIC,
        confidence=0.95,
        priority=2,
    ),
    JudgeRule(
        rule_id="R003",
        condition="Parameter already handled by safe API and LLM found no bypass path",
        verdict=FindingStatus.REJECTED_STATIC,
        confidence=0.85,
        priority=3,
    ),
    JudgeRule(
        rule_id="R004",
        condition="Static source→sink evidence exists but no dynamic verification performed",
        verdict=FindingStatus.PENDING_DYNAMIC_VALIDATION,
        confidence=0.90,
        priority=4,
    ),
    JudgeRule(
        rule_id="R005",
        condition="Only LLM reasoning, no tool-based evidence",
        verdict=FindingStatus.INCONCLUSIVE,
        confidence=0.80,
        priority=5,
    ),
    JudgeRule(
        rule_id="R006",
        condition="Secret found but validity not verified",
        verdict=FindingStatus.PENDING_DYNAMIC_VALIDATION,
        confidence=0.85,
        priority=4,
    ),
    JudgeRule(
        rule_id="R007",
        condition="Semgrep/Bandit and LLM analysis agree and code location is verifiable",
        verdict=FindingStatus.VERIFIED_STATIC,
        confidence=0.90,
        priority=4,
    ),
    JudgeRule(
        rule_id="R008",
        condition="Dynamic verification module returned NOT_IMPLEMENTED",
        verdict=FindingStatus.DYNAMIC_NOT_IMPLEMENTED,
        confidence=1.0,
        priority=3,
    ),
]
