# VeriAudit - Shared data schemas
# This is the single source of truth for all data structures in the system.
# Every other module imports types from here.
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator


# =============================
# ID Generation
# =============================

def gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# =============================
# Path Constants
# =============================

class Paths:
    WORKSPACE_ROOT = "./workspace"
    REPOS_DIR = "./workspace/repos"
    LEDGERS_DIR = "./workspace/ledgers"
    CPG_DIR = "./workspace/cpg"
    EVIDENCE_DIR = "./workspace/evidence"
    RESULTS_DIR = "./results"
    INDEX_DB_PATH = "./workspace/index.db"
    TEMP_DIR = "/tmp/veriaudit"


# =============================
# Finding Status
# =============================

class FindingStatus(str, Enum):
    RAW = "raw"
    CANDIDATE = "candidate"
    VERIFIED_STATIC = "verified_static"
    PENDING_DYNAMIC_VALIDATION = "pending_dynamic_validation"
    REACHABLE = "reachable"
    EXPLOITABLE = "exploitable"
    CONFIRMED_EXPLOITED = "confirmed_exploited"
    REJECTED = "rejected"
    UNREPRODUCIBLE = "unreproducible"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"


# Legal state transitions (separate from enum to avoid enum-value conflicts)
FINDING_TRANSITIONS: dict[FindingStatus, list[FindingStatus]] = {
    FindingStatus.RAW: [FindingStatus.CANDIDATE, FindingStatus.REJECTED, FindingStatus.FALSE_POSITIVE],
    FindingStatus.CANDIDATE: [FindingStatus.VERIFIED_STATIC, FindingStatus.REACHABLE, FindingStatus.REJECTED, FindingStatus.FALSE_POSITIVE, FindingStatus.INCONCLUSIVE, FindingStatus.PENDING_DYNAMIC_VALIDATION],
    FindingStatus.VERIFIED_STATIC: [FindingStatus.PENDING_DYNAMIC_VALIDATION, FindingStatus.REJECTED, FindingStatus.INCONCLUSIVE],
    FindingStatus.PENDING_DYNAMIC_VALIDATION: [FindingStatus.CONFIRMED_EXPLOITED, FindingStatus.UNREPRODUCIBLE, FindingStatus.FALSE_POSITIVE, FindingStatus.INCONCLUSIVE],
    FindingStatus.REACHABLE: [FindingStatus.EXPLOITABLE, FindingStatus.REJECTED, FindingStatus.INCONCLUSIVE],
    FindingStatus.EXPLOITABLE: [FindingStatus.CONFIRMED_EXPLOITED, FindingStatus.UNREPRODUCIBLE, FindingStatus.REJECTED],
    FindingStatus.CONFIRMED_EXPLOITED: [],
    FindingStatus.REJECTED: [],
    FindingStatus.UNREPRODUCIBLE: [],
    FindingStatus.FALSE_POSITIVE: [],
    FindingStatus.INCONCLUSIVE: [FindingStatus.CANDIDATE],
}


@classmethod
def _can_transition(cls, from_: FindingStatus, to: FindingStatus) -> bool:
    allowed = FINDING_TRANSITIONS.get(from_, [])
    return to in allowed


@classmethod
def _is_terminal(cls, status: FindingStatus) -> bool:
    return len(FINDING_TRANSITIONS.get(status, [])) == 0


@classmethod
def _is_confirmed(cls, status: FindingStatus) -> bool:
    return status == FindingStatus.CONFIRMED_EXPLOITED


@classmethod
def _get_allowed(cls, status: FindingStatus) -> list[FindingStatus]:
    return list(FINDING_TRANSITIONS.get(status, []))


# Monkey-patch classmethods onto FindingStatus (Pydantic Enum pattern)
FindingStatus.can_transition = _can_transition  # type: ignore[assignment]
FindingStatus.is_terminal = _is_terminal  # type: ignore[assignment]
FindingStatus.is_confirmed = _is_confirmed  # type: ignore[assignment]
FindingStatus.get_allowed = _get_allowed  # type: ignore[assignment]


# =============================
# Severity
# =============================

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================
# CWE
# =============================

class CWE(str, Enum):
    CWE_22 = "CWE-22"       # Path Traversal
    CWE_77 = "CWE-77"       # Command Injection
    CWE_78 = "CWE-78"       # OS Command Injection
    CWE_79 = "CWE-79"       # XSS
    CWE_89 = "CWE-89"       # SQL Injection
    CWE_90 = "CWE-90"       # LDAP Injection
    CWE_119 = "CWE-119"     # Buffer Overflow (generic)
    CWE_120 = "CWE-120"     # Buffer Copy without Size Check
    CWE_121 = "CWE-121"     # Stack Buffer Overflow
    CWE_122 = "CWE-122"     # Heap Buffer Overflow
    CWE_125 = "CWE-125"     # Out-of-bounds Read
    CWE_134 = "CWE-134"     # Format String
    CWE_190 = "CWE-190"     # Integer Overflow
    CWE_191 = "CWE-191"     # Integer Underflow
    CWE_259 = "CWE-259"     # Hardcoded Password
    CWE_362 = "CWE-362"     # Race Condition
    CWE_366 = "CWE-366"     # Race Condition within a Thread
    CWE_367 = "CWE-367"     # TOCTOU
    CWE_415 = "CWE-415"     # Double Free
    CWE_416 = "CWE-416"     # Use After Free
    CWE_476 = "CWE-476"     # NULL Pointer Dereference
    CWE_502 = "CWE-502"     # Deserialization
    CWE_611 = "CWE-611"     # XXE
    CWE_787 = "CWE-787"     # Out-of-bounds Write
    CWE_798 = "CWE-798"     # Hardcoded Credentials
    CWE_918 = "CWE-918"     # SSRF


# =============================
# Source & Sink Types
# =============================

class SourceType(str, Enum):
    FILE_INPUT = "file_input"
    NETWORK_INPUT = "network_input"
    USER_PARAM = "user_param"
    ENV_VARIABLE = "env_variable"
    DB_RESULT = "db_result"
    API_RESPONSE = "api_response"
    RAG_CONTEXT = "rag_context"
    FILE_METADATA = "file_metadata"


class SinkType(str, Enum):
    MEMORY_WRITE = "memory_write"
    MEMORY_ALLOC = "memory_alloc"
    SHELL_EXEC = "shell_exec"
    SQL_EXEC = "sql_exec"
    FILE_WRITE = "file_write"
    NETWORK_SEND = "network_send"
    CODE_EVAL = "code_eval"


# Source x Sink -> Vulnerability Type Mapping
SOURCE_SINK_TO_CWE = {
    (SourceType.FILE_INPUT,     SinkType.MEMORY_WRITE): CWE.CWE_122,
    (SourceType.FILE_INPUT,     SinkType.MEMORY_ALLOC): CWE.CWE_190,
    (SourceType.USER_PARAM,     SinkType.SHELL_EXEC):   CWE.CWE_78,
    (SourceType.NETWORK_INPUT,  SinkType.SHELL_EXEC):   CWE.CWE_78,
    (SourceType.USER_PARAM,     SinkType.SQL_EXEC):     CWE.CWE_89,
    (SourceType.USER_PARAM,     SinkType.FILE_WRITE):   CWE.CWE_22,
    (SourceType.USER_PARAM,     SinkType.CODE_EVAL):    CWE.CWE_502,
    (SourceType.FILE_METADATA,  SinkType.MEMORY_WRITE): CWE.CWE_122,
    (SourceType.NETWORK_INPUT,  SinkType.NETWORK_SEND): CWE.CWE_918,
    (SourceType.API_RESPONSE,   SinkType.SHELL_EXEC):   CWE.CWE_78,
}


# =============================
# Code Location
# =============================

class CodeLocation(BaseModel):
    file: str
    line_start: int
    line_end: Optional[int] = None
    function: Optional[str] = None
    code_snippet: Optional[str] = None


# =============================
# Evidence Reference
# =============================

class EvidenceRef(BaseModel):
    ref_id: str = Field(default_factory=lambda: gen_id("evref"))
    artifact_type: str  # "asan_log" | "stacktrace" | "gdb_bt" | "llm_analysis" | "sarif" | ...
    uri: str            # file path or artifact ID
    description: str = ""
    content_hash: Optional[str] = None


# =============================
# Finding
# =============================

class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: gen_id("F"))
    correlation_id: str = ""
    status: FindingStatus = FindingStatus.RAW
    source_tool: str = ""           # "semgrep" | "codeql" | "cppcheck" | "clang_tidy" | "gitleaks"
    rule_id: str = ""               # e.g. "cpp/overrunning-write"
    location: CodeLocation = Field(default_factory=lambda: CodeLocation(file="", line_start=0))
    message: str = ""               # Original tool message
    severity: Severity = Severity.INFO
    cwe: Optional[CWE] = None
    confidence: str = "medium"      # "high" | "medium" | "low"

    # Taint analysis (filled by CPG/Taint Agent)
    source_type: Optional[SourceType] = None
    sink_type: Optional[SinkType] = None
    call_path: List[CodeLocation] = Field(default_factory=list)
    sanitizers_found: List[str] = Field(default_factory=list)

    # Evidence references
    evidence: List[EvidenceRef] = Field(default_factory=list)

    # LLM analysis (informational, NOT used as verdict basis)
    llm_analysis: Optional[str] = None

    # Ruling
    ruling: Optional[str] = None
    ruling_reason: Optional[str] = None
    matched_rule_id: Optional[str] = None

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================
# Raw Finding (SAST tool intermediate format)
# =============================

class RawFinding(BaseModel):
    """Intermediate format produced by SAST tools before normalization."""
    source_tool: str
    rule_id: str
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    message: str
    severity: str         # "error" | "warning" | "note"
    cwe: Optional[str] = None
    confidence: str = "medium"


# =============================
# Event Ledger
# =============================

class EventType(str, Enum):
    # Session
    AUDIT_SESSION_CREATED = "audit.session.created"
    AUDIT_SESSION_COMPLETED = "audit.session.completed"
    AUDIT_SESSION_ABORTED = "audit.session.aborted"
    # Repo
    REPO_CLONED = "repo.cloned"
    REPO_PARSED = "repo.parsed"
    # Build
    BUILD_CONFIGURED = "build.configured"
    BUILD_COMPILED = "build.compiled"
    # Analysis
    ANALYSIS_TOOL_INVOKED = "analysis.tool_invoked"
    ANALYSIS_RAW_FINDING_EMITTED = "analysis.raw_finding_emitted"
    ANALYSIS_FINDING_PROMOTED = "analysis.finding_promoted"
    ANALYSIS_FINDING_REJECTED = "analysis.finding_rejected"
    ANALYSIS_CPG_IMPORTED = "analysis.cpg_imported"
    ANALYSIS_TAINT_PATH_FOUND = "analysis.taint_path_found"
    # Fuzz
    FUZZ_TARGET_DISCOVERED = "fuzz.target_discovered"
    FUZZ_SESSION_STARTED = "fuzz.session_started"
    FUZZ_CRASH_FOUND = "fuzz.crash_found"
    FUZZ_CRASH_MINIMIZED = "fuzz.crash_minimized"
    FUZZ_CRASH_DEDUPLICATED = "fuzz.crash_deduplicated"
    # Exploit
    EXPLOIT_POC_GENERATED = "exploit.poc_generated"
    EXPLOIT_POC_EXECUTED = "exploit.poc_executed"
    EXPLOIT_SANITIZER_REPORT = "exploit.sanitizer_report"
    EXPLOIT_STACK_TRACE = "exploit.stack_trace"
    # Verification
    VERIFICATION_DYNAMIC_NOT_IMPLEMENTED = "verification.dynamic_not_implemented"
    # Judge
    JUDGE_RULING_MADE = "judge.ruling_made"
    JUDGE_EVIDENCE_BUNDLE_CREATED = "judge.evidence_bundle_created"
    # Agent
    AGENT_TOOL_CALL = "agent.tool_call"
    AGENT_TOOL_RESULT = "agent.tool_result"
    AGENT_LLM_CALL = "agent.llm_call"
    # Report
    REPORT_GENERATED = "report.generated"
    # Error
    ERROR_OCCURRED = "error.occurred"


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: gen_id("evt"))
    correlation_id: str = ""
    task_id: Optional[str] = None
    finding_id: Optional[str] = None
    sequence: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType = EventType.AUDIT_SESSION_CREATED
    agent_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        """
        hash = SHA256(prev_hash + canonical_json(payload) + timestamp_iso + event_type_value)
        """
        payload_json = json.dumps(self.payload, sort_keys=True, default=str, ensure_ascii=False)
        ts_iso = self.timestamp.isoformat()
        raw = f"{self.prev_hash}{payload_json}{ts_iso}{self.event_type.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def model_post_init(self, __context):
        if not self.hash:
            self.hash = self.compute_hash()


# =============================
# Taint Path (from CPG)
# =============================

class TaintEdge(BaseModel):
    function: str
    file: str
    line: int


class TaintPath(BaseModel):
    source: CodeLocation
    sink: CodeLocation
    source_type: SourceType
    sink_type: SinkType
    edges: List[TaintEdge] = Field(default_factory=list)
    sanitizers_found: List[str] = Field(default_factory=list)
    path_length: int = 0


# =============================
# Build
# =============================

class BuildType(str, Enum):
    DEBUG = "debug"
    RELEASE = "release"
    ASAN = "asan"
    UBSAN = "ubsan"
    MSAN = "msan"
    FUZZER = "fuzzer"
    COVERAGE = "coverage"


class BuildResult(BaseModel):
    build_type: BuildType = BuildType.DEBUG
    build_dir: str = ""
    binary_path: Optional[str] = None
    compile_commands_path: Optional[str] = None
    success: bool = False
    stderr: str = ""
    container_id: str = ""
    exit_code: int = -1


class SanitizerConfig(BaseModel):
    available: List[str] = Field(default_factory=list)  # ["asan", "ubsan", "msan"]
    compiler: str = "clang"
    flags: Dict[str, str] = Field(default_factory=dict)


class FuzzConfig(BaseModel):
    engine: str = "libfuzzer"   # "libfuzzer" | "afl" | "go-fuzz" | "jazzer" | ...
    harness_template: str = ""
    extra_flags: List[str] = Field(default_factory=list)


# =============================
# Project Profile
# =============================

class EntryPoint(BaseModel):
    name: str
    file: str
    line: int
    type: str  # "cli_main" | "public_api" | "parser_entry" | "http_handler" | "network_listener"


class DangerousCall(BaseModel):
    function: str
    file: str
    line: int
    category: str  # "mem_unsafe" | "integer" | "format_string" | "command_exec" | "file_ops" | "code_eval"


class ProjectProfile(BaseModel):
    correlation_id: str = ""
    task_id: Optional[str] = None
    repo_url: str = ""
    commit_sha: Optional[str] = None
    local_path: Optional[str] = None
    repo_path: str = ""
    language: str = "unknown"
    build_system: str = "unknown"
    frameworks: List[str] = Field(default_factory=list)
    file_count: int = 0
    total_loc: int = 0
    dependencies: List[str] = Field(default_factory=list)
    has_fuzz_targets: bool = False
    has_ci_fuzz: bool = False
    fuzz_targets: List[str] = Field(default_factory=list)
    sast_tools: List[str] = Field(default_factory=list)
    active_vuln_classes: List[str] = Field(default_factory=list)
    entry_points: List[EntryPoint] = Field(default_factory=list)
    dangerous_calls: List[DangerousCall] = Field(default_factory=list)
    complexity: str = "unknown"  # "low" | "medium" | "high"


# =============================
# Audit Plan & Request
# =============================

class AuditMode(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class AuditPlan(BaseModel):
    correlation_id: str = ""
    mode: AuditMode = AuditMode.STANDARD
    selected_skills: List[str] = Field(default_factory=list)
    phases: List[Dict[str, Any]] = Field(default_factory=list)
    estimated_hours: float = 0.0
    risk_modules: List[str] = Field(default_factory=list)
    sast_tools: List[str] = Field(default_factory=list)
    active_vuln_classes: List[str] = Field(default_factory=list)


class AuditRequest(BaseModel):
    repo_url: str = ""
    commit: Optional[str] = None
    mode: AuditMode = AuditMode.STANDARD
    local_path: Optional[str] = None
    task_id: Optional[str] = None


# =============================
# Audit Report
# =============================

class FindingSummary(BaseModel):
    finding_id: str
    status: FindingStatus
    severity: Severity
    cwe: Optional[CWE] = None
    title: str = ""
    file: str = ""
    line: int = 0


class AuditReport(BaseModel):
    correlation_id: str = ""
    task_id: Optional[str] = None
    project_url: str = ""
    commit_sha: str = ""
    mode: AuditMode = AuditMode.STANDARD
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: str = "running"  # "running" | "completed" | "failed"

    # Counts
    total_raw: int = 0
    total_candidates: int = 0
    total_reachable: int = 0
    total_exploitable: int = 0
    total_confirmed: int = 0
    total_rejected: int = 0
    total_unreproducible: int = 0
    total_false_positive: int = 0
    total_inconclusive: int = 0

    confirmed_findings: List[FindingSummary] = Field(default_factory=list)
    all_findings: List[Dict[str, Any]] = Field(default_factory=list)
    project_profile: Optional[Dict[str, Any]] = None
    ledger_integrity: Optional[Dict[str, Any]] = None
    report_paths: Dict[str, str] = Field(default_factory=dict)
    duration_seconds: float = 0.0
    errors: List[str] = Field(default_factory=list)


# =============================
# Judge Rules
# =============================

class JudgeRule(BaseModel):
    rule_id: str
    condition: str     # Human-readable condition
    verdict: FindingStatus
    confidence: float
    priority: int      # Lower = higher priority


# =============================
# Contradiction
# =============================

class Contradiction(BaseModel):
    finding_a: str
    finding_b: str
    reason: str
    severity: str = "warning"  # "error" | "warning"


# =============================
# MCP Tool Interface
# =============================

class MCPToolCall(BaseModel):
    call_id: str = Field(default_factory=lambda: gen_id("call"))
    tool_name: str = ""        # "sast_mcp.run_semgrep"
    params: Dict[str, Any] = Field(default_factory=dict)
    caller_agent: str = ""
    correlation_id: str = ""


class MCPToolResult(BaseModel):
    call_id: str = ""
    tool_name: str = ""
    success: bool = False
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: int = 0


# =============================
# Agent Message
# =============================

class AgentIntent(str, Enum):
    DISPATCH_TASK = "dispatch_task"
    REPORT_RESULT = "report_result"
    REQUEST_CLARIFICATION = "request_clarification"
    ESCALATE = "escalate"


class AgentMessage(BaseModel):
    message_id: str = Field(default_factory=lambda: gen_id("msg"))
    correlation_id: str = ""
    from_agent: str = ""
    to_agent: str = "orchestrator"
    intent: AgentIntent = AgentIntent.REPORT_RESULT
    payload: Dict[str, Any] = Field(default_factory=dict)
    artifact_refs: List[str] = Field(default_factory=list)
    parent_message_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================
# Dynamic Verification
# =============================

class DynamicVerificationRequest(BaseModel):
    finding_id: str
    vulnerability_type: str   # "sql_injection" | "command_injection" | ...
    file_path: str
    line: Optional[int] = None
    static_evidence: Dict[str, Any] = Field(default_factory=dict)
    suggested_payloads: List[str] = Field(default_factory=list)


class DynamicVerificationResult(BaseModel):
    status: str  # "NOT_IMPLEMENTED" | "CONFIRMED" | "FAILED" | ...
    evidence_dir: Optional[str] = None
    reproducible: bool = False
    attempts: int = 0
    logs: List[str] = Field(default_factory=list)


# =============================
# SANITIZER HELPERS
# =============================

SANITIZER_ERROR_PATTERNS = {
    "heap-buffer-overflow": {
        "keywords": ["heap-buffer-overflow", "WRITE of size", "READ of size"],
        "cwe": CWE.CWE_122,
    },
    "stack-buffer-overflow": {
        "keywords": ["stack-buffer-overflow"],
        "cwe": CWE.CWE_121,
    },
    "heap-use-after-free": {
        "keywords": ["heap-use-after-free"],
        "cwe": CWE.CWE_416,
    },
    "double-free": {
        "keywords": ["double-free"],
        "cwe": CWE.CWE_415,
    },
    "signed-integer-overflow": {
        "keywords": ["signed integer overflow"],
        "cwe": CWE.CWE_190,
    },
    "nullptr-dereference": {
        "keywords": ["SEGV on unknown address", "SIGSEGV"],
        "cwe": CWE.CWE_476,
    },
}

SYSTEM_LIB_PREFIXES = [
    "/usr/lib/", "/usr/local/lib/", "/lib/",
    "libc.", "libstdc++", "libgcc", "ld-linux",
    "__libc_", "__GI_", "_start",
]
