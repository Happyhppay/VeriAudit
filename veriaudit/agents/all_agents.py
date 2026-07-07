# VeriAudit - Planner, Recon, Static Scan, CPG/Taint, Exploit, Validation, Judge Agents
# All agents follow the same BaseAgent pattern with ReAct loop.
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from veriaudit.core.event_ledger import EventLedger
from veriaudit.core.invariants import InvariantEngine
from veriaudit.core.schema import (
    AuditPlan,
    AuditMode,
    Finding,
    FindingStatus,
    ProjectProfile,
    AuditReport,
)

from .base_agent import BaseAgent


# ============================================================
# Planner Agent
# ============================================================

class PlannerAgent(BaseAgent):
    """
    Reads ProjectProfile, selects Skills and determines audit strategy.
    Tool whitelist: repo_mcp.*
    """

    def __init__(self, ledger: EventLedger, invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None):
        super().__init__(
            agent_id="planner_agent",
            allowed_tools=["repo_mcp.*"],
            ledger=ledger,
            invariants=invariants,
            llm_config=llm_config,
            max_iterations=10,
        )

    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        return """You are a security audit planner. Your role is to analyze a project profile
and determine the audit strategy.

Given a ProjectProfile (language, build system, file count, frameworks),
you must:
1. Select applicable SAST tools
2. Select applicable vulnerability classes
3. Plan the audit phases
4. Estimate audit duration

Respond with a JSON audit plan:
{
  "selected_skills": ["static-analysis", "injection-verification", ...],
  "sast_tools": ["semgrep", "codeql"],
  "active_vuln_classes": ["command-injection", "sql-injection", ...],
  "estimated_hours": 4.0,
  "risk_modules": [],
  "notes": "..."
}"""

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Simplify: extract profile and return plan directly."""
        profile_data = task.get("profile", {})

        if isinstance(profile_data, ProjectProfile):
            lang = profile_data.language
            mode = profile_data.complexity
        else:
            lang = profile_data.get("language", "unknown")
            mode = task.get("mode", "standard")

        # Map language to default plan
        language_plans = {
            "c++": {"sast": ["semgrep", "codeql"], "vuln": ["memory-corruption", "command-injection", "path-traversal", "hardcoded-secret"]},
            "c": {"sast": ["semgrep", "codeql"], "vuln": ["memory-corruption", "command-injection", "path-traversal", "hardcoded-secret"]},
            "php": {"sast": ["semgrep", "codeql"], "vuln": ["command-injection", "sql-injection", "path-traversal", "hardcoded-secret", "xss", "ssrf"]},
            "go": {"sast": ["semgrep", "codeql"], "vuln": ["command-injection", "sql-injection", "path-traversal", "hardcoded-secret", "race-condition"]},
            "python": {"sast": ["semgrep", "codeql", "bandit"], "vuln": ["command-injection", "sql-injection", "path-traversal", "hardcoded-secret", "deserialization"]},
            "java": {"sast": ["semgrep", "codeql"], "vuln": ["command-injection", "sql-injection", "path-traversal", "hardcoded-secret", "ssrf", "deserialization"]},
            "javascript": {"sast": ["semgrep", "codeql"], "vuln": ["command-injection", "path-traversal", "hardcoded-secret", "xss", "ssrf"]},
            "typescript": {"sast": ["semgrep", "codeql"], "vuln": ["command-injection", "path-traversal", "hardcoded-secret", "xss", "ssrf"]},
            "rust": {"sast": ["semgrep", "codeql"], "vuln": ["memory-corruption", "command-injection", "path-traversal", "hardcoded-secret"]},
            "ruby": {"sast": ["semgrep", "codeql"], "vuln": ["command-injection", "sql-injection", "path-traversal", "hardcoded-secret", "xss", "deserialization"]},
        }

        default = {"sast": ["semgrep", "codeql"], "vuln": ["command-injection", "path-traversal", "hardcoded-secret"]}
        plan = language_plans.get(lang.lower(), default)

        return {
            "status": "completed",
            "result": AuditPlan(
                correlation_id=task.get("correlation_id", ""),
                mode=AuditMode(task.get("mode", "standard")),
                selected_skills=["static-analysis"],
                sast_tools=plan["sast"],
                active_vuln_classes=plan["vuln"],
                estimated_hours=2.0 if task.get("mode") == "quick" else 4.0,
            ).model_dump(),
            "iterations": 0,
        }


# ============================================================
# Recon Agent
# ============================================================

class ReconAgent(BaseAgent):
    """Entry point and dangerous call discovery via CPG."""

    def __init__(self, ledger: EventLedger, invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None):
        super().__init__("recon_agent",
                         ["repo_mcp.*", "cpg_mcp.import_*", "cpg_mcp.find_*", "cpg_mcp.query_*"],
                         ledger, invariants, llm_config, max_iterations=10)

    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        return """You are a reconnaissance agent. Your job is to discover entry points
and dangerous API calls in the project using CPG queries.

Use cpg_mcp.find_entrypoints() and cpg_mcp.find_dangerous_calls()
to build a map of the attack surface. Output a reconnaissance report as JSON."""

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "completed", "result": {
            "entry_points": [],
            "high_risk_modules": [],
            "dangerous_calls": [],
            "note": "Recon agent — full analysis requires CPG import (run in Deep mode).",
        }, "iterations": 0}


# ============================================================
# Static Scan Agent
# ============================================================

class StaticScanAgent(BaseAgent):
    """Runs SAST tools in parallel and normalizes results."""

    def __init__(self, ledger: EventLedger, invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None):
        super().__init__("static_scan_agent",
                         ["sast_mcp.*", "rag_*"],
                         ledger, invariants, llm_config, max_iterations=10)

    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        return """You are a static analysis agent. Run all applicable SAST tools
against the target repository and normalize the results.

Available tools: sast_mcp.run_semgrep, sast_mcp.run_codeql, sast_mcp.run_cppcheck,
sast_mcp.run_clang_tidy, sast_mcp.run_gitleaks, sast_mcp.normalize_findings"""

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "completed", "result": {
            "findings": task.get("findings", []),
            "note": "Static scan delegated to Orchestrator._static_scan_phase",
        }, "iterations": 0}


# ============================================================
# CPG/Taint Agent
# ============================================================

class CPGTaintAgent(BaseAgent):
    """Typed taint path analysis via CPG."""

    def __init__(self, ledger: EventLedger, invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None):
        super().__init__("cpg_taint_agent",
                         ["cpg_mcp.*"],
                         ledger, invariants, llm_config, max_iterations=20)

    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        return """You are a CPG/taint analysis agent. For each CANDIDATE finding,
determine if there's a typed taint path from external input to the dangerous sink.

Use cpg_mcp.query_typed_taint_path() with the finding's source_type and sink_type.
Output findings with updated reachable status."""

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "completed", "result": {
            "reachable": [],
            "rejected": [],
            "note": "CPG/Taint analysis — requires Joern (run in Standard/Deep mode).",
        }, "iterations": 0}


# ============================================================
# Exploit Agent
# ============================================================

class ExploitAgent(BaseAgent):
    """Trigger generation, fuzz execution, self-verification pass."""

    def __init__(self, ledger: EventLedger, invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None):
        super().__init__("exploit_agent",
                         ["fuzz_mcp.*", "exploit_mcp.*", "cpg_mcp.get_*"],
                         ledger, invariants, llm_config, max_iterations=15)

    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        return """You are an exploit generation agent. For each REACHABLE finding,
generate triggers (fuzz harnesses, injection payloads) and verify they work.

After generating triggers, perform a self-verification pass:
1. Does the trigger location match the static analysis location?
2. Is the crash input minimized?
3. Is the stack trace consistent with the call path?

Output findings with EXPLOITABLE status (or REJECTED if trigger fails)."""

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "completed", "result": {
            "exploitable": [],
            "unable_to_trigger": [],
            "note": "Exploit agent — requires VulnClassHandler integration (run in Standard/Deep mode).",
        }, "iterations": 0}


# ============================================================
# Validation Agent
# ============================================================

class ValidationAgent(BaseAgent):
    """Independent re-verification with self-correction (max 3 attempts)."""

    def __init__(self, ledger: EventLedger, invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None):
        super().__init__("validation_agent",
                         ["exploit_mcp.*", "evidence_mcp.*"],
                         ledger, invariants, llm_config, max_iterations=15)

    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        return """You are an independent validation agent. Your job is to REPLICATE
(not confirm) the Exploit Agent's findings.

For each EXPLOITABLE finding:
1. Independently re-run the trigger (do NOT read Exploit Agent's logs)
2. Run 10 stability tests
3. If < 8/10 pass, attempt self-correction (adjust env vars, input) up to 3 times
4. Report RELIABLE (≥8/10) or UNREPRODUCIBLE (<8/10 after corrections)

You should actively try to DISPROVE findings, not confirm them."""

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "completed", "result": {
            "validated": [],
            "unreproducible": [],
            "note": "Validation agent — requires dynamic verification infrastructure.",
        }, "iterations": 0}


# ============================================================
# Judge Agent
# ============================================================

class JudgeAgent(BaseAgent):
    """Deterministic rules first, LLM fallback for unmatched cases."""

    def __init__(self, ledger: EventLedger, invariants: InvariantEngine,
                 llm_config: Dict[str, Any] | None = None):
        super().__init__("judge_agent",
                         ["evidence_mcp.*", "report_mcp.*"],
                         ledger, invariants, llm_config, max_iterations=5)

    def get_system_prompt(self, task_context: Dict[str, Any]) -> str:
        return """You are a judge agent. Your role is to make the FINAL ruling on findings.

Process:
1. Check if any of the 16 deterministic rules match the finding
2. If matched → apply the rule's verdict
3. If NO rule matches → use LLM to make a judgment based on all evidence
4. NEVER mark something as CONFIRMED_EXPLOITED without:
   - ASan/sanitizer report OR OOB callback OR timing confirmation OR credential validation
   - Stable reproduction (≥8/10)
   - Project code in stack trace

Output each finding with its final status and ruling reason."""

    def process(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "completed", "result": {
            "rulings": [],
            "note": "Judge agent — deterministic rules applied by JudgeEngine, LLM fallback for edge cases.",
        }, "iterations": 0}
