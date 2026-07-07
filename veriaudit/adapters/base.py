# VeriAudit - Adapter base classes
# LanguageAdapter, BuildAdapter, VulnerabilityClassHandler ABCs.
# Registry for discovering and loading adapters.
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..core.schema import (
    BuildResult,
    BuildType,
    CWE,
    DangerousCall,
    EntryPoint,
    Finding,
    FuzzConfig,
    JudgeRule,
    ProjectProfile,
    SanitizerConfig,
    SourceType,
    SinkType,
)


# ============================================================
# Language Adapter
# ============================================================

class LanguageAdapter(ABC):
    """Encapsulates all analysis knowledge for a specific language."""

    @property
    @abstractmethod
    def language_name(self) -> str:
        """e.g. "C++", "PHP", "Go" """
        ...

    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """e.g. [".cpp", ".h", ".cxx"]"""
        ...

    @abstractmethod
    def detect_build_system(self, repo_path: str) -> str:
        """Return build system name or 'unknown'."""
        ...

    @abstractmethod
    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        """
        Return SAST tool names for this language.
        Quick mode returns fewer tools than deep mode.
        """
        ...

    @abstractmethod
    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        """
        Return language-specific dangerous patterns.
        Format: [{"function": "memcpy", "category": "mem_unsafe", "severity": "high"}, ...]
        """
        ...

    @abstractmethod
    def get_vulnerability_classes(self) -> List[str]:
        """
        Return applicable vulnerability class names.
        Must match VulnClassHandler.vuln_class_name values.
        """
        ...

    @abstractmethod
    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        """
        Return patterns for discovering entry points.
        Format: [{"type": "cli_main", "pattern": "int main(", "file_filter": "*.cpp"}, ...]
        """
        ...

    def get_graph_analyzer_type(self) -> Optional[str]:
        """
        Return the graph analysis backend for this language.
        "joern" | "codeql" | "psalm" | None
        """
        return None

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        """Sanitizer configuration (compiled languages only)."""
        return None

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        """Fuzz configuration (compiled languages only)."""
        return None

    def can_dynamic_verify(self) -> bool:
        """Whether this language supports dynamic verification."""
        return self.get_sanitizer_config() is not None


# ============================================================
# Build Adapter
# ============================================================

class BuildAdapter(ABC):
    """Encapsulates build system knowledge."""

    @property
    @abstractmethod
    def build_system_name(self) -> str:
        """e.g. "cmake", "maven", "go_modules" """
        ...

    @abstractmethod
    def detect(self, repo_path: str) -> bool:
        """Detect if the project uses this build system."""
        ...

    def configure(self, container_id: str, repo_path: str,
                  build_type: BuildType = BuildType.DEBUG,
                  extra_flags: Optional[Dict[str, str]] = None) -> BuildResult:
        """
        Configure the build. Subclasses override with specific logic.
        Returns a BuildResult.
        """
        return BuildResult(build_type=build_type, container_id=container_id, success=False)

    def compile(self, container_id: str, build_dir: str,
                target: Optional[str] = None) -> BuildResult:
        """
        Compile the project or a specific target.
        Returns a BuildResult.
        """
        return BuildResult(container_id=container_id, success=False)

    def generate_build_info(self, container_id: str,
                             build_dir: str) -> Dict[str, Any]:
        """
        Generate build info (compile_commands.json path, classpath, etc.)
        Returns a dict with build system-specific fields.
        """
        return {}

    def can_sanitize(self) -> bool:
        """Whether this build system supports sanitizer builds."""
        return False

    def can_fuzz(self) -> bool:
        """Whether this build system supports fuzz target compilation."""
        return False

    def install_dependencies(self, container_id: str,
                              repo_path: str) -> BuildResult:
        """Install project dependencies (for interpreted languages)."""
        return BuildResult(container_id=container_id, success=False)


# ============================================================
# Vulnerability Class Handler
# ============================================================

class VulnerabilityClassHandler(ABC):
    """
    Encapsulates a complete "discover -> trigger -> verify -> judge" pipeline
    for one vulnerability class.
    """

    @property
    @abstractmethod
    def vuln_class_name(self) -> str:
        """e.g. "memory-corruption", "command-injection" """
        ...

    @property
    @abstractmethod
    def cwe_ids(self) -> List[str]:
        """Associated CWE IDs: ["CWE-122", "CWE-125"]"""
        ...

    @property
    @abstractmethod
    def applicable_languages(self) -> List[str]:
        """Languages this handler applies to."""
        ...

    @abstractmethod
    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        """
        SAST rules for discovering this vulnerability class in the given language.
        Returns [{"tool": "semgrep", "rule": "cpp-memory-unsafe"}, ...]
        """
        ...

    def assess_reachability(self, finding: Finding,
                             graph_query_fn: Any) -> Dict[str, Any]:
        """
        Assess whether the vulnerable code is reachable from external input.
        Default: check if finding has a call_path with entries.
        """
        if finding.call_path:
            return {"reachable": True, "confidence": "medium",
                    "reason": "Call path exists from entry point"}
        return {"reachable": False, "confidence": "low",
                "reason": "No call path to entry point"}

    @abstractmethod
    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate input/conditions to trigger the vulnerability.
        Returns a trigger dict specific to this vuln class.
        """
        ...

    @abstractmethod
    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dynamically verify the vulnerability exists.
        Returns a verification result dict.
        """
        ...

    def get_judge_rules(self) -> List[JudgeRule]:
        """Vuln-class-specific judge rules (supplements default rules)."""
        return []

    def create_evidence_bundle(self, finding: Finding,
                                verification: Dict[str, Any]) -> Dict[str, Any]:
        """Create evidence bundle from verification results."""
        return {"finding_id": finding.finding_id, "evidence": []}
