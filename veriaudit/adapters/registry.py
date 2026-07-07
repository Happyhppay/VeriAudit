# VeriAudit - Adapter Registry
from __future__ import annotations

from typing import Dict, List

from ..core.exceptions import AdapterNotFoundError
from .base import BuildAdapter, LanguageAdapter, VulnerabilityClassHandler


class AdapterRegistry:
    """Central registry for all adapters."""

    # Language name aliases — maps detected names to adapter keys
    LANGUAGE_ALIASES = {
        "c++": "c/c++",
        "c": "c/c++",
        "cpp": "c/c++",
        "javascript": "javascript/typescript",
        "typescript": "javascript/typescript",
        "js": "javascript/typescript",
        "ts": "javascript/typescript",
        "kotlin": "java",
        "scala": "java",
    }

    def __init__(self):
        self._language_adapters: Dict[str, LanguageAdapter] = {}
        self._build_adapters: Dict[str, BuildAdapter] = {}
        self._vuln_handlers: Dict[str, VulnerabilityClassHandler] = {}

    # --- Registration ---

    def register_language(self, adapter: LanguageAdapter):
        key = adapter.language_name.lower()
        self._language_adapters[key] = adapter

    def register_build(self, adapter: BuildAdapter):
        self._build_adapters[adapter.build_system_name.lower()] = adapter

    def register_vuln_handler(self, handler: VulnerabilityClassHandler):
        self._vuln_handlers[handler.vuln_class_name] = handler

    # --- Lookup ---

    def get_language(self, language: str) -> LanguageAdapter:
        key = language.lower()
        # Try alias first
        key = self.LANGUAGE_ALIASES.get(key, key)
        if key not in self._language_adapters:
            raise AdapterNotFoundError("language", language)
        return self._language_adapters[key]

    def get_build(self, build_system: str) -> BuildAdapter:
        key = build_system.lower()
        if key not in self._build_adapters:
            raise AdapterNotFoundError("build", build_system)
        return self._build_adapters[key]

    def get_vuln_handler(self, vuln_class: str) -> VulnerabilityClassHandler:
        if vuln_class not in self._vuln_handlers:
            raise AdapterNotFoundError("vuln_class", vuln_class)
        return self._vuln_handlers[vuln_class]

    def get_vuln_handlers_for_language(self, language: str) -> List[VulnerabilityClassHandler]:
        """Get all vuln handlers applicable to a language."""
        return [
            h for h in self._vuln_handlers.values()
            if language.lower() in [l.lower() for l in h.applicable_languages]
               or "all" in [l.lower() for l in h.applicable_languages]
        ]

    def detect_build_system(self, repo_path: str) -> str:
        """Auto-detect which build system a project uses."""
        for name, adapter in self._build_adapters.items():
            try:
                if adapter.detect(repo_path):
                    return name
            except Exception:
                continue
        return "unknown"

    # --- Queries ---

    def get_all_languages(self) -> List[str]:
        return list(self._language_adapters.keys())

    def get_all_build_systems(self) -> List[str]:
        return list(self._build_adapters.keys())

    def get_all_vuln_classes(self) -> List[str]:
        return list(self._vuln_handlers.keys())

    def has_language(self, language: str) -> bool:
        return language.lower() in self._language_adapters
