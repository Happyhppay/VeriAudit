"""Tests for VeriAudit adapters — language, build, vuln class."""

import os
import tempfile
import shutil

import pytest

from veriaudit.adapters.base import LanguageAdapter, BuildAdapter, VulnerabilityClassHandler
from veriaudit.adapters.registry import AdapterRegistry
from veriaudit.adapters.language.cpp import CppAdapter
from veriaudit.adapters.language.php import PhpAdapter
from veriaudit.adapters.language.go import GoAdapter
from veriaudit.adapters.language.java import JavaAdapter
from veriaudit.adapters.language.python import PythonAdapter
from veriaudit.adapters.language.javascript import JsTsAdapter
from veriaudit.adapters.language.rust import RustAdapter
from veriaudit.adapters.language.ruby import RubyAdapter
from veriaudit.adapters.build.cmake import CMakeAdapter
from veriaudit.adapters.build.composer import ComposerAdapter, GoModulesAdapter
from veriaudit.adapters.vuln_class.command_injection import CommandInjectionHandler
from veriaudit.adapters.vuln_class.sql_injection import SQLInjectionHandler
from veriaudit.adapters.vuln_class.path_traversal import PathTraversalHandler, HardcodedSecretHandler, SSRFHandler, XSSHandler
from veriaudit.adapters.vuln_class.memory_corruption import MemoryCorruptionHandler, IntegerOverflowHandler, FormatStringHandler
from veriaudit.adapters.vuln_class.deserialization import DeserializationHandler, XXEHandler, RaceConditionHandler
from veriaudit.core.exceptions import AdapterNotFoundError


# ============================================================
# Language Adapter Tests
# ============================================================

ALL_LANGUAGE_CLASSES = [
    CppAdapter, PhpAdapter, GoAdapter, JavaAdapter,
    PythonAdapter, JsTsAdapter, RustAdapter, RubyAdapter,
]

class TestLanguageAdapters:
    @pytest.mark.parametrize("cls", ALL_LANGUAGE_CLASSES)
    def test_adapter_is_concrete(self, cls):
        """Every adapter must be instantiable and implement all abstract methods."""
        adapter = cls()
        assert isinstance(adapter.language_name, str) and len(adapter.language_name) > 0
        assert isinstance(adapter.file_extensions, list) and len(adapter.file_extensions) > 0
        assert isinstance(adapter.get_sast_tools(), list)
        assert isinstance(adapter.get_dangerous_patterns(), list)
        assert isinstance(adapter.get_vulnerability_classes(), list)
        assert isinstance(adapter.get_entry_point_patterns(), list)

    @pytest.mark.parametrize("cls", ALL_LANGUAGE_CLASSES)
    def test_dangerous_patterns_have_required_keys(self, cls):
        adapter = cls()
        for pattern in adapter.get_dangerous_patterns():
            assert "function" in pattern
            assert "category" in pattern
            assert "severity" in pattern

    def test_cpp_has_sanitizer(self):
        adapter = CppAdapter()
        assert adapter.get_sanitizer_config() is not None
        assert adapter.get_fuzz_config() is not None

    def test_php_has_no_sanitizer(self):
        adapter = PhpAdapter()
        assert adapter.get_sanitizer_config() is None
        assert adapter.get_fuzz_config() is None

    def test_go_has_race_detector(self):
        adapter = GoAdapter()
        assert adapter.get_sanitizer_config() is not None


# ============================================================
# Build Adapter Tests
# ============================================================

class TestBuildAdapters:
    def test_cmake_detects_cmakelists(self):
        adapter = CMakeAdapter()
        with tempfile.TemporaryDirectory() as d:
            Path = __import__('pathlib').Path
            (Path(d) / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
            assert adapter.detect(d)

    def test_cmake_rejects_empty_dir(self):
        adapter = CMakeAdapter()
        with tempfile.TemporaryDirectory() as d:
            assert not adapter.detect(d)

    def test_composer_detects_composer_json(self):
        adapter = ComposerAdapter()
        with tempfile.TemporaryDirectory() as d:
            (__import__('pathlib').Path(d) / "composer.json").write_text("{}")
            assert adapter.detect(d)

    def test_go_modules_detects_go_mod(self):
        adapter = GoModulesAdapter()
        with tempfile.TemporaryDirectory() as d:
            (__import__('pathlib').Path(d) / "go.mod").write_text("module test")
            assert adapter.detect(d)

    def test_cmake_can_sanitize(self):
        assert CMakeAdapter().can_sanitize()

    def test_composer_cannot_sanitize(self):
        assert not ComposerAdapter().can_sanitize()


# ============================================================
# Vulnerability Class Handler Tests
# ============================================================

ALL_VULN_CLASSES = [
    CommandInjectionHandler, SQLInjectionHandler, PathTraversalHandler,
    HardcodedSecretHandler, SSRFHandler, XSSHandler,
    MemoryCorruptionHandler, IntegerOverflowHandler, FormatStringHandler,
    DeserializationHandler, XXEHandler, RaceConditionHandler,
]

class TestVulnClassHandlers:
    @pytest.mark.parametrize("cls", ALL_VULN_CLASSES)
    def test_handler_is_concrete(self, cls):
        handler = cls()
        assert isinstance(handler.vuln_class_name, str) and len(handler.vuln_class_name) > 0
        assert isinstance(handler.cwe_ids, list) and len(handler.cwe_ids) > 0
        assert isinstance(handler.applicable_languages, list)

    @pytest.mark.parametrize("cls", ALL_VULN_CLASSES)
    def test_get_discovery_rules_returns_list(self, cls):
        handler = cls()
        rules = handler.get_discovery_rules("python")
        assert isinstance(rules, list)

    @pytest.mark.parametrize("cls", ALL_VULN_CLASSES)
    def test_generate_trigger_returns_dict(self, cls):
        handler = cls()
        from veriaudit.core.schema import Finding, CodeLocation
        f = Finding(
            correlation_id="test", source_tool="semgrep", rule_id="r",
            location=CodeLocation(file="test", line_start=1), message="test",
        )
        result = handler.generate_trigger(f, {"repo_path": "/tmp", "language": "python"})
        assert isinstance(result, dict)
        assert "trigger_type" in result


# ============================================================
# Registry Tests
# ============================================================

class TestAdapterRegistry:
    @pytest.fixture
    def registry(self):
        r = AdapterRegistry()
        for cls in ALL_LANGUAGE_CLASSES:
            r.register_language(cls())
        r.register_build(CMakeAdapter())
        r.register_build(ComposerAdapter())
        for cls in ALL_VULN_CLASSES:
            r.register_vuln_handler(cls())
        return r

    def test_get_language_by_detected_name(self, registry):
        # Test alias mapping
        cpp = registry.get_language("c++")
        assert isinstance(cpp, CppAdapter)

    def test_get_language_by_canonical_name(self, registry):
        php = registry.get_language("php")
        assert isinstance(php, PhpAdapter)

    def test_unknown_language_raises(self, registry):
        with pytest.raises(AdapterNotFoundError):
            registry.get_language("brainfuck")

    def test_get_vuln_handlers_for_php(self, registry):
        handlers = registry.get_vuln_handlers_for_language("php")
        names = [h.vuln_class_name for h in handlers]
        assert "command-injection" in names
        assert "sql-injection" in names
        assert "memory-corruption" not in names  # Not for PHP

    def test_get_vuln_handlers_for_cpp(self, registry):
        handlers = registry.get_vuln_handlers_for_language("c++")
        names = [h.vuln_class_name for h in handlers]
        assert "memory-corruption" in names
        assert "sql-injection" not in names

    def test_all_languages_registered(self, registry):
        langs = registry.get_all_languages()
        assert "c/c++" in langs
        assert "php" in langs
        assert "go" in langs
