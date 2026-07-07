# VeriAudit - Python Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("pyproject.toml", "pip"),
    ("setup.cfg", "pip"),
    ("setup.py", "pip"),
    ("requirements.txt", "pip"),
    ("Pipfile", "pipenv"),
    ("Pipfile.lock", "pipenv"),
    ("poetry.lock", "poetry"),
]

_PYTHON_EXTENSIONS = [
    ".py", ".pyw", ".pyx", ".pxd", ".pxi",
]


class PythonAdapter(LanguageAdapter):
    """Language adapter for Python projects."""

    @property
    def language_name(self) -> str:
        return "Python"

    @property
    def file_extensions(self) -> List[str]:
        return _PYTHON_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        # Check poetry first (pyproject.toml with poetry.lock)
        if os.path.isfile(os.path.join(repo_path, "poetry.lock")):
            return "poetry"
        if os.path.isfile(os.path.join(repo_path, "Pipfile")):
            return "pipenv"
        for filename, system in _BUILD_INDICATORS:
            if os.path.isfile(os.path.join(repo_path, filename)):
                return system
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "bandit"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "os.system", "category": "command_exec", "severity": "high"},
            {"function": "os.popen", "category": "command_exec", "severity": "high"},
            {"function": "os.execv", "category": "command_exec", "severity": "high"},
            {"function": "os.execve", "category": "command_exec", "severity": "high"},
            {"function": "os.execl", "category": "command_exec", "severity": "high"},
            {"function": "os.execle", "category": "command_exec", "severity": "high"},
            {"function": "os.execlp", "category": "command_exec", "severity": "high"},
            {"function": "os.execlpe", "category": "command_exec", "severity": "high"},
            {"function": "os.execvp", "category": "command_exec", "severity": "high"},
            {"function": "os.execvpe", "category": "command_exec", "severity": "high"},
            {"function": "subprocess.call", "category": "command_exec", "severity": "high",
             "note": "dangerous with shell=True"},
            {"function": "subprocess.Popen", "category": "command_exec", "severity": "high",
             "note": "dangerous with shell=True"},
            {"function": "subprocess.run", "category": "command_exec", "severity": "medium",
             "note": "dangerous with shell=True"},
            {"function": "subprocess.check_output", "category": "command_exec", "severity": "medium",
             "note": "dangerous with shell=True"},
            {"function": "subprocess.check_call", "category": "command_exec", "severity": "medium"},
            {"function": "subprocess.getoutput", "category": "command_exec", "severity": "high"},
            {"function": "subprocess.getstatusoutput", "category": "command_exec", "severity": "high"},
            {"function": "eval", "category": "code_eval", "severity": "critical"},
            {"function": "exec", "category": "code_eval", "severity": "critical"},
            {"function": "compile", "category": "code_eval", "severity": "medium"},
            {"function": "__import__", "category": "code_eval", "severity": "medium"},
            {"function": "importlib.import_module", "category": "code_eval", "severity": "medium"},
            {"function": "pickle.loads", "category": "deserialization", "severity": "high"},
            {"function": "pickle.load", "category": "deserialization", "severity": "high"},
            {"function": "_pickle.loads", "category": "deserialization", "severity": "high"},
            {"function": "cPickle.loads", "category": "deserialization", "severity": "high"},
            {"function": "dill.loads", "category": "deserialization", "severity": "high"},
            {"function": "yaml.load", "category": "deserialization", "severity": "high",
             "note": "unsafe without Loader argument"},
            {"function": "yaml.full_load", "category": "deserialization", "severity": "high"},
            {"function": "requests.get", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL (SSRF)"},
            {"function": "requests.post", "category": "network_output", "severity": "medium"},
            {"function": "requests.request", "category": "network_output", "severity": "medium"},
            {"function": "urllib.request.urlopen", "category": "network_output", "severity": "medium"},
            {"function": "httpx.get", "category": "network_output", "severity": "medium"},
            {"function": "builtins.open", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "io.open", "category": "file_ops", "severity": "medium"},
            {"function": "pathlib.Path.write_text", "category": "file_ops", "severity": "medium"},
            {"function": "pathlib.Path.write_bytes", "category": "file_ops", "severity": "medium"},
            {"function": "pymysql.connect.cursor.execute", "category": "sql_exec", "severity": "medium",
             "note": "dangerous with % formatting"},
            {"function": "sqlite3.Connection.execute", "category": "sql_exec", "severity": "medium",
             "note": "dangerous with f-string"},
            {"function": "psycopg2.connect.cursor.execute", "category": "sql_exec", "severity": "medium"},
            {"function": "marshal.loads", "category": "deserialization", "severity": "high"},
            {"function": "shelve.open", "category": "deserialization", "severity": "medium"},
            {"function": "shlex.split", "category": "command_exec", "severity": "low"},
            {"function": "xml.etree.ElementTree.parse", "category": "xxe", "severity": "medium"},
            {"function": "xml.sax.parse", "category": "xxe", "severity": "medium"},
            {"function": "lxml.etree.parse", "category": "xxe", "severity": "medium",
             "note": "dangerous with resolve_entities=True"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "command-injection",
            "sql-injection",
            "path-traversal",
            "hardcoded-secret",
            "ssrf",
            "deserialization",
            "xxe",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "cli_main",
                "pattern": r'''if\s+__name__\s*==\s*['"]__main__['"]''',
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "flask_route",
                "pattern": r"@\w*app\.route\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "flask_route",
                "pattern": r"@\w*blueprint\.route\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "fastapi_route",
                "pattern": r"@\w*app\.get\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "fastapi_route",
                "pattern": r"@\w*app\.post\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "fastapi_route",
                "pattern": r"@\w*app\.put\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "fastapi_route",
                "pattern": r"@\w*app\.delete\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "django_urls",
                "pattern": r"urlpatterns\s*=",
                "file_filter": "urls.py",
            },
            {
                "type": "django_view",
                "pattern": r"def\s+\w+\s*\(\s*request\b",
                "file_filter": "views.py",
            },
            {
                "type": "click_command",
                "pattern": r"@click\.command\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "click_command",
                "pattern": r"@click\.group\s*\(",
                "file_filter": "*.py,*.pyw",
            },
            {
                "type": "argparse_main",
                "pattern": r"ArgumentParser\s*\(",
                "file_filter": "*.py,*.pyw",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "codeql"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        return None

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        harness_template = """\
import atheris
import sys

def TestOneInput(data):
    # TODO: Call target function with fuzzer data
    pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
"""
        return FuzzConfig(
            engine="atheris",
            harness_template=harness_template,
            extra_flags=[],
        )
