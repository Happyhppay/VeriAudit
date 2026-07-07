# VeriAudit - Ruby Language Adapter
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from veriaudit.adapters.base import LanguageAdapter
from veriaudit.core.schema import FuzzConfig, SanitizerConfig


_BUILD_INDICATORS = [
    ("Gemfile.lock", "bundler"),
    ("Gemfile", "bundler"),
    ("gems.rb", "bundler"),
]

_RUBY_EXTENSIONS = [
    ".rb", ".rake", ".gemspec", ".ru",
]


class RubyAdapter(LanguageAdapter):
    """Language adapter for Ruby projects."""

    @property
    def language_name(self) -> str:
        return "Ruby"

    @property
    def file_extensions(self) -> List[str]:
        return _RUBY_EXTENSIONS

    def detect_build_system(self, repo_path: str) -> str:
        for filename, system in _BUILD_INDICATORS:
            if os.path.isfile(os.path.join(repo_path, filename)):
                return system
        return "unknown"

    def get_sast_tools(self, mode: str = "standard") -> List[str]:
        if mode == "quick":
            return ["semgrep"]
        if mode == "deep":
            return ["semgrep", "codeql", "brakeman"]
        return ["semgrep", "codeql"]

    def get_dangerous_patterns(self) -> List[Dict[str, Any]]:
        return [
            {"function": "eval", "category": "code_eval", "severity": "critical"},
            {"function": "instance_eval", "category": "code_eval", "severity": "high"},
            {"function": "class_eval", "category": "code_eval", "severity": "high"},
            {"function": "module_eval", "category": "code_eval", "severity": "high"},
            {"function": "system", "category": "command_exec", "severity": "high"},
            {"function": "exec", "category": "command_exec", "severity": "high"},
            {"function": "spawn", "category": "command_exec", "severity": "high"},
            {"function": "Kernel.open", "category": "command_exec", "severity": "high",
             "note": "opens pipe when argument starts with |"},
            {"function": "IO.popen", "category": "command_exec", "severity": "high"},
            {"function": "Open3.popen3", "category": "command_exec", "severity": "high"},
            {"function": "Open3.capture2", "category": "command_exec", "severity": "medium"},
            {"function": "Open3.capture3", "category": "command_exec", "severity": "medium"},
            {"function": "`backticks`", "category": "command_exec", "severity": "high",
             "note": "backtick execution, e.g. `ls #{user_input}`"},
            {"function": "%x{}", "category": "command_exec", "severity": "high",
             "note": "percent-x literal for command execution"},
            {"function": "open", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "Kernel.open", "category": "file_ops", "severity": "medium"},
            {"function": "File.open", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "File.read", "category": "file_ops", "severity": "medium"},
            {"function": "File.write", "category": "file_ops", "severity": "medium"},
            {"function": "File.delete", "category": "file_ops", "severity": "medium"},
            {"function": "FileUtils.rm_rf", "category": "file_ops", "severity": "high"},
            {"function": "IO.read", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled path"},
            {"function": "IO.readlines", "category": "file_ops", "severity": "medium"},
            {"function": "Pathname.read", "category": "file_ops", "severity": "medium"},
            {"function": "Dir.glob", "category": "file_ops", "severity": "medium",
             "note": "dangerous with user-controlled pattern"},
            {"function": "Net::HTTP.get", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled URL (SSRF)"},
            {"function": "Net::HTTP.get_response", "category": "network_output", "severity": "medium"},
            {"function": "Net::HTTP.post_form", "category": "network_output", "severity": "medium"},
            {"function": "Net::HTTP.new", "category": "network_output", "severity": "medium",
             "note": "dangerous with user-controlled host"},
            {"function": "OpenURI.open_uri", "category": "network_output", "severity": "medium"},
            {"function": "RestClient.get", "category": "network_output", "severity": "medium"},
            {"function": "RestClient.post", "category": "network_output", "severity": "medium"},
            {"function": "HTTParty.get", "category": "network_output", "severity": "medium"},
            {"function": "HTTParty.post", "category": "network_output", "severity": "medium"},
            {"function": "Faraday.get", "category": "network_output", "severity": "medium"},
            {"function": "Faraday.post", "category": "network_output", "severity": "medium"},
            {"function": "ActiveRecord::Base.find_by_sql", "category": "sql_exec", "severity": "high"},
            {"function": "ActiveRecord::Base.connection.execute", "category": "sql_exec", "severity": "high"},
            {"function": "ActiveRecord::Base.connection.select_all", "category": "sql_exec", "severity": "high"},
            {"function": "where", "category": "sql_exec", "severity": "medium",
             "note": "dangerous with string interpolation in ActiveRecord"},
            {"function": "render", "category": "xss", "severity": "medium",
             "note": "dangerous with render inline: user_input"},
            {"function": "raw", "category": "xss", "severity": "high",
             "note": "bypasses HTML escaping in views"},
            {"function": "html_safe", "category": "xss", "severity": "high",
             "note": "marks string as HTML-safe, bypasses escaping"},
            {"function": "YAML.load", "category": "deserialization", "severity": "high",
             "note": "unsafe YAML deserialization (use safe_load)"},
            {"function": "YAML.load_file", "category": "deserialization", "severity": "high"},
            {"function": "Marshal.load", "category": "deserialization", "severity": "high"},
            {"function": "Marshal.restore", "category": "deserialization", "severity": "high"},
            {"function": "Kernel.load", "category": "code_eval", "severity": "high",
             "note": "loads and executes Ruby file"},
            {"function": "Kernel.require", "category": "code_eval", "severity": "medium"},
            {"function": "Kernel.autoload", "category": "code_eval", "severity": "medium"},
            {"function": "send", "category": "code_eval", "severity": "high",
             "note": "dynamic method dispatch with user-controlled method name"},
            {"function": "public_send", "category": "code_eval", "severity": "medium"},
            {"function": "__send__", "category": "code_eval", "severity": "high"},
            {"function": "method", "category": "code_eval", "severity": "medium",
             "note": "dangerous with user-controlled method name"},
            {"function": "REXML::Document.new", "category": "xxe", "severity": "medium"},
            {"function": "Nokogiri::XML", "category": "xxe", "severity": "medium",
             "note": "dangerous without noent option"},
        ]

    def get_vulnerability_classes(self) -> List[str]:
        return [
            "command-injection",
            "sql-injection",
            "path-traversal",
            "hardcoded-secret",
            "xss",
            "ssrf",
            "deserialization",
        ]

    def get_entry_point_patterns(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "rails_routes",
                "pattern": r"routes\.rb",
                "file_filter": "routes.rb,*.rb",
            },
            {
                "type": "rails_routes",
                "pattern": r"\bget\s+['\"]/",
                "file_filter": "*.rb",
            },
            {
                "type": "rails_routes",
                "pattern": r"\bpost\s+['\"]/",
                "file_filter": "*.rb",
            },
            {
                "type": "rails_routes",
                "pattern": r"\bresources\s+:",
                "file_filter": "*.rb",
            },
            {
                "type": "sinatra_route",
                "pattern": r"\bget\s+['\"]/",
                "file_filter": "*.rb",
            },
            {
                "type": "sinatra_route",
                "pattern": r"\bpost\s+['\"]/",
                "file_filter": "*.rb",
            },
            {
                "type": "sinatra_route",
                "pattern": r"\bput\s+['\"]/",
                "file_filter": "*.rb",
            },
            {
                "type": "sinatra_route",
                "pattern": r"\bdelete\s+['\"]/",
                "file_filter": "*.rb",
            },
            {
                "type": "rack_config",
                "pattern": r"config\.ru",
                "file_filter": "config.ru",
            },
            {
                "type": "rack_config",
                "pattern": r"\brun\s+",
                "file_filter": "config.ru",
            },
            {
                "type": "controller_action",
                "pattern": r"class\s+\w+Controller\s*<",
                "file_filter": "*.rb",
            },
            {
                "type": "controller_action",
                "pattern": r"\bdef\s+(index|show|create|update|destroy|new|edit)\b",
                "file_filter": "*_controller.rb",
            },
            {
                "type": "rake_task",
                "pattern": r"\btask\s+:",
                "file_filter": "*.rake,Rakefile",
            },
            {
                "type": "rake_task",
                "pattern": r"\bdesc\s+['\"]",
                "file_filter": "*.rake,Rakefile",
            },
            {
                "type": "cli_main",
                "pattern": r"Thor\.desc\b",
                "file_filter": "*.rb",
            },
            {
                "type": "cli_main",
                "pattern": r"option\s+:",
                "file_filter": "*.rb",
            },
        ]

    def get_graph_analyzer_type(self) -> Optional[str]:
        return "codeql"

    def get_sanitizer_config(self) -> Optional[SanitizerConfig]:
        return None

    def get_fuzz_config(self) -> Optional[FuzzConfig]:
        return None
