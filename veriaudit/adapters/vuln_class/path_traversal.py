# VeriAudit - Path Traversal, Hardcoded Secret, SSRF, XSS Handlers
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List

from veriaudit.core.schema import Finding, JudgeRule, FindingStatus

from ..base import VulnerabilityClassHandler


class PathTraversalHandler(VulnerabilityClassHandler):
    """Handles path traversal (CWE-22, CWE-23). Applicable to ALL languages."""

    @property
    def vuln_class_name(self) -> str:
        return "path-traversal"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-22", "CWE-23"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["all"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "semgrep", "rule": f"{language.lower()}-path-traversal"},
            {"tool": "codeql", "rule": f"{language.lower()}/path-traversal"},
        ]

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        payloads = [
            {"payload": "../../../etc/passwd", "encoding": "plain",
             "description": "Basic path traversal to /etc/passwd"},
            {"payload": "....//....//....//etc/passwd", "encoding": "plain",
             "description": "Double-dot-slash variant"},
            {"payload": "..%2f..%2f..%2fetc%2fpasswd", "encoding": "url",
             "description": "URL-encoded traversal"},
            {"payload": "..%252f..%252f..%252fetc%252fpasswd", "encoding": "double_url",
             "description": "Double URL-encoded traversal"},
            {"payload": "../../../etc/passwd\0.jpg", "encoding": "null_byte",
             "description": "Null byte injection"},
        ]

        return {
            "trigger_type": "path_traversal_payloads",
            "vulnerability_type": "path-traversal",
            "injection_point": context.get("injection_point", ""),
            "payloads": payloads,
            "target_file": "/etc/passwd",
            "expected_content_pattern": "root:.*:0:0:",
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        import httpx

        target_url = context.get("target_url", "")
        injection_point = trigger.get("injection_point", "")
        payloads = trigger.get("payloads", [])
        expected_pattern = trigger.get("expected_content_pattern", "")

        results = {"confirmed": False, "payloads_tried": 0, "evidence": {}}

        if not target_url:
            return results

        client = httpx.Client(timeout=10)
        for p in payloads:
            results["payloads_tried"] += 1
            try:
                url = target_url.replace("{{PAYLOAD}}", p["payload"])
                resp = client.get(url)

                if expected_pattern and re.search(expected_pattern, resp.text):
                    results["confirmed"] = True
                    results["evidence"] = {
                        "accessed_outside_intended": True,
                        "target_file_read": "/etc/passwd",
                        "payload": p["payload"],
                        "matched_content": resp.text[:200],
                    }
                    break

                # Also check for common indicators
                if "root:" in resp.text and self._looks_like_passwd(resp.text):
                    results["confirmed"] = True
                    results["evidence"] = {
                        "accessed_outside_intended": True,
                        "payload": p["payload"],
                    }
                    break
            except Exception:
                continue

        client.close()
        return results

    def _looks_like_passwd(self, text: str) -> bool:
        return bool(re.match(r'^root:.*:0:0:', text.strip())) and '\n' in text


class HardcodedSecretHandler(VulnerabilityClassHandler):
    """Handles hardcoded credentials (CWE-798, CWE-259). Applicable to ALL languages."""

    @property
    def vuln_class_name(self) -> str:
        return "hardcoded-secret"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-798", "CWE-259"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["all"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "gitleaks", "rule": "all"},
            {"tool": "semgrep", "rule": "generic-secrets"},
        ]

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        secret_value = context.get("secret_value", "")
        secret_type = self._classify_secret(secret_value)

        return {
            "trigger_type": "credential_validation",
            "vulnerability_type": "hardcoded-secret",
            "secret_type": secret_type,
            "secret_value": secret_value,
            "file_path": finding.location.file,
            "line": finding.location.line_start,
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        secret = trigger.get("secret_value", "")
        secret_type = trigger.get("secret_type", "unknown")

        results = {
            "confirmed": False,
            "credential_valid": None,
            "evidence": {},
        }

        if not secret:
            return results

        # Test the credential based on type
        if secret_type == "github_token" or secret.startswith("ghp_"):
            results = self._test_github_token(secret)
        elif secret_type == "aws_key":
            results = self._test_aws_key(secret)
        elif secret_type == "generic_api_key":
            results = {"confirmed": False, "credential_valid": None,
                       "evidence": {"note": "Cannot validate generic key — marked for manual review"}}

        return results

    def _classify_secret(self, value: str) -> str:
        if value.startswith("ghp_") or value.startswith("github_pat_"):
            return "github_token"
        if value.startswith("AKIA") and len(value) == 20:
            return "aws_key"
        if re.match(r'sk-[a-zA-Z0-9]{32,}', value):
            return "openai_key"
        if re.match(r'xox[bpras]-[0-9]+-[0-9]+-[a-zA-Z0-9]+', value):
            return "slack_token"
        return "generic_api_key"

    def _test_github_token(self, token: str) -> Dict[str, Any]:
        try:
            import httpx
            resp = httpx.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}"},
                timeout=10,
            )
            if resp.status_code == 200:
                return {
                    "confirmed": True,
                    "credential_valid": True,
                    "evidence": {"service": "GitHub", "user": resp.json().get("login", "unknown")},
                }
            return {"confirmed": False, "credential_valid": False,
                    "evidence": {"status_code": resp.status_code}}
        except Exception:
            return {"confirmed": False, "credential_valid": False, "evidence": {}}

    def _test_aws_key(self, key: str) -> Dict[str, Any]:
        # AWS key validation would require the secret key pair
        return {"confirmed": False, "credential_valid": None,
                "evidence": {"note": "AWS access key detected — requires secret key for validation"}}


class SSRFHandler(VulnerabilityClassHandler):
    """Handles Server-Side Request Forgery (CWE-918)."""

    @property
    def vuln_class_name(self) -> str:
        return "ssrf"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-918"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["php", "java", "python", "go", "javascript", "ruby"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "semgrep", "rule": f"{language.lower()}-ssrf"},
            {"tool": "codeql", "rule": f"{language.lower()}/ssrf"},
        ]

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        callback_url = context.get("callback_url", "")
        return {
            "trigger_type": "ssrf_callback",
            "vulnerability_type": "ssrf",
            "payloads": [
                {"type": "http_callback", "payload": callback_url,
                 "description": "Request to callback server"},
            ],
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        return {"confirmed": False, "oob_callback_received": False,
                "evidence": {"note": "SSRF verification requires a live callback server"}}


class XSSHandler(VulnerabilityClassHandler):
    """Handles Cross-Site Scripting (CWE-79)."""

    @property
    def vuln_class_name(self) -> str:
        return "xss"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-79"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["php", "javascript", "python", "ruby"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "semgrep", "rule": f"{language.lower()}-xss"},
            {"tool": "codeql", "rule": f"{language.lower()}/xss"},
        ]

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "trigger_type": "xss_payloads",
            "vulnerability_type": "xss",
            "payloads": [
                {"type": "reflected", "payload": "<script>alert('XSS')</script>",
                 "description": "Basic reflective XSS"},
                {"type": "reflected", "payload": "<img src=x onerror=alert('XSS')>",
                 "description": "IMG onerror XSS"},
                {"type": "reflected", "payload": "'\"><script>alert('XSS')</script>",
                 "description": "Break-out-of-attribute XSS"},
            ],
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        import httpx

        target_url = context.get("target_url", "")
        payloads = trigger.get("payloads", [])
        results = {"confirmed": False, "payloads_tried": 0, "evidence": {}}

        if not target_url:
            return results

        client = httpx.Client(timeout=10)
        for p in payloads:
            results["payloads_tried"] += 1
            try:
                url = target_url.replace("{{PAYLOAD}}", p["payload"])
                resp = client.get(url)
                content = resp.text
                # Check if the payload is reflected unescaped
                if p["payload"] in content and not self._is_escaped(content, p["payload"]):
                    results["confirmed"] = True
                    results["evidence"]["reflected_unfiltered"] = True
                    results["evidence"]["payload"] = p["payload"]
                    break
            except Exception:
                continue

        client.close()
        return results

    def _is_escaped(self, content: str, payload: str) -> bool:
        """Check if the payload appears HTML-escaped in the response."""
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
        return escaped in content
