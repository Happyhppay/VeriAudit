# VeriAudit - Deserialization, XXE, Race Condition Handlers
from __future__ import annotations

from typing import Any, Dict, List

from veriaudit.core.schema import Finding, JudgeRule, FindingStatus

from ..base import VulnerabilityClassHandler


class DeserializationHandler(VulnerabilityClassHandler):
    """Handler for insecure deserialization (CWE-502)."""

    @property
    def vuln_class_name(self) -> str:
        return "deserialization"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-502"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["php", "java", "python", "ruby"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        rules = {
            "php": [
                {"tool": "semgrep", "rule": "php-deserialization"},
                {"tool": "codeql", "rule": "php/unsafe-deserialization"},
            ],
            "python": [
                {"tool": "semgrep", "rule": "python-deserialization"},
                {"tool": "bandit", "rule": "B301"},  # pickle
                {"tool": "bandit", "rule": "B506"},  # yaml.load
            ],
            "java": [
                {"tool": "semgrep", "rule": "java-deserialization"},
                {"tool": "codeql", "rule": "java/unsafe-deserialization"},
            ],
            "ruby": [
                {"tool": "semgrep", "rule": "ruby-deserialization"},
                {"tool": "codeql", "rule": "ruby/unsafe-deserialization"},
            ],
        }
        return rules.get(language.lower(), [
            {"tool": "semgrep", "rule": f"{language.lower()}-deserialization"},
        ])

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "trigger_type": "deserialization_payload",
            "vulnerability_type": "deserialization",
            "payloads": [
                {"type": "malformed", "payload": "O:8:\"stdClass\":0:{}",
                 "description": "PHP serialized object"},
                {"type": "malformed", "payload": "aced0005737200",
                 "description": "Java serialized object header (base64)"},
                {"type": "malformed", "payload": "cPickle\n.",
                 "description": "Python pickle protocol header"},
            ],
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        results = {"confirmed": False, "evidence": {}}

        target_url = context.get("target_url", "")
        if not target_url:
            return results

        import httpx
        client = httpx.Client(timeout=10)

        for p in trigger.get("payloads", []):
            try:
                resp = client.post(target_url, data=p["payload"],
                                   headers={"Content-Type": "application/octet-stream"})
                # Abnormal response (500 error, stack trace, exception) indicates potential
                if resp.status_code >= 500 or "exception" in resp.text.lower():
                    results["confirmed"] = True
                    results["evidence"] = {"status_code": resp.status_code,
                                            "response_preview": resp.text[:300]}
                    break
            except Exception:
                continue

        client.close()
        return results


class XXEHandler(VulnerabilityClassHandler):
    """Handler for XML External Entity injection (CWE-611)."""

    @property
    def vuln_class_name(self) -> str:
        return "xxe"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-611"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["php", "java", "python"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "semgrep", "rule": f"{language.lower()}-xxe"},
            {"tool": "codeql", "rule": f"{language.lower()}/xxe"},
        ]

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        callback_url = context.get("callback_url", "")
        return {
            "trigger_type": "xxe_payloads",
            "vulnerability_type": "xxe",
            "payloads": [{
                "type": "oob_xxe",
                "payload": f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}/xxe_callback">
]>
<data>&xxe;</data>''',
                "description": "OOB XXE via external DTD",
            }],
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        return {"confirmed": False, "oob_callback_received": False,
                "evidence": {"note": "XXE verification requires a live callback server"}}


class RaceConditionHandler(VulnerabilityClassHandler):
    """Handler for race conditions (CWE-362, CWE-366, CWE-367)."""

    @property
    def vuln_class_name(self) -> str:
        return "race-condition"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-362", "CWE-366", "CWE-367"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["go", "java", "c++", "c", "rust"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        return [
            {"tool": "codeql", "rule": f"{language.lower()}/race-condition"},
            {"tool": "semgrep", "rule": f"{language.lower()}-race-condition"},
        ]

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "trigger_type": "concurrency_stress",
            "vulnerability_type": "race-condition",
            "concurrent_requests": 100,
            "duration_seconds": 10,
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        results = {"confirmed": False, "race_triggered": False,
                   "evidence": {}}

        target_url = context.get("target_url", "")
        concurrent = trigger.get("concurrent_requests", 100)

        if not target_url:
            return results

        import concurrent.futures
        import httpx

        def make_request():
            try:
                resp = httpx.get(target_url, timeout=5)
                return resp.status_code
            except Exception:
                return 0

        # Fire concurrent requests to trigger race
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrent, 50)) as ex:
            futures = [ex.submit(make_request) for _ in range(concurrent)]
            concurrent.futures.wait(futures, timeout=10)

        # Check for anomalies
        statuses = set(f.result() for f in futures if f.done())
        if 0 in statuses or 500 in statuses:
            results["confirmed"] = True
            results["race_triggered"] = True
            results["evidence"]["anomalous_statuses"] = list(statuses)

        return results
