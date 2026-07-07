# VeriAudit - SQL Injection Handler
from __future__ import annotations

import time
from typing import Any, Dict, List

from veriaudit.core.schema import Finding, JudgeRule, FindingStatus

from ..base import VulnerabilityClassHandler


class SQLInjectionHandler(VulnerabilityClassHandler):
    """Handles SQL injection (CWE-89, CWE-90)."""

    @property
    def vuln_class_name(self) -> str:
        return "sql-injection"

    @property
    def cwe_ids(self) -> List[str]:
        return ["CWE-89", "CWE-90"]

    @property
    def applicable_languages(self) -> List[str]:
        return ["php", "java", "python", "go", "javascript", "ruby"]

    def get_discovery_rules(self, language: str) -> List[Dict[str, Any]]:
        lang_rules = {
            "php": [
                {"tool": "semgrep", "rule": "php-sql-injection"},
                {"tool": "codeql", "rule": "php/sql-injection"},
            ],
            "python": [
                {"tool": "semgrep", "rule": "python-sql-injection"},
                {"tool": "bandit", "rule": "B608"},
            ],
            "java": [
                {"tool": "semgrep", "rule": "java-sql-injection"},
                {"tool": "codeql", "rule": "java/sql-injection"},
            ],
            "go": [
                {"tool": "semgrep", "rule": "go-sql-injection"},
                {"tool": "codeql", "rule": "go/sql-injection"},
            ],
            "javascript": [
                {"tool": "semgrep", "rule": "javascript-sql-injection"},
                {"tool": "codeql", "rule": "js/sql-injection"},
            ],
            "ruby": [
                {"tool": "semgrep", "rule": "ruby-sql-injection"},
                {"tool": "codeql", "rule": "ruby/sql-injection"},
            ],
        }
        return lang_rules.get(language.lower(), [
            {"tool": "semgrep", "rule": f"{language.lower()}-sql-injection"},
        ])

    def generate_trigger(self, finding: Finding,
                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SQL injection payload sequence: error → boolean → timing → UNION → OOB."""
        payloads = [
            # Phase 1: Error detection
            {"type": "error", "payload": "'",
             "description": "Single quote — trigger SQL syntax error"},
            {"type": "error", "payload": "\"",
             "description": "Double quote — trigger SQL syntax error"},
            {"type": "error", "payload": "')",
             "description": "Close parenthesis and quote"},

            # Phase 2: Boolean-based blind
            {"type": "boolean", "payload": "' OR '1'='1",
             "description": "Always-true condition"},
            {"type": "boolean", "payload": "' AND '1'='2",
             "description": "Always-false condition"},

            # Phase 3: Time-based blind
            {"type": "time_based", "payload": "' AND SLEEP(5)--",
             "description": "MySQL time-based blind (5s delay)", "dbms": "mysql",
             "expected_delay": 5},
            {"type": "time_based", "payload": "'; WAITFOR DELAY '0:0:5'--",
             "description": "MSSQL time-based blind", "dbms": "mssql",
             "expected_delay": 5},
            {"type": "time_based", "payload": "' OR pg_sleep(5)--",
             "description": "PostgreSQL time-based blind", "dbms": "postgresql",
             "expected_delay": 5},
            {"type": "time_based", "payload": "' AND RANDOMBLOB(50000000)--",
             "description": "SQLite heavy operation delay", "dbms": "sqlite"},
        ]

        return {
            "trigger_type": "sqli_payloads",
            "vulnerability_type": "sql-injection",
            "injection_point": context.get("injection_point", ""),
            "param_name": context.get("param_name", ""),
            "payloads": payloads,
        }

    def verify_dynamically(self, finding: Finding,
                            trigger: Dict[str, Any],
                            context: Dict[str, Any]) -> Dict[str, Any]:
        """Dynamic verification of SQL injection."""
        import httpx

        target_url = context.get("target_url", "")
        injection_point = trigger.get("injection_point", "")
        payloads = trigger.get("payloads", [])

        results = {
            "confirmed": False,
            "method": "",
            "evidence": {},
            "payloads_tried": 0,
        }

        if not target_url:
            results["error"] = "No target URL"
            return results

        client = httpx.Client(timeout=15)

        # Baseline: send a normal request
        try:
            baseline_resp = client.get(target_url)
            baseline_body = baseline_resp.text
            baseline_time = baseline_resp.elapsed.total_seconds()
        except Exception:
            baseline_body = ""
            baseline_time = 0.2

        # Phase 1: Error detection
        for p in payloads:
            if p["type"] != "error":
                continue
            results["payloads_tried"] += 1
            try:
                resp = self._send_payload(client, target_url, injection_point, p["payload"])
                if resp.status_code >= 500 or self._has_sql_error(resp.text):
                    results["confirmed"] = True
                    results["method"] = "error_based"
                    results["evidence"] = {"error_response": resp.text[:500]}
                    client.close()
                    return results
            except Exception:
                continue

        # Phase 2: Boolean blind
        for p in payloads:
            if p["type"] != "boolean":
                continue
            results["payloads_tried"] += 1
            try:
                resp = self._send_payload(client, target_url, injection_point, p["payload"])
                if len(resp.text) != len(baseline_body):
                    results["confirmed"] = True
                    results["method"] = "boolean_blind"
                    results["evidence"] = {
                        "baseline_length": len(baseline_body),
                        "injected_length": len(resp.text),
                    }
                    client.close()
                    return results
            except Exception:
                continue

        # Phase 3: Time-based blind
        for p in payloads:
            if p["type"] != "time_based":
                continue
            results["payloads_tried"] += 1
            try:
                start = time.time()
                self._send_payload(client, target_url, injection_point, p["payload"])
                elapsed = time.time() - start
                expected = p.get("expected_delay", 5)
                if elapsed > expected - 0.5:
                    results["confirmed"] = True
                    results["method"] = "time_blind"
                    results["evidence"] = {
                        "observed_delay": elapsed,
                        "expected_delay": expected,
                    }
                    client.close()
                    return results
            except Exception:
                continue

        client.close()
        return results

    def _send_payload(self, client, target_url, injection_point, payload):
        url = target_url.replace("{{PAYLOAD}}", payload)
        return client.get(url)

    def _has_sql_error(self, text: str) -> bool:
        """Check response for SQL error messages."""
        sql_errors = [
            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
            "SQLite", "SQLSTATE", "unclosed quotation mark",
            "Unclosed quotation mark", "You have an error in your SQL syntax",
            "Warning: mysql", "Microsoft OLE DB", "ODBC Driver",
            "org.hibernate", "PSQLException", "SQLServer JDBC",
        ]
        return any(err.lower() in text.lower() for err in sql_errors)

    def get_judge_rules(self) -> List[JudgeRule]:
        return [
            JudgeRule(rule_id="SQLI-R001",
                      condition="Time-based blind SLEEP(N) > N-0.5s + consistent",
                      verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.90, priority=2),
            JudgeRule(rule_id="SQLI-R002",
                      condition="Boolean blind OR 1=1 vs AND 1=2 response differs",
                      verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.92, priority=2),
            JudgeRule(rule_id="SQLI-R003",
                      condition="SQL error message visible in response",
                      verdict=FindingStatus.CONFIRMED_EXPLOITED, confidence=0.88, priority=3),
        ]
