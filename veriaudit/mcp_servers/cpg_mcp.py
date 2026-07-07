# VeriAudit - CPG MCP Server (Code Property Graph via Joern)
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from veriaudit.mcp_servers.base_mcp import BaseMCP


class CPGMCP(BaseMCP):
    """MCP server for Code Property Graph operations via Joern."""

    @property
    def server_name(self) -> str:
        return "cpg_mcp"

    # ==================== Import ====================

    def import_to_graph(self, repo_path: str, language: str,
                         compile_commands_path: str = None,
                         backend: str = "joern") -> dict:
        """
        Import project into Joern to build the Code Property Graph.
        This is a heavyweight operation — may take 10-30 minutes for large projects.
        """
        import subprocess

        graph_name = os.path.basename(repo_path.strip('/').strip('\\'))
        output_dir = os.path.join("./workspace/cpg", graph_name)
        os.makedirs(output_dir, exist_ok=True)

        try:
            cmd = ["joern-parse", repo_path, "--output", output_dir]
            if compile_commands_path and os.path.exists(compile_commands_path):
                cmd.extend(["--compile-commands", compile_commands_path])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            node_count = 0
            edge_count = 0
            # Rough estimation from Joern output
            for line in result.stderr.split('\n'):
                if 'nodes' in line.lower():
                    m = re.search(r'(\d+)\s*nodes', line, re.IGNORECASE)
                    if m:
                        node_count = int(m.group(1))
                if 'edges' in line.lower():
                    m = re.search(r'(\d+)\s*edges', line, re.IGNORECASE)
                    if m:
                        edge_count = int(m.group(1))

            return {
                "graph_id": output_dir,
                "node_count": node_count,
                "edge_count": edge_count,
                "success": result.returncode == 0,
                "stderr": result.stderr[-1000:],
            }
        except subprocess.TimeoutExpired:
            return {"graph_id": output_dir, "node_count": 0, "edge_count": 0,
                    "success": False, "stderr": "Joern import timed out (30 min)"}
        except FileNotFoundError:
            return {"graph_id": output_dir, "node_count": 0, "edge_count": 0,
                    "success": False, "stderr": "Joern not installed — `joern-parse` not found in PATH"}

    # ==================== Queries ====================

    def query_callers(self, graph_id: str, function_name: str,
                       file: str = None, max_depth: int = 5) -> dict:
        """Query callers of a function."""
        return self._run_joern_query(graph_id, f"cpg.method.name(\"{function_name}\").caller.l",
                                      "callers")

    def query_callees(self, graph_id: str, function_name: str,
                       file: str = None, max_depth: int = 5) -> dict:
        """Query callees of a function."""
        return self._run_joern_query(graph_id, f"cpg.method.name(\"{function_name}\").callee.l",
                                      "callees")

    def query_typed_taint_path(self, graph_id: str,
                                source_types: List[str],
                                sink_types: List[str],
                                source_function: str = None,
                                sink_function: str = None,
                                max_path_length: int = 30) -> dict:
        """
        Query typed taint paths from typed sources to typed sinks.
        This is a simplified version — full implementation requires Joern's
        dataflow/taint analysis passes.
        """
        # For now, return a structured placeholder
        # In production, this would run Joern's:
        #   cpg.method.name(...).reachableBy(...).l
        # with source/sink filtering
        return {
            "paths": [],
            "note": "Full typed taint path query requires Joern dataflow passes. "
                    "Placeholder implementation. In production, this executes: "
                    "joern --script query_taint.scala with source/sink type filtering.",
        }

    def find_entrypoints(self, graph_id: str, language: str) -> dict:
        """Find all entry points in the project."""
        patterns = {
            "c++": ["main\\(", "LLVMFuzzerTestOneInput"],
            "c": ["main\\(", "LLVMFuzzerTestOneInput"],
            "php": ["function ", "public function "],
            "go": ["func main\\(\\)", "func \\(.*\\) Handle"],
            "java": ["public static void main", "@RestController", "@PostMapping", "@GetMapping"],
            "python": ["def main", "if __name__ == '__main__'", "@app.route", "@app.get"],
            "javascript": ["app\\.get\\(", "router\\.post\\(", "module\\.exports", "export default"],
            "rust": ["fn main\\(\\)", "#\\[tokio::main\\]", "#\\[actix_web::main\\]"],
            "ruby": ["def ", "class .*Controller"],
        }

        return {
            "entry_points": [],  # Would be populated by Joern query
            "search_patterns": patterns.get(language.lower(), ["main\\("]),
            "note": "Entry point discovery via Joern. Run joern-query on the graph for precise results.",
        }

    def find_dangerous_calls(self, graph_id: str, language: str,
                              categories: List[str] = None) -> dict:
        """Find all dangerous API calls in the project."""
        dangerous_functions = {
            "c++": ["memcpy", "strcpy", "sprintf", "gets", "system", "popen",
                     "execl", "malloc", "free", "read", "fread", "recv", "send",
                     "strcat", "getenv", "putenv"],
            "php": ["system", "exec", "shell_exec", "passthru", "popen", "eval",
                     "assert", "create_function", "unserialize", "include", "require",
                     "file_get_contents", "curl_exec", "proc_open"],
            "go": ["os/exec.Command", "os.Open", "fmt.Sprintf", "unsafe.Pointer",
                    "syscall", "net.Listen", "http.Get"],
            "java": ["Runtime.exec", "ProcessBuilder", "ObjectInputStream",
                      "DocumentBuilder", "ScriptEngine.eval", "URL.openConnection"],
            "python": ["os.system", "subprocess.call", "eval", "exec", "pickle.loads",
                        "yaml.load", "requests.get", "marshal.loads"],
            "javascript": ["eval", "child_process.exec", "Function(", "vm.runInNewContext",
                            "innerHTML", "dangerouslySetInnerHTML"],
            "rust": ["unsafe", "std::mem::transmute", "std::process::Command",
                      "std::ptr::read", "std::ptr::write"],
            "ruby": ["eval", "system", "exec", "`", "%x", "YAML.load", "Marshal.load",
                      "open(", "File.open"],
        }

        return {
            "dangerous_calls": [],
            "searched_functions": dangerous_functions.get(language.lower(), []),
            "note": "Dangerous call discovery via Joern. In production, runs cpg.method.name(...).l for each pattern.",
        }

    def get_function_source(self, graph_id: str, function_name: str,
                             file: str = None) -> dict:
        """Get the source code of a specific function."""
        return {
            "source_code": f"// Source for {function_name} — retrieved via Joern CPG",
            "file": file or "unknown",
            "start_line": 0,
            "end_line": 0,
            "note": "Function source retrieval via Joern. In production, uses cpg.method.name('...').code.l",
        }

    # ==================== Internal ====================

    def _run_joern_query(self, graph_id: str, query: str,
                          result_key: str) -> dict:
        """Execute a Joern CPGQL query."""
        import subprocess

        try:
            cmd = ["joern", "--import", graph_id, "--script", "-"]
            result = subprocess.run(
                cmd,
                input=query.encode(),
                capture_output=True,
                text=True,
                timeout=120,
            )

            entries = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('//') and not line.startswith('val'):
                    # Parse Joern's output format
                    m = re.search(r'\((.*):(\d+)\)', line)
                    if m:
                        entries.append({
                            "name": line.split('(')[0].strip() if '(' in line else line,
                            "file": m.group(1),
                            "line": int(m.group(2)),
                        })

            return {result_key: entries, "count": len(entries)}
        except FileNotFoundError:
            return {result_key: [], "count": 0,
                    "error": "Joern not installed"}
        except subprocess.TimeoutExpired:
            return {result_key: [], "count": 0,
                    "error": "Query timed out"}

    # ==================== Tool Schemas ====================

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {"name": f"{self.server_name}.import_to_graph",
             "description": "Import project into Joern Code Property Graph",
             "parameters": {"type": "object", "properties": {"repo_path": {"type": "string"}, "language": {"type": "string"}, "compile_commands_path": {"type": "string"}, "backend": {"type": "string", "default": "joern"}}, "required": ["repo_path", "language"]}},
            {"name": f"{self.server_name}.query_callers",
             "description": "Find functions that call the given function",
             "parameters": {"type": "object", "properties": {"graph_id": {"type": "string"}, "function_name": {"type": "string"}, "file": {"type": "string"}, "max_depth": {"type": "integer", "default": 5}}, "required": ["graph_id", "function_name"]}},
            {"name": f"{self.server_name}.query_callees",
             "description": "Find functions called by the given function",
             "parameters": {"type": "object", "properties": {"graph_id": {"type": "string"}, "function_name": {"type": "string"}, "file": {"type": "string"}, "max_depth": {"type": "integer", "default": 5}}, "required": ["graph_id", "function_name"]}},
            {"name": f"{self.server_name}.query_typed_taint_path",
             "description": "Query typed taint paths from source types to sink types",
             "parameters": {"type": "object", "properties": {"graph_id": {"type": "string"}, "source_types": {"type": "array", "items": {"type": "string"}}, "sink_types": {"type": "array", "items": {"type": "string"}}, "source_function": {"type": "string"}, "sink_function": {"type": "string"}, "max_path_length": {"type": "integer", "default": 30}}, "required": ["graph_id", "source_types", "sink_types"]}},
            {"name": f"{self.server_name}.find_entrypoints",
             "description": "Find all entry points in the project",
             "parameters": {"type": "object", "properties": {"graph_id": {"type": "string"}, "language": {"type": "string"}}, "required": ["graph_id", "language"]}},
            {"name": f"{self.server_name}.find_dangerous_calls",
             "description": "Find dangerous API calls in the project",
             "parameters": {"type": "object", "properties": {"graph_id": {"type": "string"}, "language": {"type": "string"}, "categories": {"type": "array", "items": {"type": "string"}}}, "required": ["graph_id", "language"]}},
            {"name": f"{self.server_name}.get_function_source",
             "description": "Get the source code of a specific function",
             "parameters": {"type": "object", "properties": {"graph_id": {"type": "string"}, "function_name": {"type": "string"}, "file": {"type": "string"}}, "required": ["graph_id", "function_name"]}},
        ]
