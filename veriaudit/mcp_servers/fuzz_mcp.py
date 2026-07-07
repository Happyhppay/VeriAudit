# VeriAudit - Fuzz MCP Server
from __future__ import annotations

import glob
import hashlib
import os
import re
import subprocess
from typing import Any, Dict, List, Optional

from veriaudit.core.schema import MCPToolCall, MCPToolResult
from veriaudit.mcp_servers.base_mcp import BaseMCP


class FuzzMCP(BaseMCP):
    """MCP server for fuzzing orchestration — libFuzzer, AFL++, per-language fuzz engines."""

    @property
    def server_name(self) -> str:
        return "fuzz_mcp"

    # ==================== Discovery ====================

    def discover_targets(self, repo_path: str) -> dict:
        """
        Discover existing fuzz targets in the repository.
        Scans for LLVMFuzzerTestOneInput, AFL harnesses, and fuzz directories.
        """
        targets = []

        # Scan fuzz directories
        fuzz_dirs = ["fuzz", "fuzz/", "fuzzing", "test/fuzz", "tests/fuzz", "tests/fuzzing"]
        for fuzz_dir in fuzz_dirs:
            full = os.path.join(repo_path, fuzz_dir)
            if not os.path.isdir(full):
                continue
            for root, dirs, files in os.walk(full):
                for f in files:
                    fpath = os.path.join(root, f)
                    if f.endswith(('.cpp', '.c', '.cc', '.cxx', '.go', '.java', '.rs')):
                        try:
                            content = open(fpath, encoding='utf-8', errors='ignore').read()
                            if 'LLVMFuzzerTestOneInput' in content:
                                targets.append({
                                    "name": os.path.splitext(f)[0],
                                    "file": fpath,
                                    "engine": "libfuzzer",
                                    "build_target": self._guess_build_target(fpath),
                                })
                            elif 'AFL_HARNESS' in content or '__AFL_FUZZ_INIT' in content:
                                targets.append({
                                    "name": os.path.splitext(f)[0],
                                    "file": fpath,
                                    "engine": "afl",
                                    "build_target": self._guess_build_target(fpath),
                                })
                        except Exception:
                            pass

        # Also check Go fuzz tests
        for root, dirs, files in os.walk(repo_path):
            for f in files:
                if f.endswith('_test.go'):
                    fpath = os.path.join(root, f)
                    try:
                        content = open(fpath, encoding='utf-8', errors='ignore').read()
                        if 'func Fuzz' in content:
                            targets.append({
                                "name": os.path.splitext(f)[0],
                                "file": fpath,
                                "engine": "go-fuzz",
                                "build_target": os.path.relpath(root, repo_path),
                            })
                    except Exception:
                        pass

        return {"targets": targets, "count": len(targets)}

    def _guess_build_target(self, fpath: str) -> str:
        """Guess the CMake/Make target name from file path."""
        name = os.path.splitext(os.path.basename(fpath))[0]
        common = {
            "fuzz": "fuzz", "fuzz_read_print_write": "fuzz-read-print-write",
        }
        return common.get(name, name)

    # ==================== Build ====================

    def build_target(self, container_id: str, repo_path: str,
                      target_name: str, build_dir: str = "") -> dict:
        """Build a fuzz target inside the container."""
        from veriaudit.core.container_pool import ContainerPool
        pool = ContainerPool()

        actual_build_dir = build_dir or os.path.join(repo_path, "build_fuzz")
        cmd = f"cmake --build {actual_build_dir} --target {target_name} -j$(nproc)"

        exit_code, stdout, stderr = pool.exec_cmd(container_id, cmd, timeout=600)

        # Find the built binary
        binary_path = ""
        for search in [os.path.join(actual_build_dir, target_name),
                       os.path.join(actual_build_dir, "fuzz", target_name)]:
            if os.path.exists(search):
                binary_path = search
                break

        return {
            "binary_path": binary_path,
            "build_dir": actual_build_dir,
            "success": exit_code == 0,
            "stderr": stderr[:2000],
        }

    # ==================== Run ====================

    def run_fuzzer(self, container_id: str, target_binary: str,
                    corpus_dir: str, timeout_seconds: int = 3600,
                    artifact_dir: str = "/tmp/fuzz_artifacts",
                    max_len: int = None,
                    extra_args: List[str] = None) -> dict:
        """Run a fuzzer on a target binary."""
        from veriaudit.core.container_pool import ContainerPool
        pool = ContainerPool()

        # Create artifact directory
        pool.exec_cmd(container_id, f"mkdir -p {artifact_dir}", timeout=10)

        cmd_parts = [
            target_binary,
            f"-max_total_time={timeout_seconds}",
            f"-artifact_prefix={artifact_dir}/",
            "-print_final_stats=1",
        ]
        if max_len:
            cmd_parts.append(f"-max_len={max_len}")
        if extra_args:
            cmd_parts.extend(extra_args)
        cmd_parts.append(corpus_dir)

        cmd = " ".join(cmd_parts)
        exit_code, stdout, stderr = pool.exec_cmd(container_id, cmd, timeout=timeout_seconds + 60)

        # Collect crashes
        crashes = []
        pool.exec_cmd(container_id, f"ls {artifact_dir}/", timeout=5)
        _, ls_out, _ = pool.exec_cmd(container_id, f"ls -la {artifact_dir}/", timeout=5)
        for line in ls_out.split('\n'):
            if line.startswith('-') and 'crash' in line.lower():
                fname = line.split()[-1]
                crashes.append({
                    "input_file": f"{artifact_dir}/{fname}",
                    "crash_type": "",
                    "asan_log_path": "",
                })

        # Parse stats
        total_execs = 0
        execs_per_sec = 0
        stats_match = re.search(r'stat::number_of_executed_units:\s*(\d+)', stdout)
        if stats_match:
            total_execs = int(stats_match.group(1))
        speed_match = re.search(r'exec/s:\s*(\d+)', stdout)
        if speed_match:
            execs_per_sec = int(speed_match.group(1))

        return {
            "crashes": crashes,
            "coverage_pct": 0.0,
            "total_execs": total_execs,
            "execs_per_sec": execs_per_sec,
            "duration_seconds": timeout_seconds,
            "stderr_tail": stderr[-2000:],
        }

    # ==================== Crash Processing ====================

    def minimize_crash(self, container_id: str, crash_input: str,
                        target_binary: str,
                        output_path: str = "/tmp/minimized_crash") -> dict:
        """Minimize a crash input using libFuzzer's minimize mode."""
        from veriaudit.core.container_pool import ContainerPool
        pool = ContainerPool()

        cmd = f"{target_binary} -minimize_crash=1 -runs=100000 {crash_input}"
        pool.exec_cmd(container_id, cmd, timeout=120)

        # Copy minimized file
        pool.exec_cmd(container_id, f"cp {crash_input} {output_path}", timeout=5)

        # Get sizes
        before_stat = pool.exec_cmd(container_id, f"stat -c%s {crash_input} 2>/dev/null || wc -c < {crash_input}", timeout=5)
        after_stat = pool.exec_cmd(container_id, f"stat -c%s {output_path} 2>/dev/null || wc -c < {output_path}", timeout=5)

        try:
            original_size = int(before_stat[1].strip().split('\n')[0])
            minimized_size = int(after_stat[1].strip().split('\n')[0])
        except (ValueError, IndexError):
            original_size = os.path.getsize(crash_input) if os.path.exists(crash_input) else 0
            minimized_size = original_size

        reduction = (1 - minimized_size / max(original_size, 1)) * 100

        return {
            "minimized_input": output_path,
            "original_size": original_size,
            "minimized_size": minimized_size,
            "reduction_pct": round(reduction, 1),
        }

    def deduplicate_crashes(self, crashes: List[Dict]) -> dict:
        """
        Deduplicate crashes by (sanitizer error type, top 3 project frames, input size bucket).
        """
        if not crashes:
            return {"deduplicated": [], "original_count": 0, "deduped_count": 0}

        buckets = {}
        for c in crashes:
            error_type = c.get("error_type", c.get("crash_type", "unknown"))
            frames = c.get("top_frames", [])
            size = c.get("input_size", 0)

            # Create a normalized key
            frame_key = tuple(
                (f.get("function", ""), f.get("file", os.path.basename(f.get("file", ""))))
                for f in frames[:3]
            )
            size_bucket = size // 1024
            key = (error_type, frame_key, size_bucket)

            if key not in buckets:
                buckets[key] = []
            buckets[key].append(c)

        # Keep smallest input per bucket
        deduped = []
        for bucket_crashes in buckets.values():
            best = min(bucket_crashes, key=lambda c: c.get("input_size", float("inf")))
            deduped.append(best)

        return {
            "deduplicated": deduped,
            "original_count": len(crashes),
            "deduped_count": len(deduped),
        }

    def generate_corpus(self, repo_path: str, output_dir: str,
                         language: str = "c++") -> dict:
        """Generate a seed corpus from project test data."""
        imported = []

        # Collect sample files
        test_dirs = ["test/data", "tests/data", "samples", "examples", "test/images", "tests/fixtures"]
        for td in test_dirs:
            full = os.path.join(repo_path, td)
            if os.path.isdir(full):
                for f in glob.glob(f"{full}/**/*", recursive=True):
                    if os.path.isfile(f) and os.path.getsize(f) < 1024 * 100:
                        dest = os.path.join(output_dir, hashlib.md5(f.encode()).hexdigest()[:8])
                        try:
                            import shutil
                            shutil.copy2(f, dest)
                            imported.append(dest)
                        except Exception:
                            pass

        os.makedirs(output_dir, exist_ok=True)

        return {
            "corpus_dir": output_dir,
            "file_count": len(imported),
            "imported_from": test_dirs,
        }

    def generate_harness(self, function_name: str, file_path: str,
                          language: str, repo_path: str,
                          output_dir: str = "/tmp/harnesses") -> dict:
        """
        Generate a libFuzzer harness skeleton for a target function.
        In production, this would use an LLM to generate a complete harness.
        For now, generates a template.
        """
        os.makedirs(output_dir, exist_ok=True)
        harness_file = os.path.join(output_dir, f"harness_{function_name}.cpp")
        target_name = f"fuzz-{function_name}"

        harness_code = f'''// Auto-generated fuzz harness by VeriAudit
// Target: {function_name} in {file_path}
#include <cstdint>
#include <cstddef>

// TODO: Add proper includes for the target
// #include "{os.path.relpath(file_path, repo_path)}"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {{
    if (size < 8) return 0;
    // TODO: Call the target function with fuzz data
    // {function_name}(data, size);
    return 0;
}}
'''
        with open(harness_file, 'w') as f:
            f.write(harness_code)

        return {
            "harness_path": harness_file,
            "harness_code": harness_code,
            "build_target_name": target_name,
            "note": "Harness skeleton generated. Requires manual completion of includes and function call.",
        }

    # ==================== Tool Schemas ====================

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {"name": f"{self.server_name}.discover_targets",
             "description": "Discover existing fuzz targets in a repository",
             "parameters": {"type": "object", "properties": {"repo_path": {"type": "string"}}, "required": ["repo_path"]}},
            {"name": f"{self.server_name}.build_target",
             "description": "Build a fuzz target inside a Docker container",
             "parameters": {"type": "object", "properties": {"container_id": {"type": "string"}, "repo_path": {"type": "string"}, "target_name": {"type": "string"}, "build_dir": {"type": "string"}}, "required": ["container_id", "repo_path", "target_name"]}},
            {"name": f"{self.server_name}.run_fuzzer",
             "description": "Run libFuzzer/AFL on a target binary",
             "parameters": {"type": "object", "properties": {"container_id": {"type": "string"}, "target_binary": {"type": "string"}, "corpus_dir": {"type": "string"}, "timeout_seconds": {"type": "integer", "default": 3600}, "artifact_dir": {"type": "string"}, "max_len": {"type": "integer"}, "extra_args": {"type": "array", "items": {"type": "string"}}}, "required": ["container_id", "target_binary", "corpus_dir"]}},
            {"name": f"{self.server_name}.minimize_crash",
             "description": "Minimize a crash input",
             "parameters": {"type": "object", "properties": {"container_id": {"type": "string"}, "crash_input": {"type": "string"}, "target_binary": {"type": "string"}, "output_path": {"type": "string"}}, "required": ["container_id", "crash_input", "target_binary"]}},
            {"name": f"{self.server_name}.deduplicate_crashes",
             "description": "Deduplicate crashes by error type and stack frames",
             "parameters": {"type": "object", "properties": {"crashes": {"type": "array", "items": {"type": "object"}}}, "required": ["crashes"]}},
            {"name": f"{self.server_name}.generate_corpus",
             "description": "Generate seed corpus from project test data",
             "parameters": {"type": "object", "properties": {"repo_path": {"type": "string"}, "output_dir": {"type": "string"}, "language": {"type": "string"}}, "required": ["repo_path", "output_dir"]}},
            {"name": f"{self.server_name}.generate_harness",
             "description": "Generate a fuzz harness skeleton for a target function",
             "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}, "file_path": {"type": "string"}, "language": {"type": "string"}, "repo_path": {"type": "string"}, "output_dir": {"type": "string"}}, "required": ["function_name", "file_path", "language", "repo_path"]}},
        ]
