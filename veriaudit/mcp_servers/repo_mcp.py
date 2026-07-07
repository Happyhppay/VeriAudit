# VeriAudit - Repository MCP Server
# Provides tools for cloning repos, detecting language/build system,
# extracting project manifests, listing tags, and reading files.
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from veriaudit.core.schema import MCPToolCall, MCPToolResult
from veriaudit.mcp_servers.base_mcp import BaseMCP

# ---- Well-known file extension -> language mapping ----
EXTENSION_LANG_MAP = {
    ".py": "Python",
    ".php": "PHP",
    ".go": "Go",
    ".java": "Java",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".c": "C++",
    ".h": "C++",
    ".hpp": "C++",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".js": "JavaScript",
    ".ts": "JavaScript",
    ".jsx": "JavaScript",
    ".tsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".cs": "C#",
    ".scala": "Scala",
    ".lua": "Lua",
    ".sh": "Shell",
    ".bash": "Shell",
    ".sql": "SQL",
    ".vue": "JavaScript",
    ".svelte": "JavaScript",
}

# ---- Build system indicator files ----
BUILD_INDICATORS = {
    "CMakeLists.txt": "cmake",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "go.mod": "go_modules",
    "Cargo.toml": "cargo",
    "package.json": "npm",
    "composer.json": "composer",
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "pyproject.toml": "poetry",
    "setup.py": "setuptools",
    "Gemfile": "bundler",
    "Makefile": "make",
    "meson.build": "meson",
    "BUILD": "bazel",
    "WORKSPACE": "bazel",
    "BUILD.bazel": "bazel",
}

# ---- Framework indicators (filename -> framework) ----
FRAMEWORK_INDICATORS = {
    "Dockerfile": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "nginx.conf": "nginx",
    "httpd.conf": "apache",
    ".htaccess": "apache",
}

# ---- Test directory names ----
TEST_DIR_NAMES = {"test", "tests", "spec", "specs", "__tests__", "t", "testing"}

# ---- Fuzz directory names ----
FUZZ_DIR_NAMES = {"fuzz", "fuzzing", "fuzzer", "fuzzers", "test_fuzz"}

# ---- CI config file patterns ----
CI_PATTERNS = [
    ".github/workflows/",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/",
    ".travis.yml",
    ".drone.yml",
    "azure-pipelines.yml",
    ".buildkite/",
]

# ---- Common dependency file names ----
DEPENDENCY_FILE_NAMES = [
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.json", "composer.lock",
    "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "CMakeLists.txt", "conanfile.txt", "conanfile.py", "vcpkg.json",
    "meson.build",
    "Makefile",
    "WORKSPACE", "BUILD", "BUILD.bazel",
]


class RepoMCP(BaseMCP):
    """MCP server for repository operations: clone, detect, manifest, tags, file access."""

    # ------------------------------------------------------------------
    # server_name
    # ------------------------------------------------------------------

    @property
    def server_name(self) -> str:
        return "repo_mcp"

    # ==================================================================
    # Tool methods
    # ==================================================================

    # ── clone_repo ────────────────────────────────────────────────────

    def clone_repo(self, url: str, commit: str = None,
                   target_dir: str = None) -> dict:
        """
        Clone a git repository (shallow) and optionally check out
        a specific commit.
        """
        start = time.time()

        # Determine project name and target directory
        project_name = self._project_name_from_url(url)
        if target_dir is None:
            target_dir = os.path.join(
                os.path.abspath("./workspace/repos"), project_name
            )

        os.makedirs(os.path.dirname(target_dir), exist_ok=True)

        # Remove existing directory if present
        if os.path.exists(target_dir):
            import shutil
            shutil.rmtree(target_dir)

        if url.startswith("http://") or url.startswith("https://"):
            clone_cmd = ["git", "clone", "--depth=1", url, target_dir]
        else:
            # Local path
            clone_cmd = ["git", "clone", url, target_dir]

        result = subprocess.run(
            clone_cmd, capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr.strip()}")

        # If a specific commit is requested, fetch and checkout
        if commit:
            fetch_cmd = ["git", "-C", target_dir, "fetch", "--depth=1",
                         "origin", commit]
            subprocess.run(fetch_cmd, capture_output=True, text=True,
                           timeout=120, check=True)
            checkout_cmd = ["git", "-C", target_dir, "checkout", commit]
            subprocess.run(checkout_cmd, capture_output=True, text=True,
                           timeout=30, check=True)

        # Record final commit SHA
        sha_result = subprocess.run(
            ["git", "-C", target_dir, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=True
        )
        commit_sha = sha_result.stdout.strip()

        elapsed = time.time() - start
        return {
            "repo_path": os.path.abspath(target_dir),
            "commit_sha": commit_sha,
            "clone_time_seconds": round(elapsed, 3),
        }

    # ── detect_language ───────────────────────────────────────────────

    def detect_language(self, repo_path: str) -> dict:
        """
        Walk the repository tree, count file extensions, and infer the
        primary language, build system, and frameworks in use.
        """
        if not os.path.isdir(repo_path):
            raise ValueError(f"Not a directory: {repo_path}")

        ext_counter: Counter = Counter()
        build_system = "unknown"
        frameworks: List[str] = []
        total_files = 0

        for root, dirs, files in os.walk(repo_path):
            # Skip hidden / vendor / node_modules directories
            dirs[:] = [d for d in dirs if not d.startswith(".")
                        and d not in ("node_modules", "vendor",
                                       "__pycache__", "target",
                                       ".git", "build", "dist", "out")]

            for fname in files:
                total_files += 1
                ext = os.path.splitext(fname)[1].lower()
                if ext in EXTENSION_LANG_MAP:
                    ext_counter[ext] += 1

                # Detect build system from indicator files
                if fname in BUILD_INDICATORS and build_system == "unknown":
                    build_system = BUILD_INDICATORS[fname]

                # Detect frameworks
                if fname in FRAMEWORK_INDICATORS:
                    fw = FRAMEWORK_INDICATORS[fname]
                    if fw not in frameworks:
                        frameworks.append(fw)

        # Primary language = most common extension
        primary_language = "unknown"
        confidence = 0.0
        if ext_counter:
            top_ext, top_count = ext_counter.most_common(1)[0]
            primary_language = EXTENSION_LANG_MAP.get(top_ext, "unknown")
            total_lang_files = sum(ext_counter.values())
            confidence = round(top_count / max(total_lang_files, 1), 3)

        # Build file_stats dict
        file_stats = {
            "total_files": total_files,
            "language_files": sum(ext_counter.values()),
            "extensions": dict(ext_counter.most_common(20)),
        }

        return {
            "primary_language": primary_language,
            "confidence": confidence,
            "build_system": build_system,
            "file_stats": file_stats,
            "frameworks": frameworks,
        }

    # ── extract_manifest ──────────────────────────────────────────────

    def extract_manifest(self, repo_path: str) -> dict:
        """
        Produce a high-level manifest: file count, approximate LOC,
        test/fuzz directories, CI configs, and dependency files.
        """
        if not os.path.isdir(repo_path):
            raise ValueError(f"Not a directory: {repo_path}")

        file_count = 0
        total_loc = 0
        test_dirs: List[str] = []
        fuzz_dirs: List[str] = []
        ci_configs: List[str] = []
        dependency_files: List[str] = []

        for root, dirs, files in os.walk(repo_path):
            # Skip well-known noise directories
            dirs[:] = [d for d in dirs
                        if d not in ("node_modules", "vendor",
                                      "__pycache__", ".git",
                                      "target", "build", "dist",
                                      "out", ".tox", ".eggs")]

            rel_root = os.path.relpath(root, repo_path).replace("\\", "/")

            # Detect test directories
            dir_basename = os.path.basename(root).lower()
            if dir_basename in TEST_DIR_NAMES:
                test_dirs.append(rel_root)

            # Detect fuzz directories
            if dir_basename in FUZZ_DIR_NAMES:
                fuzz_dirs.append(rel_root)

            for fname in files:
                file_count += 1

                # Attempt to count LOC for text-ish files
                ext = os.path.splitext(fname)[1].lower()
                if self._is_text_extension(ext):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8",
                                  errors="ignore") as fh:
                            loc = sum(1 for _ in fh)
                        total_loc += loc
                    except OSError:
                        pass

                # Check CI configs
                full_rel = os.path.join(rel_root, fname).replace("\\", "/")
                for ci_pat in CI_PATTERNS:
                    if (ci_pat.endswith("/") and full_rel.startswith(ci_pat)) \
                            or full_rel == ci_pat or full_rel.endswith("/" + ci_pat):
                        ci_configs.append(full_rel)

                # Collect dependency files
                if fname in DEPENDENCY_FILE_NAMES:
                    dependency_files.append(full_rel)

        return {
            "file_count": file_count,
            "total_loc": total_loc,
            "has_fuzz_dir": len(fuzz_dirs) > 0,
            "fuzz_dirs": fuzz_dirs,
            "ci_configs": sorted(set(ci_configs)),
            "test_dirs": sorted(set(test_dirs)),
            "dependency_files": sorted(set(dependency_files)),
        }

    # ── list_tags ─────────────────────────────────────────────────────

    def list_tags(self, repo_path: str, count: int = 20) -> dict:
        """
        Return the most recent tags (version-sorted) with their
        commit SHAs and whether they look like releases.
        """
        result = subprocess.run(
            ["git", "-C", repo_path, "tag", "-l",
             "--sort=-version:refname"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            raise RuntimeError(f"git tag failed: {result.stderr.strip()}")

        all_tags = [t.strip() for t in result.stdout.splitlines() if t.strip()]
        tags: List[dict] = []

        for tag_name in all_tags[:count]:
            try:
                sha_result = subprocess.run(
                    ["git", "-C", repo_path, "rev-list", "-n", "1", tag_name],
                    capture_output=True, text=True, timeout=10
                )
                commit_sha = sha_result.stdout.strip() if sha_result.returncode == 0 else ""
            except Exception:
                commit_sha = ""

            is_release = bool(
                re.match(r"^v?\d+\.\d+", tag_name) or
                re.match(r"^release", tag_name, re.IGNORECASE)
            )
            tags.append({
                "name": tag_name,
                "commit_sha": commit_sha,
                "is_release": is_release,
            })

        return {"tags": tags}

    # ── get_file ──────────────────────────────────────────────────────

    def get_file(self, repo_path: str, file_path: str,
                 max_bytes: int = 524288) -> dict:
        """
        Read a file from the repository and return its content.
        """
        # Resolve the full path safely
        full_path = os.path.normpath(
            os.path.join(repo_path, file_path)
        )
        # Prevent directory traversal attacks
        abs_repo = os.path.abspath(repo_path)
        abs_file = os.path.abspath(full_path)
        if not abs_file.startswith(abs_repo + os.sep) and abs_file != abs_repo:
            raise ValueError(
                f"Path traversal denied: {file_path} is outside {repo_path}"
            )

        if not os.path.isfile(abs_file):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(abs_file)
        if file_size > max_bytes:
            raise ValueError(
                f"File size {file_size} exceeds max_bytes limit {max_bytes}"
            )

        with open(abs_file, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        return {
            "content": content,
            "file_path": file_path,
            "size_bytes": file_size,
        }

    # ==================================================================
    # Tool schemas (OpenAI-compatible)
    # ==================================================================

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": f"{self.server_name}.clone_repo",
                "description": "Shallow-clone a git repository and optionally check out a specific commit. Returns repo path, commit SHA, and elapsed time.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Git clone URL (http/https) or local path.",
                        },
                        "commit": {
                            "type": "string",
                            "description": "Optional commit SHA to checkout after cloning.",
                        },
                        "target_dir": {
                            "type": "string",
                            "description": "Optional target directory. Defaults to ./workspace/repos/<project_name>.",
                        },
                    },
                    "required": ["url"],
                },
            },
            {
                "name": f"{self.server_name}.detect_language",
                "description": "Walk the repository and detect primary language, build system, and frameworks by counting file extensions.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                    },
                    "required": ["repo_path"],
                },
            },
            {
                "name": f"{self.server_name}.extract_manifest",
                "description": "Extract a high-level manifest: file count, approximate LOC, test/fuzz directories, CI configs, and dependency files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                    },
                    "required": ["repo_path"],
                },
            },
            {
                "name": f"{self.server_name}.list_tags",
                "description": "List the most recent git tags (version-sorted) with their commit SHAs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                        "count": {
                            "type": "integer",
                            "description": "Maximum number of tags to return (default 20).",
                            "default": 20,
                        },
                    },
                    "required": ["repo_path"],
                },
            },
            {
                "name": f"{self.server_name}.get_file",
                "description": "Read a file from the repository and return its content (up to max_bytes).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute path to the cloned repository.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Relative path to the file within the repository.",
                        },
                        "max_bytes": {
                            "type": "integer",
                            "description": "Maximum file size in bytes to read (default 524288 = 512 KB).",
                            "default": 524288,
                        },
                    },
                    "required": ["repo_path", "file_path"],
                },
            },
        ]

    # ==================================================================
    # Internal helpers
    # ==================================================================

    @staticmethod
    def _project_name_from_url(url: str) -> str:
        """Extract a human-readable project name from a git URL."""
        # Remove trailing .git and take the last path component
        name = url.rstrip("/")
        if name.endswith(".git"):
            name = name[:-4]
        # Take everything after the last slash
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        # Remove any query / fragment
        name = name.split("?")[0].split("#")[0]
        return name or "repo"

    @staticmethod
    def _is_text_extension(ext: str) -> bool:
        """Return True if the file extension suggests a text file worth counting LOC."""
        return ext in {
            ".py", ".php", ".go", ".java", ".cpp", ".cc", ".cxx", ".c",
            ".h", ".hpp", ".rs", ".rb", ".js", ".ts", ".jsx", ".tsx",
            ".mjs", ".cjs", ".swift", ".kt", ".cs", ".scala", ".lua",
            ".sh", ".bash", ".sql", ".vue", ".svelte", ".css", ".scss",
            ".less", ".html", ".htm", ".xml", ".json", ".yaml", ".yml",
            ".toml", ".ini", ".cfg", ".conf", ".txt", ".md", ".rst",
            ".cmake", ".gradle", ".dockerfile", ".proto", ".graphql",
            ".sol", ".vy", ".move",
        }
