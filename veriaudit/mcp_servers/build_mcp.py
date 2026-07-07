# VeriAudit - Build MCP Server
# Provides tools for creating ephemeral Docker build environments,
# configuring builds, compiling targets, and tearing containers down.
from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Dict, List, Optional

from veriaudit.core.schema import MCPToolCall, MCPToolResult
from veriaudit.mcp_servers.base_mcp import BaseMCP

# ---- Default Docker images per (language, build_system) ----
# These map to images pre-built with appropriate toolchains.
DEFAULT_IMAGES = {
    ("c++", "cmake"): "veriaudit/cpp-fuzz:latest",
    ("c", "cmake"): "veriaudit/cpp-fuzz:latest",
    ("c++", "make"): "veriaudit/cpp-fuzz:latest",
    ("c", "make"): "veriaudit/cpp-fuzz:latest",
    ("c++", "meson"): "veriaudit/cpp-fuzz:latest",
    ("php", "composer"): "veriaudit/php-web:latest",
    ("go", "go_modules"): "veriaudit/go:latest",
    ("java", "maven"): "veriaudit/java:latest",
    ("java", "gradle"): "veriaudit/java:latest",
    ("python", "pip"): "veriaudit/python:latest",
    ("python", "poetry"): "veriaudit/python:latest",
    ("python", "setuptools"): "veriaudit/python:latest",
    ("rust", "cargo"): "veriaudit/rust:latest",
    ("ruby", "bundler"): "veriaudit/ruby:latest",
    ("javascript", "npm"): "veriaudit/js:latest",
}


class BuildMCP(BaseMCP):
    """MCP server for Docker-based build environment lifecycle."""

    # ------------------------------------------------------------------
    # server_name
    # ------------------------------------------------------------------

    @property
    def server_name(self) -> str:
        return "build_mcp"

    # ==================================================================
    # Tool methods
    # ==================================================================

    # ── create_build_env ──────────────────────────────────────────────

    def create_build_env(self, language: str, build_system: str,
                         image_tag: str = None) -> dict:
        """
        Create a Docker container with the appropriate toolchain image.
        Returns the container ID and image tag used.
        """
        language_lower = language.lower()
        build_lower = build_system.lower()

        if image_tag is None:
            key = (language_lower, build_lower)
            image_tag = DEFAULT_IMAGES.get(key)
            if image_tag is None:
                # Fallback to a generic image
                image_tag = f"veriaudit/{language_lower}:latest"

        # Create and start the container (daemon mode, keep alive with sleep)
        cmd = [
            "docker", "run", "-d", "--rm",
            image_tag,
            "sleep", "infinity",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to create Docker container: {result.stderr.strip()}"
            )

        container_id = result.stdout.strip()[:12]

        return {
            "container_id": container_id,
            "image_tag": image_tag,
        }

    # ── configure_build ───────────────────────────────────────────────

    def configure_build(self, container_id: str, repo_path: str,
                        build_type: str = "debug",
                        extra_args: str = "") -> dict:
        """
        Detect the build system inside the repo and run the appropriate
        configure step inside the container.

        Returns the build directory, path to compile_commands.json (if
        generated), success flag, and any stderr output.
        """
        # Determine build system from the repo
        build_system = self._detect_build_system(repo_path)

        # Ensure the repo is copied into the container
        self._copy_repo_to_container(container_id, repo_path)

        container_repo = "/workspace/repo"

        if build_system == "cmake":
            return self._configure_cmake(
                container_id, container_repo, build_type, extra_args
            )
        elif build_system == "meson":
            return self._configure_meson(
                container_id, container_repo, build_type, extra_args
            )
        elif build_system == "make":
            return self._configure_make(
                container_id, container_repo, build_type, extra_args
            )
        elif build_system == "composer":
            return self._configure_composer(container_id, container_repo)
        elif build_system == "go_modules":
            return self._configure_go(container_id, container_repo)
        elif build_system in ("maven", "gradle"):
            return self._configure_java(
                container_id, container_repo, build_system, extra_args
            )
        elif build_system == "cargo":
            return self._configure_cargo(
                container_id, container_repo, build_type, extra_args
            )
        elif build_system in ("npm", "yarn", "pnpm"):
            return self._configure_javascript(
                container_id, container_repo, build_system
            )
        elif build_system in ("pip", "poetry", "setuptools", "pipenv"):
            return self._configure_python(
                container_id, container_repo, build_system
            )
        elif build_system == "bundler":
            return self._configure_ruby(container_id, container_repo)
        else:
            # Unknown build system -- return a basic success since
            # there is nothing to configure.
            return {
                "build_dir": container_repo,
                "compile_commands_path": None,
                "success": True,
                "stderr": f"Unknown build system '{build_system}', no configuration performed.",
            }

    # ── compile_target ────────────────────────────────────────────────

    def compile_target(self, container_id: str, build_dir: str,
                       target: str = None, jobs: int = None) -> dict:
        """
        Run the build command inside the container.

        The build_dir is assumed to already be configured.
        """
        if jobs is None:
            import os as _os
            jobs = _os.cpu_count() or 4

        # Heuristic to determine which build command to use
        # Prioritize: cmake --build, then make, then ninja
        if os.path.isabs(build_dir):
            # build_dir is a host path; convert to container path
            container_build_dir = build_dir
        else:
            container_build_dir = build_dir

        # Try cmake --build first (most common)
        cmake_build_cmd = (
            f"cmake --build {container_build_dir} -j{jobs}"
            + (f" --target {target}" if target else "")
        )

        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmake_build_cmd, timeout=900
        )

        if exit_code == 0:
            binary_path = self._find_binary_in_container(
                container_id, container_build_dir
            )
            return {
                "binary_path": binary_path,
                "success": True,
                "stderr": stderr[:3000],
                "exit_code": exit_code,
            }

        # Fallback: try make
        make_cmd = (
            f"make -C {container_build_dir} -j{jobs}"
            + (f" {target}" if target else "")
        )
        exit_code, stdout, stderr = self._docker_exec(
            container_id, make_cmd, timeout=900
        )
        if exit_code == 0:
            binary_path = self._find_binary_in_container(
                container_id, container_build_dir
            )
            return {
                "binary_path": binary_path,
                "success": True,
                "stderr": stderr[:3000],
                "exit_code": exit_code,
            }

        # Fallback: ninja
        ninja_cmd = (
            f"ninja -C {container_build_dir} -j{jobs}"
            + (f" {target}" if target else "")
        )
        exit_code, stdout, stderr = self._docker_exec(
            container_id, ninja_cmd, timeout=900
        )

        binary_path = None
        if exit_code == 0:
            binary_path = self._find_binary_in_container(
                container_id, container_build_dir
            )

        return {
            "binary_path": binary_path,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
            "exit_code": exit_code,
        }

    # ── destroy_build_env ─────────────────────────────────────────────

    def destroy_build_env(self, container_id: str) -> dict:
        """
        Stop and remove a build container.
        """
        success = True
        errors: List[str] = []

        # Stop the container
        stop_result = subprocess.run(
            ["docker", "stop", container_id],
            capture_output=True, text=True, timeout=30,
        )
        if stop_result.returncode != 0:
            success = False
            errors.append(f"docker stop: {stop_result.stderr.strip()}")

        # Force-remove in case stop didn't clean up
        rm_result = subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True, text=True, timeout=15,
        )
        if rm_result.returncode != 0:
            success = False
            errors.append(f"docker rm: {rm_result.stderr.strip()}")

        return {
            "success": success,
            "errors": errors if errors else None,
        }

    # ==================================================================
    # Tool schemas (OpenAI-compatible)
    # ==================================================================

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": f"{self.server_name}.create_build_env",
                "description": "Create a Docker container with the appropriate toolchain image for the given language and build system.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "language": {
                            "type": "string",
                            "description": "Programming language (e.g. 'c++', 'php', 'go', 'java', 'python', 'rust').",
                        },
                        "build_system": {
                            "type": "string",
                            "description": "Build system (e.g. 'cmake', 'composer', 'go_modules', 'maven', 'cargo').",
                        },
                        "image_tag": {
                            "type": "string",
                            "description": "Optional Docker image tag. Auto-selected from language+build_system if omitted.",
                        },
                    },
                    "required": ["language", "build_system"],
                },
            },
            {
                "name": f"{self.server_name}.configure_build",
                "description": "Detect the build system inside the repo and run the appropriate configure step inside the container.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "container_id": {
                            "type": "string",
                            "description": "Docker container ID returned by create_build_env.",
                        },
                        "repo_path": {
                            "type": "string",
                            "description": "Absolute host path to the cloned repository.",
                        },
                        "build_type": {
                            "type": "string",
                            "description": "Build type: debug, release, asan, ubsan, msan, fuzzer, coverage.",
                            "default": "debug",
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional arguments to pass to the configure command.",
                            "default": "",
                        },
                    },
                    "required": ["container_id", "repo_path"],
                },
            },
            {
                "name": f"{self.server_name}.compile_target",
                "description": "Run the build command inside the container to compile the project.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "container_id": {
                            "type": "string",
                            "description": "Docker container ID.",
                        },
                        "build_dir": {
                            "type": "string",
                            "description": "Build directory path inside the container (from configure_build).",
                        },
                        "target": {
                            "type": "string",
                            "description": "Optional specific build target to compile.",
                        },
                        "jobs": {
                            "type": "integer",
                            "description": "Number of parallel jobs (defaults to CPU count).",
                        },
                    },
                    "required": ["container_id", "build_dir"],
                },
            },
            {
                "name": f"{self.server_name}.destroy_build_env",
                "description": "Stop and remove a build Docker container.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "container_id": {
                            "type": "string",
                            "description": "Docker container ID to destroy.",
                        },
                    },
                    "required": ["container_id"],
                },
            },
        ]

    # ==================================================================
    # Internal: build-system configuration dispatchers
    # ==================================================================

    def _configure_cmake(self, container_id: str, repo_path: str,
                         build_type: str, extra_args: str) -> dict:
        """Configure a CMake project."""
        build_dir_name = f"build_{build_type}"
        build_dir = f"{repo_path}/{build_dir_name}"

        build_type_flag = build_type.upper()
        if build_type in ("asan", "ubsan", "msan", "fuzzer", "coverage"):
            # These are specialized builds; use Debug with extra flags
            build_type_flag = "Debug"
            extra_args += f" -DVERIAUDIT_BUILD_MODE={build_type}"

        cmd = (
            f"cmake -B {build_dir} "
            f"-DCMAKE_BUILD_TYPE={build_type_flag} "
            f"-DCMAKE_C_COMPILER=clang "
            f"-DCMAKE_CXX_COMPILER=clang++ "
            f"-DCMAKE_EXPORT_COMPILE_COMMANDS=ON "
            f"{extra_args} "
            f"{repo_path}"
        )

        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=300
        )

        compile_commands = f"{build_dir}/compile_commands.json" if exit_code == 0 else None

        return {
            "build_dir": build_dir,
            "compile_commands_path": compile_commands,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_meson(self, container_id: str, repo_path: str,
                         build_type: str, extra_args: str) -> dict:
        """Configure a Meson project."""
        build_dir = f"{repo_path}/build_{build_type}"
        buildtype = "debug" if build_type == "debug" else "release"

        cmd = f"meson setup {build_dir} {repo_path} --buildtype={buildtype} {extra_args}"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=300
        )

        compile_commands = f"{build_dir}/compile_commands.json" if exit_code == 0 else None

        return {
            "build_dir": build_dir,
            "compile_commands_path": compile_commands,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_make(self, container_id: str, repo_path: str,
                        build_type: str, extra_args: str) -> dict:
        """Configure a Make-based project (usually just ./configure)."""
        configure_script = f"{repo_path}/configure"
        # Check if configure script exists
        check_cmd = f"test -f {configure_script} && echo 'exists' || echo 'missing'"
        _, stdout, _ = self._docker_exec(container_id, check_cmd, timeout=10)

        if "missing" in stdout:
            # No configure needed for simple Makefiles
            return {
                "build_dir": repo_path,
                "compile_commands_path": None,
                "success": True,
                "stderr": "No configure script found; treating source directory as build directory.",
            }

        flags = ""
        if build_type == "debug":
            flags = "CFLAGS='-g -O0' CXXFLAGS='-g -O0'"
        cmd = f"cd {repo_path} && {flags} ./configure {extra_args}"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=300
        )

        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_composer(self, container_id: str,
                            repo_path: str) -> dict:
        """Configure a PHP/Composer project."""
        cmd = f"cd {repo_path} && composer install --no-interaction --prefer-dist 2>&1 || true"
        self._docker_exec(container_id, cmd, timeout=300)
        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": True,
            "stderr": "",
        }

    def _configure_go(self, container_id: str,
                      repo_path: str) -> dict:
        """Configure a Go module project."""
        cmd = f"cd {repo_path} && go mod download"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=300
        )
        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_java(self, container_id: str, repo_path: str,
                        build_system: str, extra_args: str) -> dict:
        """Configure a Java project (Maven or Gradle)."""
        if build_system == "maven":
            cmd = f"cd {repo_path} && mvn compile -DskipTests {extra_args}"
        else:
            cmd = f"cd {repo_path} && gradle compileJava {extra_args}"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=600
        )
        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_cargo(self, container_id: str, repo_path: str,
                         build_type: str, extra_args: str) -> dict:
        """Configure a Rust/Cargo project."""
        release_flag = "--release" if build_type == "release" else ""
        cmd = f"cd {repo_path} && cargo fetch {extra_args}"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=300
        )
        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_javascript(self, container_id: str, repo_path: str,
                              build_system: str) -> dict:
        """Configure a JavaScript/Node project."""
        if build_system == "npm":
            cmd = f"cd {repo_path} && npm install --no-audit --no-fund"
        elif build_system == "yarn":
            cmd = f"cd {repo_path} && yarn install --frozen-lockfile"
        else:  # pnpm
            cmd = f"cd {repo_path} && pnpm install --frozen-lockfile"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=600
        )
        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_python(self, container_id: str, repo_path: str,
                          build_system: str) -> dict:
        """Configure a Python project."""
        if build_system == "poetry":
            cmd = f"cd {repo_path} && poetry install --no-interaction"
        elif build_system == "pipenv":
            cmd = f"cd {repo_path} && pipenv install --dev"
        else:
            # pip / setuptools
            cmd = f"cd {repo_path} && pip install -e '.[dev,test]' 2>&1 || pip install -r requirements.txt 2>&1 || true"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=600
        )
        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    def _configure_ruby(self, container_id: str,
                        repo_path: str) -> dict:
        """Configure a Ruby/Bundler project."""
        cmd = f"cd {repo_path} && bundle install --jobs=$(nproc)"
        exit_code, stdout, stderr = self._docker_exec(
            container_id, cmd, timeout=600
        )
        return {
            "build_dir": repo_path,
            "compile_commands_path": None,
            "success": exit_code == 0,
            "stderr": stderr[:3000],
        }

    # ==================================================================
    # Internal: Docker helpers
    # ==================================================================

    @staticmethod
    def _docker_exec(container_id: str, command: str,
                     timeout: int = 600) -> tuple:
        """Execute a shell command inside a Docker container.
        Returns (exit_code, stdout, stderr)."""
        cmd = ["docker", "exec", container_id, "sh", "-c", command]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout}s"

    @staticmethod
    def _copy_repo_to_container(container_id: str, host_repo_path: str):
        """Copy the repository from the host into the container's /workspace/repo."""
        # Ensure /workspace exists
        subprocess.run(
            ["docker", "exec", container_id, "mkdir", "-p", "/workspace"],
            capture_output=True, text=True, timeout=10,
        )
        # Remove any existing /workspace/repo
        subprocess.run(
            ["docker", "exec", container_id, "rm", "-rf", "/workspace/repo"],
            capture_output=True, text=True, timeout=10,
        )
        # Copy
        subprocess.run(
            ["docker", "cp", host_repo_path,
             f"{container_id}:/workspace/repo"],
            capture_output=True, text=True, timeout=120,
        )

    @staticmethod
    def _detect_build_system(repo_path: str) -> str:
        """Detect the build system by looking for indicator files in repo_path."""
        indicators = [
            ("CMakeLists.txt", "cmake"),
            ("meson.build", "meson"),
            ("Makefile", "make"),
            ("composer.json", "composer"),
            ("go.mod", "go_modules"),
            ("pom.xml", "maven"),
            ("build.gradle", "gradle"),
            ("build.gradle.kts", "gradle"),
            ("Cargo.toml", "cargo"),
            ("package.json", "npm"),
            ("Gemfile", "bundler"),
            ("requirements.txt", "pip"),
            ("Pipfile", "pipenv"),
            ("pyproject.toml", "poetry"),
            ("setup.py", "setuptools"),
        ]
        for filename, system in indicators:
            if os.path.isfile(os.path.join(repo_path, filename)):
                # For pyproject.toml, check if it's Poetry
                if filename == "pyproject.toml":
                    try:
                        with open(os.path.join(repo_path, filename), "r") as f:
                            content = f.read()
                        if "[tool.poetry]" in content:
                            return "poetry"
                        if "[project]" in content:
                            return "setuptools"
                    except Exception:
                        pass
                    continue
                return system

        return "unknown"

    @staticmethod
    def _find_binary_in_container(container_id: str,
                                  build_dir: str) -> Optional[str]:
        """
        Try to find a compiled binary in the container's build directory.
        """
        cmd = (
            f"find {build_dir} -maxdepth 3 -type f -executable "
            f"! -name '*.so' ! -name '*.dylib' ! -name '*.o' "
            f"! -name '*.py' ! -name '*.sh' "
            f"| head -n 5"
        )
        _, stdout, _ = BuildMCP._docker_exec(container_id, cmd, timeout=10)
        candidates = [line.strip() for line in stdout.splitlines() if line.strip()]
        return candidates[0] if candidates else None
