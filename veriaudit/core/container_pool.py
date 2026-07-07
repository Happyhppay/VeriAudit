# VeriAudit - Container Pool
# Docker container lifecycle management for isolated build/run environments.
from __future__ import annotations

import subprocess
import time
import threading
from typing import Dict, Optional


class ContainerPool:
    """
    Manages a pool of Docker containers for isolated build and execution.
    Supports multiple container types (cpp-fuzz, php-web, java, go, python, generic).
    """

    def __init__(self, max_containers: int = 8):
        self._max = max_containers
        self._containers: Dict[str, dict] = {}  # container_id -> {image, status, type}
        self._lock = threading.Lock()

    @property
    def active_count(self) -> int:
        return len([c for c in self._containers.values()
                     if c["status"] == "running"])

    def create(self, image: str, name: str | None = None,
               volumes: dict | None = None,
               environment: dict | None = None,
               network: str = "bridge") -> str:
        """
        Create and start a Docker container.
        Returns container_id.
        """
        with self._lock:
            if self.active_count >= self._max:
                raise RuntimeError(f"Container pool exhausted (max={self._max})")

        cmd = ["docker", "run", "-d", "--rm"]
        if name:
            cmd.extend(["--name", name])
        if volumes:
            for host_path, container_path in volumes.items():
                cmd.extend(["-v", f"{host_path}:{container_path}"])
        if environment:
            for k, v in environment.items():
                cmd.extend(["-e", f"{k}={v}"])
        if network:
            cmd.extend(["--network", network])

        cmd.append(image)
        cmd.append("sleep infinity")  # Keep container alive

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to create container: {result.stderr.strip()}")

            container_id = result.stdout.strip()[:12]

            with self._lock:
                self._containers[container_id] = {
                    "image": image,
                    "status": "running",
                    "name": name or "",
                    "created_at": time.time(),
                }

            return container_id
        except subprocess.TimeoutExpired:
            raise RuntimeError("Docker container creation timed out")

    def exec_cmd(self, container_id: str, command: str | list[str],
                 timeout: int = 600, workdir: str | None = None) -> tuple[int, str, str]:
        """
        Execute a command inside a container.
        Returns (exit_code, stdout, stderr).
        """
        if isinstance(command, str):
            cmd = ["docker", "exec", container_id, "sh", "-c", command]
        else:
            cmd = ["docker", "exec", container_id] + command

        if workdir:
            cmd = cmd[:3] + ["-w", workdir] + cmd[3:]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout}s"

    def exec_cmd_detached(self, container_id: str,
                           command: str | list[str]) -> str:
        """Execute a command detached, return immediately."""
        if isinstance(command, str):
            cmd = ["docker", "exec", "-d", container_id, "sh", "-c", command]
        else:
            cmd = ["docker", "exec", "-d", container_id] + command

        subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return container_id

    def copy_to(self, container_id: str, host_path: str,
                container_path: str) -> bool:
        """Copy a file/directory into the container."""
        cmd = ["docker", "cp", host_path, f"{container_id}:{container_path}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0

    def copy_from(self, container_id: str, container_path: str,
                  host_path: str) -> bool:
        """Copy a file/directory from the container."""
        cmd = ["docker", "cp", f"{container_id}:{container_path}", host_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0

    def is_running(self, container_id: str) -> bool:
        """Check if a container is still running."""
        with self._lock:
            if container_id not in self._containers:
                return False
        cmd = ["docker", "inspect", "-f", "{{.State.Running}}", container_id]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.stdout.strip() == "true"

    def stop(self, container_id: str):
        """Stop and remove a container."""
        with self._lock:
            self._containers.pop(container_id, None)
        subprocess.run(["docker", "stop", container_id],
                        capture_output=True, text=True, timeout=15)
        subprocess.run(["docker", "rm", "-f", container_id],
                        capture_output=True, text=True, timeout=5)

    def stop_all(self):
        """Stop all managed containers."""
        with self._lock:
            ids = list(self._containers.keys())
        for cid in ids:
            self.stop(cid)

    def get_container(self, container_id: str) -> Optional[dict]:
        with self._lock:
            return self._containers.get(container_id)
