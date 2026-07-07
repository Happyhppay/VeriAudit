# VeriAudit - CLI
import os
import sys
from pathlib import Path
from typing import Optional

import click
import yaml

from veriaudit import __version__


def _load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from YAML file."""
    default_path = Path(__file__).parent / "config" / "default.yaml"
    path = config_path or str(default_path)
    try:
        with open(path) as f:
            config = yaml.safe_load(f)
            # Expand env vars
            for section in config.values():
                if isinstance(section, dict):
                    for k, v in section.items():
                        if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                            env_var = v[2:-1].split(":-")[0].strip()
                            default = v[2:-1].split(":-")[1].strip() if ":-" in v else ""
                            config[list(config.keys())[list(config.values()).index(section)]][k] = os.environ.get(env_var, default)
            return config
    except FileNotFoundError:
        click.echo(f"Warning: Config file not found at {path}, using defaults", err=True)
        return {}


def _build_orchestrator(config: dict):
    """Build the orchestrator with all dependencies."""
    from veriaudit.core.event_ledger import EventLedger
    from veriaudit.core.invariants import InvariantEngine
    from veriaudit.core.judge_engine import JudgeEngine
    from veriaudit.core.contradiction_detector import ContradictionDetector
    from veriaudit.core.finding_state_machine import FindingStateMachine
    from veriaudit.core.container_pool import ContainerPool
    from veriaudit.core.schema import Paths

    from veriaudit.adapters.registry import AdapterRegistry
    from veriaudit.adapters.language.cpp import CppAdapter
    from veriaudit.adapters.language.php import PhpAdapter
    from veriaudit.adapters.language.go import GoAdapter
    from veriaudit.adapters.language.java import JavaAdapter
    from veriaudit.adapters.language.python import PythonAdapter
    from veriaudit.adapters.language.javascript import JsTsAdapter
    from veriaudit.adapters.language.rust import RustAdapter
    from veriaudit.adapters.language.ruby import RubyAdapter
    from veriaudit.adapters.build.cmake import CMakeAdapter
    from veriaudit.adapters.build.composer import ComposerAdapter, GoModulesAdapter

    from veriaudit.agents.all_agents import (
        PlannerAgent, ReconAgent, StaticScanAgent, CPGTaintAgent,
        ExploitAgent, ValidationAgent, JudgeAgent,
    )
    from veriaudit.agents.orchestrator import Orchestrator

    # Core
    ledger_dir = config.get("ledger", {}).get("dir", "./workspace/ledgers")
    ledger = EventLedger(ledger_dir)
    invariants = InvariantEngine()
    judge = JudgeEngine()
    contradiction = ContradictionDetector()
    state_machine = FindingStateMachine()
    containers = ContainerPool(max_containers=config.get("docker", {}).get("max_containers", 8))

    # Adapters
    adapters = AdapterRegistry()
    # Language adapters
    for cls in [CppAdapter, PhpAdapter, GoAdapter, JavaAdapter, PythonAdapter,
                 JsTsAdapter, RustAdapter, RubyAdapter]:
        adapters.register_language(cls())
    # Build adapters
    for cls in [CMakeAdapter, ComposerAdapter, GoModulesAdapter]:
        adapters.register_build(cls())

    # LLM config
    llm_cfg = config.get("llm", {})

    # Agents
    agents = {
        "planner_agent": PlannerAgent(ledger, invariants, llm_cfg),
        "recon_agent": ReconAgent(ledger, invariants, llm_cfg),
        "static_scan_agent": StaticScanAgent(ledger, invariants, llm_cfg),
        "cpg_taint_agent": CPGTaintAgent(ledger, invariants, llm_cfg),
        "exploit_agent": ExploitAgent(ledger, invariants, llm_cfg),
        "validation_agent": ValidationAgent(ledger, invariants, llm_cfg),
        "judge_agent": JudgeAgent(ledger, invariants, llm_cfg),
    }

    orchestrator = Orchestrator(
        agents=agents,
        adapters=adapters,
        ledger=ledger,
        invariants=invariants,
        judge_engine=judge,
        contradiction_detector=contradiction,
        container_pool=containers,
        state_machine=state_machine,
        config=config,
    )

    return orchestrator


# ============================================================
# CLI Commands
# ============================================================

@click.group()
@click.version_option(version=__version__)
def cli():
    """VeriAudit — LLM-based Multi-Agent Security Audit System."""
    pass


@cli.command()
@click.argument("input_path")
@click.option("--mode", "-m", type=click.Choice(["quick", "standard", "deep"]),
              default="standard", help="Audit mode (default: standard)")
@click.option("--output-dir", "-o", default=None,
              help="Output directory for reports")
@click.option("--task-id", default=None, help="Custom task ID")
@click.option("--commit", "-c", default=None, help="Target commit SHA or tag")
@click.option("--config", "config_path", default=None, help="Path to config file")
def audit(input_path: str, mode: str, output_dir: Optional[str],
          task_id: Optional[str], commit: Optional[str],
          config_path: Optional[str]):
    """
    Run a security audit on a repository.

    INPUT_PATH: GitHub/GitLab URL or local directory path.
    """
    config = _load_config(config_path)

    from veriaudit.core.schema import AuditRequest, AuditMode

    click.echo(f"🔍 VeriAudit v{__version__}")
    click.echo(f"   Target: {input_path}")
    click.echo(f"   Mode: {mode}")

    try:
        orch = _build_orchestrator(config)

        click.echo(f"\n[1/6] Parsing repository...")
        request = AuditRequest(
            repo_url=input_path,
            commit=commit,
            mode=AuditMode(mode),
            task_id=task_id,
        )

        click.echo("[2/6] Running static analysis...")
        report = orch.audit(request)

        click.echo(f"[3/6] Verifying findings...")
        click.echo(f"[4/6] Dynamic verification... (reserved)")
        click.echo(f"[5/6] Generating report...")

        if report.status == "failed":
            click.echo(f"\n❌ Audit failed: {report.errors}", err=True)
            sys.exit(1)

        click.echo(f"[6/6] Done.\n")

        # Print summary
        click.echo("=" * 60)
        click.echo(f"  Audit Report — {report.project_url}")
        click.echo("=" * 60)
        click.echo(f"  Total raw alerts:    {report.total_raw:>6}")
        click.echo(f"  Confirmed exploited:  {report.total_confirmed:>6}")
        click.echo(f"  Rejected:             {report.total_rejected:>6}")
        click.echo(f"  False positives:      {report.total_false_positive:>6}")
        click.echo(f"  Inconclusive:         {report.total_inconclusive:>6}")
        click.echo(f"  Duration:             {report.duration_seconds:.1f}s")
        click.echo()

        for fmt, path in report.report_paths.items():
            if path:
                click.echo(f"  📄 {fmt}: {path}")

        click.echo()

    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument("task_id")
@click.option("--format", "-f", "fmt", type=click.Choice(["html", "json", "markdown"]),
              default="html", help="Report format")
@click.option("--output", "-o", default=None, help="Output path")
def report(task_id: str, fmt: str, output: Optional[str]):
    """View or export an audit report."""
    from veriaudit.core.schema import Paths

    ext_map = {"html": "report.html", "json": "findings.json", "markdown": "report.md"}
    ext = ext_map.get(fmt, "report.html")

    report_path = os.path.join(Paths.RESULTS_DIR, task_id, ext)
    if not os.path.exists(report_path):
        click.echo(f"❌ Report not found: {report_path}", err=True)
        sys.exit(1)

    if output:
        import shutil
        shutil.copy(report_path, output)
        click.echo(f"✅ Report saved to {output}")
    else:
        with open(report_path, encoding='utf-8') as f:
            click.echo(f.read()[:10000])


@cli.command()
@click.option("--limit", "-n", default=20, help="Max tasks to show")
@click.option("--status", default=None, help="Filter by status")
def list(limit: int, status: Optional[str]):
    """List recent audit tasks."""
    from veriaudit.core.schema import Paths

    results_dir = Paths.RESULTS_DIR
    if not os.path.isdir(results_dir):
        click.echo("No audit results found.")
        return

    tasks = sorted(
        [d for d in os.listdir(results_dir) if os.path.isdir(os.path.join(results_dir, d))],
        reverse=True,
    )[:limit]

    if not tasks:
        click.echo("No audit tasks found.")
        return

    click.echo(f"{'Task ID':<30} {'Date':<22} {'Report'}")
    click.echo("-" * 70)
    for t in tasks:
        task_dir = os.path.join(results_dir, t)
        report_file = os.path.join(task_dir, "report.html")
        has_report = "✅" if os.path.exists(report_file) else "⏳"
        mtime = os.path.getmtime(task_dir)
        from datetime import datetime
        date_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        click.echo(f"{t:<30} {date_str:<22} {has_report}")


@cli.command()
@click.argument("task_id_1")
@click.argument("task_id_2")
def compare(task_id_1: str, task_id_2: str):
    """Compare two audit results."""
    from veriaudit.core.schema import Paths
    import json

    results1 = os.path.join(Paths.RESULTS_DIR, task_id_1, "findings.json")
    results2 = os.path.join(Paths.RESULTS_DIR, task_id_2, "findings.json")

    if not os.path.exists(results1):
        click.echo(f"❌ Results not found for {task_id_1}", err=True)
        sys.exit(1)
    if not os.path.exists(results2):
        click.echo(f"❌ Results not found for {task_id_2}", err=True)
        sys.exit(1)

    with open(results1) as f:
        data1 = json.load(f)
    with open(results2) as f:
        data2 = json.load(f)

    f1 = len(data1.get("findings", []))
    f2 = len(data2.get("findings", []))

    click.echo(f"\n{'Metric':<30} {'Task 1':>10} {'Task 2':>10} {'Delta':>10}")
    click.echo("-" * 62)
    click.echo(f"{'Total findings':<30} {f1:>10} {f2:>10} {f2 - f1:>+10}")

    for status in ["raw", "candidate", "confirmed_exploited", "rejected", "false_positive"]:
        c1 = sum(1 for f in data1.get("findings", []) if f.get("status") == status)
        c2 = sum(1 for f in data2.get("findings", []) if f.get("status") == status)
        click.echo(f"  {status:<28} {c1:>10} {c2:>10} {c2 - c1:>+10}")


@cli.command()
@click.argument("task_id")
def verify_ledger(task_id: str):
    """Verify the Event Ledger hash chain integrity."""
    from veriaudit.core.event_ledger import EventLedger

    ledger = EventLedger()
    # Derive correlation_id from task_id
    result = ledger.verify_integrity(task_id)

    if result["valid"]:
        click.echo(f"✅ Ledger integrity verified ({result['total_events']} events)")
    else:
        click.echo(f"❌ Ledger integrity BROKEN at seq {result['first_broken_seq']}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
