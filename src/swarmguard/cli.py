from __future__ import annotations

import asyncio
import json
from pathlib import Path
import typer
import yaml
from swarmguard.experiment.policies import SCENARIOS
from swarmguard.experiment.runner import run_suite
from swarmguard.reporting.report import build_report
from swarmguard.experiment.replay import verify_replay

app = typer.Typer(name="swarmguard", no_args_is_help=True)

@app.command()
def generate(output: Path = typer.Option(...), agents: str = "10,100,1000,10000", scenarios: str = ",".join(SCENARIOS), repeats: int = 10, requests_per_agent: int = 3, concurrency: int = 256, seed: int = 20261005, alpha: float = 0.01, shrinkage: float = 0.10, hybrid_weight: float = 0.50):
    if not 0 < alpha < 1:
        raise typer.BadParameter("alpha must be in (0,1)")
    names=[x.strip() for x in scenarios.split(",") if x.strip()]
    invalid=sorted(set(names)-set(SCENARIOS))
    if invalid: raise typer.BadParameter(f"unknown scenarios: {invalid}")
    data={"name":output.stem,"agent_counts":[int(x) for x in agents.split(",")],"scenarios":names,"repeats":repeats,"requests_per_agent":requests_per_agent,"concurrency":concurrency,"arrival_window_ms":1000,"seed":seed,"baseline_identity_request_limit":20,
          "strict_telemetry":True,"save_event_traces":True,
          "detector":{"threshold":0.72,"min_events":10,"consecutive_windows":2,"evaluation_interval":100},
          "online":{"enabled":True,"window_events":64,"window_seconds":1.0,"min_window_events":8,"shrinkage":shrinkage},
          "calibration":{"training_repeats":3,"streams":max(99,int(3/alpha)),"alpha":alpha},
          "statistical":{"enabled":True,"alpha":alpha,"shrinkage":shrinkage,"hybrid_weight":hybrid_weight,"validation_modes":["leave_repeat_out","leave_scale_out","leave_attack_out"]}}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(yaml.safe_dump(data,sort_keys=False),encoding="utf-8")
    typer.echo(f"Wrote {output}")

@app.command(name="run")
def run_command(suite: Path = typer.Option(..., exists=True, readable=True), result_root: Path | None = None):
    out=asyncio.run(run_suite(suite,result_root=result_root))
    typer.echo(f"Completed. Report: {out / 'report.html'}")
    typer.echo(f"Summary: {out / 'executive_summary.md'}")
    typer.echo(f"Online comparisons: {out / 'online_summary.csv'}")

@app.command()
def report(run_dir: Path = typer.Option(..., exists=True, file_okay=False)):
    manifest=json.loads((run_dir/'manifest.json').read_text())
    runs=[json.loads(x) for x in (run_dir/'runs.jsonl').read_text().splitlines() if x.strip()]
    build_report(runs,manifest,run_dir)


@app.command()
def replay(run_dir: Path = typer.Option(..., exists=True, file_okay=False)):
    """Verify all saved online decisions from compressed raw gateway events."""
    checks = verify_replay(run_dir)
    typer.echo(f"Verified {len(checks)} run/method decisions. Results: {run_dir / 'replay_checks.csv'}")

if __name__ == '__main__':
    app()
