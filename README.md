# SwarmReconGuard

**SwarmReconGuard** is a reproducible, Docker-isolated research testbed for studying **distributed semantic reconnaissance** by large populations of individually low-risk agents.

The central research question is:

> Can a defender detect a harmful collective reconnaissance process when each individual agent stays inside an allowed or gray zone, while preserving the SLA of a high-availability service?

The lab deliberately separates the **hidden attacker side** from the **observable defender boundary**. Agents coordinate internally, while the defender sees only ordinary HTTP telemetry emitted by a gateway. No prompts, shared memory, swarm membership, or agent internals are exposed to the detector.

## Research focus

SwarmReconGuard compares three traffic regimes at matched per-agent request budgets:

1. **`benign_flash`** — legitimate high-volume users with realistic locality and repeated access patterns.
2. **`independent_recon`** — independent exploratory agents sampling the full synthetic service space.
3. **`coordinated_swarm`** — coordinated agents partition the same service space to maximize collective information gain while each identity remains low-rate.

The publication suite evaluates **10, 100, 1,000 and 10,000 virtual agents** with repeated trials and reports mean, sample standard deviation, and 95% confidence intervals.

## Safety boundary

This repository is intentionally scoped to a **synthetic service on an internal Docker network**. Runtime containers have no route to the public Internet, no host networking, no Docker socket, and no host credentials. The experiment runner refuses non-lab target hosts. The benchmark does not contain a general-purpose scanner or exploit engine.

## Architecture

```text
                hidden swarm side

  virtual agents ── optional coordination policy
         │
         │ ordinary low-rate HTTP GET requests
         ▼
 ┌───────────────────────────────────────────────┐
 │               defender boundary               │
 │                                               │
 │  gateway ──► synthetic municipal service     │
 │     │                                         │
 │     └──► Redis telemetry ──► detector         │
 │                              │                │
 │                              └──► risk state  │
 └───────────────────────────────────────────────┘
                         │
                         ▼
              experiment evaluator
                         │
                         ▼
        CSV + JSONL + self-contained HTML report, including cross-validated distributional detector comparisons
```

## Quick start

Requirements: Docker Engine with Docker Compose v2.

```bash
git clone https://github.com/vtavakkoli/swarm-recon-guard.git
cd swarm-recon-guard

# Small end-to-end validation
docker compose run --rm experiment run --suite /app/scenarios/smoke.yaml

# Pilot study
docker compose run --rm experiment run --suite /app/scenarios/pilot.yaml

# Publication matrix: 3 scenarios × 4 swarm sizes × 10 repeats
docker compose run --rm experiment run --suite /app/scenarios/publication.yaml
```

Results are written under `results/<suite>-<timestamp>/`:

```text
manifest.json
runs.jsonl
raw_metrics.csv
summary.csv
classification.json
classification_by_agents.csv
effect_sizes.csv
distributional_scores.csv
distributional_folds.csv
distributional_summary.csv
gaussian_diagnostics.json
report.html
```

Open `report.html` locally in a browser. It is self-contained and requires no external assets.

## Generate a custom scenario matrix

```bash
docker compose run --rm experiment generate \
  --output /app/results/custom-suite.yaml \
  --agents 10,100,1000,10000 \
  --scenarios benign_flash,independent_recon,coordinated_swarm \
  --repeats 10 \
  --requests-per-agent 3 \
  --concurrency 512 \
  --seed 20261005
```

Run it with:

```bash
docker compose run --rm experiment run --suite /app/results/custom-suite.yaml
```

## Core metrics

SwarmReconGuard records both service and security outcomes:

- requests, throughput, status-code distribution
- client latency p50 / p95 / p99
- unique semantic resources observed
- final collective semantic coverage
- detector peak and final risk score
- detection rate and time-to-detection
- **exposure before detection**: coverage already learned when the alarm fires
- synthetic vulnerability discovery rate
- conventional per-identity rule trigger rate
- run-level AUROC and average precision for the collective detector
- mean ± standard deviation and 95% confidence intervals over repeated trials

The detector is intentionally evaluated without access to agent internals. See [docs/methodology.md](docs/methodology.md) and [docs/threat-model.md](docs/threat-model.md).

## Reproducibility profiles

| Suite | Agents | Repeats | Purpose |
|---|---:|---:|---|
| `smoke.yaml` | 10, 30 | 3 | CI / statistical sanity check |
| `pilot.yaml` | 10, 100, 1,000 | 3 | fast local study |
| `publication.yaml` | 10, 100, 1,000, 10,000 | 10 | paper-quality repeated matrix |

`10,000 agents` means 10,000 distinct virtual identities and policy instances. They are implemented as bounded asynchronous workers inside the experiment container rather than 10,000 Docker containers. This preserves reproducibility and makes large-N experiments feasible on a workstation.

## Scientific positioning

The benchmark targets a failure mode that is easy to miss with per-agent controls:

```text
Agent_i: low rate + individually valid request  -> green / gray
Population: systematic collective coverage      -> harmful reconnaissance
```

The detector therefore estimates population-level features such as semantic novelty, namespace span, gap regularity, endpoint-family balance, diagnostic exposure and collective coverage pressure rather than relying only on requests-per-second.

## Development

```bash
make test
make smoke
```

Python 3.12 is used in Docker. Unit tests cover statistics, policies and detector feature extraction.

## Citation

If you use the framework in academic work, please cite the repository using `CITATION.cff`. A paper citation can be added once a manuscript is public.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Distributional detection

Version 0.2 adds a statistical detection layer on top of the original transparent collective-risk score.

The report now evaluates four detectors out-of-fold:

- **Heuristic** — the original interpretable collective-risk score.
- **Gaussian OOD** — squared Mahalanobis distance from the benign collective-feature distribution.
- **Gaussian LLR** — log-likelihood ratio between a benign Gaussian and a scenario-conditioned mixture of reconnaissance Gaussians.
- **Hybrid** — a configurable fusion of the original heuristic score and the Gaussian LLR.

Two validation schemes are produced automatically: `leave_repeat_out` and `leave_scale_out`. The latter tests whether a model trained on other swarm sizes generalizes to an unseen population size.

Gaussian normality is not assumed blindly. Each report writes Shapiro-Wilk feature diagnostics plus Mardia multivariate skewness and kurtosis to `gaussian_diagnostics.json`.

Example statistical configuration:

```yaml
statistical:
  enabled: true
  alpha: 0.01
  shrinkage: 0.10
  hybrid_weight: 0.50
  validation_modes: [leave_repeat_out, leave_scale_out]
```

The corresponding output files are `distributional_scores.csv`, `distributional_folds.csv`, `distributional_summary.csv`, and `gaussian_diagnostics.json`. Macro AUROC/AP are averaged across held-out folds so scores from independently fitted folds are not treated as directly calibrated probabilities.
