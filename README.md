<p align="center">
  <img src="docs/assets/swarm-recon-guard-logo.svg" alt="SwarmReconGuard" width="820">
</p>

<p align="center"><strong>Detect collective reconnaissance when individual agents remain within ordinary request budgets.</strong></p>
<p align="center">
  <a href="https://github.com/vtavakkoli/swarm-recon-guard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/vtavakkoli/swarm-recon-guard/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg">
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-3776AB.svg">
  <img alt="Version 0.3.0" src="https://img.shields.io/badge/version-0.3.0-0f766e.svg">
</p>
<p align="center"><strong>Vahid Tavakkoli · Kabeh Mohsenzadegan · Kyamakya Kyandoghere</strong></p>

## Overview

**SwarmReconGuard** is a reproducible, Docker-isolated research benchmark for collective semantic reconnaissance. Many individually low-budget identities can explore a service cooperatively while leaving its availability intact. A defender therefore needs to measure population behavior, exposure before an alarm, legitimate-workload false alarms and service quality together.

The defender observes gateway telemetry only. It receives no policy label, attacker membership, coordination messages, prompts or agent memory. Version **0.3** adds online statistical, graph, kernel and sequential methods, independent reference calibration, harder traffic controls, raw-event replay and a comprehensive offline HTML report.

This is a controlled benchmark with scripted virtual identities. It does not claim that coordination proves malicious intent, that every virtual identity is an LLM agent, or that synthetic results establish production IDS performance.

## Run the comprehensive study

Requirements: Python 3.12+ for development; Docker Engine and a current Docker Compose v2 for the isolated benchmark.

```bash
git clone https://github.com/vtavakkoli/swarm-recon-guard.git
cd swarm-recon-guard
docker compose run --rm experiment run --suite /app/scenarios/publication.yaml
```

Open the printed **results/publication-.../report.html** in a browser. It is self-contained: charts, tables and filters work without external scripts or an Internet connection. Keep the adjacent artifacts for download links and replay.

The same command fits models, calibrates every alarm policy, runs the test matrix, verifies telemetry completeness and writes the report. Compose rebuilds the application images from the current source using its build policy. Existing unchanged layers are cached.

**Publication workload:** 440 test runs and 3,666,300 test requests, plus 72 training streams and 299 independent benign calibration streams. All three phases use measured HTTP gateway telemetry. This is a substantial experiment; runtime depends on host capacity. Calibration may add several million requests. Fast profiles are available:

| Profile | Test populations | Test repeats | Calibration | Purpose |
|---|---|---:|---|---|
| smoke.yaml | 10, 40 | 3 | 24 measured streams, alpha 10% | All methods and scenarios; CI integration |
| pilot.yaml | 10, 100, 1,000 | 3 | 99 measured streams, alpha 1% | Smaller complete study |
| publication.yaml | 10, 100, 1,000, 10,000 | 10 | 299 measured streams, alpha 1% | Full repeated study |
| scale-ci.yaml | 10,000 | 1 | Policy references, alpha 10% | Capacity/integrity regression only |

```bash
docker compose run --rm experiment run --suite /app/scenarios/smoke.yaml
docker compose run --rm experiment run --suite /app/scenarios/pilot.yaml
```

On Linux with a non-1000 UID, set SWARM_UID and SWARM_GID to your user/group IDs before running so the result bind mount is writable. Containers remain unprivileged. SWARM_COMMIT can record the checkout SHA in the manifest.

## Detection methods

Every online detector scores the same non-overlapping telemetry windows. An initial 16-event window permits small swarms to be assessed before their 30-request budget ends; subsequent publication windows contain up to 64 events, with a time limit and an explicitly scored terminal tail.

| Method | Evidence | Role |
|---|---|---|
| heuristic | Novelty, namespace span, gap regularity, diagnostics, endpoint entropy, coverage pressure | Transparent window baseline |
| gaussian_ood | Mahalanobis distance from an unconditional benign Gaussian | Original distributional baseline online |
| gaussian_llr | Known-attack mixture / unconditional benign density | Supervised generative baseline |
| conditional_ood | Closest benign workload component after context regression | Multiple benign regimes and load |
| conditional_llr | Context-conditioned attack / benign mixture likelihood ratio | Load-aware supervised evidence |
| graph | Temporal identity/resource-region bipartite graph descriptors | Collective organization and complementary exploration |
| kernel_mmd | Gaussian-kernel approximation with fixed random Fourier features | Non-Gaussian distributional comparison |
| hybrid | Standardized heuristic + conditional LLR + graph evidence | Interpretable fusion |
| cusum | Sequential conditional log-likelihood accumulation | Early change detection |
| hybrid_cusum | Sequential fused evidence with drift allowance | Joint sequential detector |

Three independently calibrated component ablations remove graph, LLR or heuristic evidence from the pointwise hybrid. The legacy cumulative heuristic is retained and reported separately.

The graph detector is a statistical model of interpretable graph descriptors, not a graph neural network. It measures cross-identity reuse, resource-region balance and entropy, identity specialization, temporal namespace progression and connected-component fraction. Cumulative novelty, coverage and reuse counters preserve evidence across window boundaries. In a partitioning swarm, **unexpectedly little duplicated work** can be more informative than shared-resource overlap.

The kernel method approximates MMD over recent context residuals. It is not a claim of an exact permutation-test p-value. All models and fusion normalization are fitted on training streams; each complete alarm policy is calibrated on separate benign streams.

## Independent training, calibration and testing

1. **Training:** measured benign controls and the two known reconnaissance policies fit densities, context regression, graph models, kernel parameters and fusion normalization.
2. **Calibration:** independent benign HTTP streams set thresholds from each detector's maximum over the complete stream, including CUSUM and MMD history.
3. **Testing:** a separate seeded matrix measures performance. Its labels and attacker membership never enter prediction.

Training/calibration seeds are derived with phase-specific SHA-256 namespaces. Reference sources, seeds and windows are saved. Online test traffic is never used to select its own thresholds.

For n calibration streams, the upper rank is ceil((n + 1) * (1 - alpha)). If this exceeds n, the threshold is infinite and the report states that there is insufficient calibration resolution. Rank validity requires exchangeability and comparable monitoring horizons; a nominal 1% target does not certify production or every-scale FPR.

Completed-run Gaussian baselines also have separate **leave-repeat-out**, **leave-scale-out** and **leave-attack-policy-out** evaluation. An inner benign repetition is held out for threshold calibration and excluded from model fitting. These smaller folds are not sufficient evidence for a 1% false-alarm claim; the report makes this distinction explicit.

## Traffic controls

Every identity receives the same request budget.

| Scenario | Label | Purpose |
|---|---|---|
| benign_flash | Benign | Locality, hot resources and repetition |
| benign_diagnostic | Benign | Legitimate diagnostic access; removes a convenient exclusive attack cue |
| benign_explorer | Benign | Independent broad exploration with low diagnostic probability |
| benign_bulk | Benign | Legitimate broad, repetitive batch workflow; hard negative |
| independent_recon | Attack | Independent uniform reconnaissance; known training policy |
| coordinated_swarm | Attack | Randomized stratified partitioning; known training policy |
| swarm_no_diagnostic | Attack | Coordinated exploration without diagnostic access |
| matched_swarm | Attack | Approximately matched individual resource marginals; coordinated collective sampling |
| camouflaged_swarm | Attack | Blends hot-resource requests with coordinated exploration |
| low_and_slow_swarm | Attack | Adds seeded per-request delays |
| mixed_swarm | Attack | Hidden 20% attacker subset embedded in benign traffic |

Different resource families use independent seeded permutations and within-stratum jitter. Repeats vary actual actions, not just arrival timing. Matched marginals are a controlled approximate construction, not a proof that every complete individual joint distribution is identical.

The detector sees the whole trial stream in mixed tests. Membership is evaluator-only. Trial boundaries are supplied by the lab; segmentation of a permanently running production stream remains future work.

## What the report contains

- Online AUROC/AP, precision, F1, confusion counts, detection and false-positive rates with 95% Wilson intervals.
- Results by population, benign workload, attack policy and known/unseen policy group.
- Exposure before detection, exposure at alarm **or run end**, missed-attack counts and delay among detected attacks.
- Interactive score/threshold trajectories from predetermined repetition 0.
- Three component ablations with their own calibrated thresholds.
- Offline macro-fold metrics, effect sizes and Gaussian assumption diagnostics.
- HTTP p50/p95/p99, throughput, transport errors, matched benign SLA deltas and detector processing cost.
- Calibration resolution, horizon checks, trace completeness, host metadata, limitations and an executive summary.

Namespace coverage is a proxy for information acquisition. It is not a verified percentage of recovered secrets. Alarms are observational and do not block requests; SLA deltas measure traffic effects, not mitigation benefits.

## Artifacts and replay

| Artifact | Contents |
|---|---|
| report.html / executive_summary.md | Self-contained visual report / concise findings |
| manifest.json / integrity.json / limitations.json | Configuration, provenance, completeness and interpretation |
| online_summary.csv / online_scores.csv | Per-method aggregate / per-run online outcomes |
| online_by_scale.csv / online_by_scenario.csv | Population and workload breakdowns |
| online_generalization.csv / ablation_summary.csv | Unseen policy evaluation / component removal |
| window_traces.jsonl / event_traces.jsonl.gz | Every test window / compressed raw gateway events |
| detector_bundle.json / calibration.json | Exact fitted model / independent threshold evidence |
| reference_manifest.jsonl / reference_windows.jsonl | Disjoint reference seeds and model inputs |
| reference_events.jsonl.gz / reference_http_metrics.csv | Measured HTTP reference telemetry and service metrics |
| raw_metrics.csv / summary.csv / service_metrics.csv | Run data / repeated-cell intervals / service cost |
| distributional_*.csv / gaussian_diagnostics.json | Offline cross-validation and distribution diagnostics |
| effect_sizes.csv / classification*.json,csv | Effect sizes and legacy cumulative baseline |

Replay verifies every saved online peak score, alarm decision, request count and exposure without making HTTP requests:

```bash
docker compose run --rm experiment replay --run-dir /app/results/<experiment-folder>
docker compose run --rm experiment report --run-dir /app/results/<experiment-folder>
```

Replay writes replay_checks.csv and fails if decisions differ. Report regeneration uses the saved test outcomes, calibration and windows; it does not silently refit the online model.

## Custom studies

```bash
docker compose run --rm experiment generate \
  --output /app/results/custom-suite.yaml \
  --agents 10,100,1000,10000 --repeats 10 \
  --requests-per-agent 3 --alpha 0.01
docker compose run --rm experiment run --suite /app/results/custom-suite.yaml
```

Reference calibration defaults to HTTP. A calibration source of policy explicitly selects simulated semantic metadata for faster development. The report records this choice and does not present simulated references as measured service traffic.

## Safety and implementation

The target is a synthetic municipal-style API with ticket enumeration, a prefix-count oracle and diagnostic disclosure. It has no shell execution path or real secrets. The Docker network is internal, no target port is published, capabilities are dropped and arbitrary gateway/detector hosts are rejected.

Ten thousand agents means ten thousand virtual identities executed by bounded asynchronous workers, not ten thousand containers. Identity headers are lab signals, not an implemented authentication mechanism. The per-identity baseline is a run-budget count rule, not a comprehensive production rate limiter.

See [Threat model](docs/threat-model.md), [Methodology](docs/methodology.md) and [SECURITY.md](SECURITY.md).

## Development

```bash
python -m pip install -e '.[dev]'
pytest
```

CI runs regression tests, every method/scenario in Docker, raw-event replay and a 10,000-identity capacity test. It uploads result artifacts for inspection.

The methods build on [Page's sequential inspection work](https://doi.org/10.1093/biomet/41.1-2.100), [kernel two-sample testing](https://jmlr.org/papers/v13/gretton12a.html), and [temporal multiplex coordination research](https://doi.org/10.1609/icwsm.v20i1.42682). Their adaptation to this benchmark is an experimentally testable proposal.

## Authors, citation and license

**Vahid Tavakkoli · Kabeh Mohsenzadegan · Kyamakya Kyandoghere**

Use [CITATION.cff](CITATION.cff) for software attribution. Licensed under [Apache-2.0](LICENSE).
