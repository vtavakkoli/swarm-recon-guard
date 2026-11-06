# IEEE Access reviewer-control protocol (Access-2026-51124)

These are planned reproducibility and confounding controls, NOT new observed
findings. The October 2026 manuscript reports a historical 440-run matrix;
its complete exact output archive has not been deposited in the public repository.

## Evidence and controls

1. Train a 12-feature, shrinkage-regularized one-class per-identity semantic
   detector on benign reference HTTP streams. Calibrate its stream maximum on
   independent benign reference streams. Its score uses only one identity's
   request count, endpoint distribution, semantic key positions/dispersion,
   diagnostic usage and within-identity arrival gaps. Compare with collective
   methods at run level, emphasizing matched_swarm versus benign_explorer.
2. Independently run matched_swarm_diagnostic and
   benign_explorer_diagnostic (75% per-zone diagnostic probability) as a
   diagnostic-usage control; compare the original 5%-diagnostic pair and
   independent_recon_no_diagnostic. These do not, on their own, remove all
   endpoint-key or timing generator differences.
3. Refit the online detector on training events with diagnostic fields
   removed, calibrate on held-out stripped benign reference streams, then test
   on stripped gateway events. This is a feature-ablation, not a claim to
   reconstruct HTTP responses under alternative query parameters.
4. Compare identical event prefixes (e.g. 30 and 300 events) across eligible
   population sizes. Each horizon needs its own independent benign-prefix
   threshold; exclude runs shorter than the horizon. A forced-prefix terminal
   flush is not a prospective mid-stream alarm. Report windows scored, terminal
   only alarms, and threshold/horizon sensitivity.
5. Run the separate low-concurrency reviewer-controls.yaml study and inspect
   actual service latency, throughput and errors before calling it
   "non-saturated." A 32-request concurrency limit is not proof of spare
   capacity. A second independent target service is still needed for broad
   external validity.
6. Use 95% Wilson intervals with independent *runs* as the outcome units.
   Report per-scenario and per-scale alarm outcomes, event-prefix versus
   gateway-timestamp wall exposure, full-run versus at-alarm/end coverage,
   and evaluator-only attacker coverage for mixed membership.
7. Publish the evidence ZIP with exact Git commit SHA, run configuration,
   fitted model, calibration strata, reference and test traces, per-run
   outcomes, replay checks, and each file's SHA-256. The publication numbers
   must not be updated until these controlled experiments actually run.

## Commands

From repository root, with Docker Compose and Python 3.12+:

    SWARM_COMMIT=$(git rev-parse HEAD) docker compose run --rm experiment run --suite /app/scenarios/reviewer-controls.yaml
    python scripts/validate_results.py results
    python -m swarmguard.experiment.reviewer_controls --run-dir results/reviewer-controls-<timestamp>-<id> --alpha 0.01 --prefixes 30,300 --diagnostic-ablation
    python scripts/package_evidence.py --run-dir results/reviewer-controls-<timestamp>-<id> --output results/reviewer-controls-evidence.zip

Use the actual directory returned by the run command. The same controls
can be exercised with the smaller smoke configuration at alpha=0.10,
prefixes=30; do not interpret that as a publication evaluation.

## Method definition and calibration cautions

- Score threshold comparison is strict greater-than; ties are non-alarms.
- The first window closes at the configured initial event count. Later
  windows close at the full event count or when elapsed event time exceeds
  the configured duration *and* a minimum count is reached, checked only on
  arriving events. Finalize flushes an incomplete terminal tail.
- Feature inputs are bounded to [1e-5, 1-1e-5], logit-transformed.
  Conditional regression uses log1p of window and cumulative request and
  identity counts; mixture weights are proportional to training-window counts.
  The default Gaussian covariance shrinkage is 0.15. Publication graph
  regions use 16 bins, RFF dimensions=64, MMD recent window history=8.
- For alpha=0.01 and 299 calibration streams, order statistic rank=297;
  independent complete-stream benign exchangeability is essential. Sample
  sizes do not establish per-scale or sub-1% observed false-alarm rates.
  With zero alarms, the two-sided 95% Wilson upper bounds are approximately
  2.35% for 160 runs and 8.76% for 40 runs.
- All semantic coverage percentages use 51,796 possible distinct keys.
  Alarm/end exposure substitutes final exposure for misses. The detector
  never receives evaluator membership labels.
- Source paper claims should be revised to low-budget identities rather
  than statistically benign-looking identities unless the control validates
  the latter. Any scale advantage must be qualified for event-count and
  saturation confounding.
