# COVE: causal coverage-regularity detection

**Status:** Research candidate, not a certified intrusion detector. This
implementation adds **COVE** (Coverage-Oriented Vigilance Estimator) to the
SwarmReconGuard HTTP benchmark, plus two independently calibrated ablations.

## Scientific rationale

The transferable *hypothesis* from EARS-Info is that coordinated
information-seeking agents can partition the observation space and obtain
less redundant, unusually regular coverage. EARS-Info [1] is a multi-robot
exploration policy, **not** a cybersecurity detector, and its published
robotics performance says nothing about reconnaissance-detection accuracy.
The defense observes only gateway requests, pseudonymous identity,
resource family, resource key, request time and service response telemetry.
It never sees coordination labels, attacker membership, target secrets,
the generator policy, or future traffic.

For family \\(f\\), with key-space size \\(S_f\\) and 16 observable
resource-region bins, let \\(n_{f,b}(t)\\) be the causal count in bin
\\(b\\), \\(n_f(t)=\\sum_b n_{f,b}(t)\\), and
\\(u_f(t)\\) the distinct observed keys.

The observed **coverage regularity** statistic is

\\[
X_f^2(t)=\\sum_{b=1}^{16}
\\frac{(n_{f,b}(t)-n_f(t)/16)^2}{n_f(t)/16}.
\\]

Lower values indicate unusually even occupancy. This is **not** used as
a chi-square p-value: requests are neither necessarily IID nor uniform,
and resource key regions have unequal production popularity.

The **observed excess novelty** proxy is

\\[
G_f(t)=\\frac{u_f(t)-S_f[1-(1-1/S_f)^{n_f(t)}]}
{\\sqrt{n_f(t)}}.
\\]

The reference in the numerator is the expected number of distinct keys
under *hypothetical* IID-uniform sampling, not verified sensitive-data
leakage or ground-truth information gained.

Families with fewer than eight valid numerically mapped requests are
excluded. An empty active set receives a finite no-evidence score
\\(-1000\\), which does not create a default alarm.

The immediate score and persistent score are

\\[
q_t=-\\operatorname{mean}_f X_f^2(t)+
\\operatorname{mean}_f G_f(t),\\qquad
\\mathrm{COVE}_t=\\min(q_{t-1},q_t).
\\]

Both input windows are emitted **online**, from disjoint request windows,
while their resource histograms are cumulative. COVE therefore requires
two distinct observed scoring opportunities. Two control methods are
included: `cove_instant=q_t` and
`cove_balance=\\min(-\\overline{X^2}_{t-1},-\\overline{X^2}_t)`.
No policy labels or diagnostic flag are consulted by these scores.

## Calibration and limitations

COVE uses the same rank-based, **complete benign stream-maximum**
calibration as the existing methods. At \\(n\\) independent benign
calibration streams and desired \\(\\alpha\\), the threshold uses
rank \\(k=\\lceil(n+1)(1-\\alpha)\\rceil\\); if \\(k>n\\) the
threshold is infinite rather than pretending to offer a finite 1% cutoff.
The decision rule is `score > threshold` and one alarm per stream.

This rule controls false-alarm probability only under exchangeability
and comparable horizons between benign calibration and deployment.
It does **not** certify 1% false positives for individual workloads,
scales, shifted services, or real-world traffic. Benign explorers, search
indexing, and batch pipelines are hard negative controls.

COVE does not prove malicious intent; it cannot distinguish perfectly
matched coordinated benign exploration without additional authorization
or application-context evidence. Observed semantic coverage is only a
resource-key proxy, not actual recovered secrets.

## Evaluation

The standard Docker run automatically fits, calibrates, reports and
replays COVE alongside existing detectors, with per-scale/per-scenario
Wilson intervals and exposure measures:

```bash
git checkout main && git pull
export SWARM_COMMIT="$(git rev-parse HEAD)"
docker compose build
docker compose run --rm experiment run --suite /app/scenarios/reviewer-controls.yaml
```

To independently audit the **already archived** measured HTTP evidence
without repeating the expensive HTTP workload, place
`reviewer-evidence.zip` in the checkout root and run:

```bash
docker compose run --rm \
  -v "$PWD/reviewer-evidence.zip:/app/reviewer-evidence.zip:ro" \
  --entrypoint python experiment -m swarmguard.experiment.cove_archive \
  --archive /app/reviewer-evidence.zip --output /app/results/cove-audit
```

This verifies exact event/window boundaries against the archive, reads
only archived *benign calibration* streams to choose method thresholds,
then scores the 420 recorded tests separately. Outputs are
`results/cove-audit/cove_archive_runs.csv`,
`cove_archive_summary.csv` and `cove_archive_manifest.json`
(including source ZIP SHA-256 and count/rank).

**Crucial:** the current archive was explored during method design.
Any retrospective gains are hypothesis-generating and must be confirmed
in a prospectively frozen, independently seeded benchmark and preferably
on a second distinct API service. Compare at matched false-alarm rates,
equal event prefixes, during-stream alarms, attacker-only exposure and
both workload and population strata; do not emphasize recall alone.

## Research context

1. K. Mohsenzadegan, V. Tavakkoli, and K. Kyamakya, *EARS-Info:
   Information-Aware Event-Driven Reallocation for Multi-Robot
   Exploration*, arXiv:2610.38040, 2026.
   https://arxiv.org/abs/2610.38040
2. S. Mungari et al., *ARES: Anomaly Recognition Model for Edge Streams*,
   arXiv:2511.22078, 2025. Relevant contrasting architecture:
   learned graph embeddings plus Half-Space Trees, not implemented here.
   https://arxiv.org/abs/2511.22078
3. U. Aharon et al., *HTTP2DoS: Detecting Low-and-Slow HTTP/2 DoS
   Attacks with Complex Transfer-Entropy Graph-Temporal Learning*,
   *Computers & Security*, 2026, DOI:10.1016/j.cose.2026.105198.
   Protocol-level DoS is a different threat model; no claim that the
   benchmark reproduces its HTTP/2 features or results.

The graph-learning approaches [2,3] merit future **matched** comparison,
but introducing an untrained GNN into the present small synthetic
benchmark would add model capacity and confounding without independent
generalization evidence. The proposed baseline is deliberately simple,
fully interpretable and easy to replay.
