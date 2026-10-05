# Methodology

## Experimental factors

The default publication matrix varies two controlled factors:

- traffic regime: `benign_flash`, `independent_recon`, `coordinated_swarm`;
- population size: 10, 100, 1,000 and 10,000 virtual agents.

Each identity receives the same request budget. The publication profile uses 10 repeated trials per cell with deterministic but repeat-specific pseudo-random seeds.

## Synthetic service and ground truth

The service exposes three harmless information surfaces:

1. **V001 — sequential ticket enumeration:** valid and invalid synthetic ticket identifiers produce distinguishable service responses.
2. **V002 — permit prefix oracle:** a public two-character prefix lookup reveals synthetic aggregate counts over a finite namespace.
3. **V003 — diagnostic disclosure:** an allowed `view=diagnostic` parameter returns unnecessary synthetic backend metadata.

These are benchmark channels, not real exploits. The target contains no shell execution path and no external connectivity.

## Traffic regimes

### Benign flash crowd

Users concentrate on a small hot subset of tickets and zones and repeatedly use a small set of common permit prefixes. This creates high legitimate concurrency, collisions and locality.

### Independent reconnaissance

Agents sample each namespace independently and uniformly. They obtain broad coverage but duplicate work because there is no coordination.

### Coordinated swarm

Agents use deterministic stratified partitioning. Each identity remains low-rate, but the population covers the namespaces with minimal redundant work.

## Defender features

The v0.1 transparent detector computes:

- **novelty ratio**: unique semantic resources / total requests;
- **namespace span**: normalized min-to-max span across numeric resource families;
- **gap uniformity**: regularity of adjacent gaps in sorted observed identifiers;
- **diagnostic ratio**: fraction of allowed diagnostic requests;
- **family entropy**: normalized entropy of resource-family exploration;
- **coverage pressure**: semantic coverage relative to a fixed early-warning budget.

The fixed v0.1 risk score is

\[
R = 0.18N + 0.22S + 0.20G + 0.15D + 0.15H + 0.10C.
\]

The detector has no scenario label and no attacker-internal signal. The fixed score is a baseline, not a claim of optimality. Later work should compare graph, sequential, Bayesian and learned detectors on exactly the same raw traces.

## Collective semantic coverage

Let the synthetic observable state be \(\mathcal{S}\). Every request resolves one semantic resource key. At time \(t\),

\[
C(t)=\frac{|\cup_{i \le t}\phi(q_i)|}{|\mathcal{S}|}.
\]

The benchmark additionally records **exposure before detection**:

\[
EBD = C(t_{alarm}).
\]

A detector that alarms only after most of the service namespace has been learned is operationally weak even if its final classification is correct.

## Statistical reporting

For every scenario/population cell, run-level metrics are summarized as:

- arithmetic mean;
- sample standard deviation (Bessel correction);
- two-sided 95% confidence interval using the Student-t critical value.

The report also computes run-level AUROC and average precision using `detector_score_peak`, with `benign_flash` as the negative class and the two reconnaissance regimes as the positive class.

A future paper should additionally report effect sizes, sensitivity analysis for detector thresholds, calibration curves, ablations over each feature, and external validation on at least one independently implemented synthetic service.

## SLA evaluation

The gateway publishes telemetry on a best-effort basis and does not fail closed when telemetry storage is unavailable. Client-observed p50/p95/p99 latency, throughput and transport-error rate are reported for every cell. This makes it possible to test security separation without hiding service degradation.

## Reproducibility cautions

Container CPU scheduling and host hardware influence absolute throughput and latency. For publication, record host CPU, memory, Docker version and operating system alongside the generated manifest. Run all compared scenarios on the same host under controlled background load.

## Distributional detection (v0.2)

Version 0.2 adds a second detection dimension that is evaluated alongside the original transparent heuristic score.

For every completed run, the defender constructs the bounded collective feature vector

\[
\\mathbf{x} = [N, S, G, D, H, C],
\]

where \(N\) is novelty ratio, \(S\) namespace span, \(G\) gap uniformity, \(D\) diagnostic ratio, \(H\) family entropy, and \(C\) semantic coverage. Each bounded feature is logit-transformed before fitting.

### Benign Gaussian model

The null model is a regularized multivariate Gaussian estimated only from benign training folds:

\[
H_0: \\mathbf{x} \\sim \\mathcal{N}(\\boldsymbol{\\mu}_0, \\boldsymbol{\\Sigma}_0).
\]

A shrinkage covariance estimator is used to remain numerically stable when the number of observations is modest. The Gaussian out-of-distribution score is the squared Mahalanobis distance

\[
D_M^2(\\mathbf{x}) =
(\\mathbf{x}-\\boldsymbol{\\mu}_0)^T
\\boldsymbol{\\Sigma}_0^{-1}
(\\mathbf{x}-\\boldsymbol{\\mu}_0).
\]

### Known-attack mixture

Known reconnaissance regimes are modeled as a mixture of scenario-conditioned Gaussians:

\[
p_1(\\mathbf{x}) =
\\sum_k \\pi_k
\\mathcal{N}(\\mathbf{x};\\boldsymbol{\\mu}_k,\\boldsymbol{\\Sigma}_k).
\]

The supervised generative detector uses the log-likelihood ratio

\[
\\Lambda(\\mathbf{x}) =
\\log p_1(\\mathbf{x}) - \\log p_0(\\mathbf{x}).
\]

This separates two questions: Gaussian OOD asks whether behavior is inconsistent with known benign traffic, while Gaussian LLR asks whether it is better explained by a known reconnaissance distribution.

### Hybrid detector

The previous transparent heuristic score is retained rather than replaced. The hybrid score fuses the standardized heuristic score and standardized Gaussian LLR:

\[
R_{hybrid}
=
w z(R_{heuristic})
+
(1-w) z(\\Lambda),
\]

with \(w=0.5\) by default. Standardization parameters are estimated from benign training folds only.

### Cross-validation

Distributional results are reported with two leakage-resistant validation schemes:

- **leave-repeat-out**: one experimental repetition is held out at a time;
- **leave-scale-out**: one complete agent population size is held out at a time.

The second test is intentionally difficult: a detector trained on other swarm sizes must generalize to an unseen population scale.

For thresholded results, each training fold chooses its detector threshold from the upper benign score quantile corresponding to the configured \(\\alpha\). The default is \(\\alpha=0.01\). Thresholds are never fitted on the held-out fold.

### Gaussian assumption checks

A Gaussian model is a scientific baseline, not an assumption declared true by construction. The report therefore includes:

- per-feature Shapiro-Wilk diagnostics after transformation;
- Mardia multivariate skewness;
- Mardia multivariate kurtosis.

If these diagnostics reject normality, the Gaussian detector remains useful as an interpretable baseline, but richer density models should be compared in later experiments.

### New output artifacts

Every statistical-enabled report adds:

- `distributional_scores.csv` — out-of-fold detector scores and thresholds;
- `distributional_summary.csv` — AUROC, average precision, detection rate and FPR for each detector/validation scheme;
- `gaussian_diagnostics.json` — univariate and multivariate normality diagnostics.

This design avoids reporting an in-sample Gaussian fit as evidence of detection performance.
