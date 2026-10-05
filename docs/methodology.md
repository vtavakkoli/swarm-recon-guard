# Methodology — SwarmReconGuard v0.3

## Estimands and observation boundary

The experiment asks whether population-level evidence can reveal collective reconnaissance when individual request budgets are ordinary. Classification labels describe controlled policies; they are not directly observable intent.

The defender receives timestamp, synthetic identity, resource family/key, numeric key, diagnostic flag, HTTP response metadata and an opaque trial stream id. It does not receive the scenario, attacker subset, policy seed or coordination state. Trial boundaries remain a supplied experimental condition.

Four benign controls and seven attack regimes are evaluated at 10, 100, 1,000 and 10,000 identities with ten repetitions, totaling 440 test runs. Each identity makes three requests. Execution order within each population/repetition is independently shuffled to reduce order effects.

Matched workload comparisons use the same population and repetition. Absolute latency and throughput depend on host hardware, container scheduling and background activity.

## Reference phases and leakage prevention

Publication training and calibration are separately measured HTTP traffic on the same service. Training uses three reference repetitions of four benign and two known-attack policies at every configured population: 72 streams. Calibration uses 299 independently selected benign streams. SHA-256 phase namespaces derive distinct seeds for every reference stream. Test seed/repetition tuples are not used for fitting.

Models, kernel bandwidth/features and fusion normalization use training windows only. Calibration contains benign traffic only. The trained detector bundle is installed before test traffic begins and stays fixed during the matrix.

The alternative policy reference source is explicitly simulated: it creates semantic metadata from scripted actions and arrival policies without HTTP measurements. scale-ci.yaml uses this to shorten a capacity check. Reference provenance is saved in calibration.json and the report.

Raw reference events, reference windows and phase manifests are saved. Report regeneration consumes saved test outcomes and does not refit the online model.

## Windows and graph descriptors

Windows do not overlap or reuse events. The first publication window contains 16 events. Subsequent windows close after 64 events or after at least eight events and one second of event time. Final partial windows are scored explicitly; no events are discarded. Request count and observed identity count enter the conditional model, including short tails.

Six original bounded features describe window novelty, namespace extent, identifier-gap regularity, diagnostic ratio, family entropy and namespace coverage. The transparent score uses:

`R = .18 novelty + .22 span + .20 gaps + .15 diagnostics + .15 entropy + .10 coverage_pressure`.

The legacy cumulative detector retains its fixed 0.72 threshold and two-evaluation requirement. Its evaluation interval is shortened for small request budgets so a 30-request run can actually complete two evaluations.

The graph is a timestamped bipartite multigraph connecting observed identities with one of 16 normalized regions per resource family. Its descriptors are:

- **Cross-identity novelty:** one minus the fraction of requests repeating a resource already requested by another identity.
- **Region balance:** average inverse coefficient-of-variation measure across the region counts of each family.
- **Region entropy:** average Shannon entropy over the 16 regions, normalized by log(16).
- **Identity specialization:** average one minus the normalized resource-family entropy per identity.
- **Temporal progression:** average absolute time/resource-position correlation for eligible families.
- **Component fraction:** fraction of observed identity nodes in the largest identity/resource-region connected component.

Cumulative cross-identity novelty and region balance track complementary work across window boundaries with constant-time per-event counters. Conditional semantic models also include cumulative novelty and coverage. The original unconditional Gaussian baselines retain the six window features for comparison.

No descriptor relies on the spelling or sort order of identity labels. Graph extraction is linear in window edges apart from bounded-window numeric operations; it avoids an all-pairs identity matrix. The graph anomaly score is conditional Mahalanobis distance on these descriptors, not a GNN.

Reduced duplication can reflect cooperative partitioning. Broad legitimate workflows can also do this, so benign_bulk and benign_explorer are necessary hard controls. Complete equality of observable joint distributions would make different intentions unidentifiable to this observer.

## Density models and observable context

Bounded features are clipped to [1e-5, 1 - 1e-5] and logit transformed. Gaussian covariances shrink toward a scaled identity matrix with a ridge term. Shrinkage improves numerical stability; it does not prove the true distribution Gaussian.

The unconditional OOD baseline fits one benign Gaussian. The unconditional LLR uses a scenario-grouped known-attack Gaussian mixture against it.

Conditional benign and attack models fit separate reference-workload components. Each component regresses transformed features on:

`c = [1, log(1+window_requests), log(1+window_identities), log(1+cumulative_requests), log(1+cumulative_identities)]`.

Residuals receive a regularized Gaussian model. At prediction, densities mix all components; the observed test scenario is not used to select a component. Conditional OOD uses the closest benign component's residual distance. Conditional LLR is log attack density minus log benign density.

Component weights follow the training-window counts, which means long reference streams contribute more windows. Reported calibration and per-workload false alarms are essential checks on this modeling choice.

## Kernel comparison, fusion and sequential alarms

kernel_mmd uses a Gaussian kernel approximated with fixed random Fourier features. The bandwidth comes from training residual distances, with a bounded reference sample of 512 windows. The statistic compares the mean embedding of recent observed context residuals with the training benign reference mean. Up to eight recent windows contribute. It is a nonparametric comparison baseline, not an exact unbiased finite-sample MMD or permutation p-value.

The pointwise hybrid equally combines benign-training-standardized heuristic, conditional LLR and graph scores. Each leave-one-component-out ablation receives its own calibrated threshold.

CUSUM accumulates the conditional log-likelihood ratio:

`S_t = max(0, S_(t-1) + log p_A(x_t | c_t) - log p_B(x_t | c_t))`.

Hybrid CUSUM instead accumulates fused standardized evidence minus a configured drift allowance (0.5). It is a score-based sequential comparator, not an exact likelihood ratio.

History and sequential state reset at the start of each trial stream. The detector evaluates all identities in that stream, including benign background in mixed_swarm. It never resets per true attacker group.

## Calibration unit and false-alarm target

For every detector, the calibration score is its maximum over the **whole benign stream**, including sequential state and MMD history. This calibrates a one-alarm-per-stream policy rather than treating each repeated window test as an independent 1% test.

For n independent benign streams and target alpha, take ordered maximum score at rank ceil((n + 1)(1 - alpha)), with strict greater-than alarms. If the rank exceeds n, thresholds are infinite and the report flags insufficient resolution. Infinite thresholds are serialized as null, not invalid JSON infinities.

The rank argument requires exchangeable calibration/test benign streams and a comparable horizon. Mixed population sizes, workload shifts, changing service behavior or longer monitoring periods can violate the assumptions. Nominal 1% is an experimental target; measured FPR with Wilson intervals is reported overall and by workload/population. There is no claimed distribution-free conditional guarantee for every scale or production site.

## Policy variation and hard controls

Coordinated actions use independent seeded resource-family permutations plus within-stratum jitter. This changes both actions and arrival schedules between repeats and avoids a convenient shared identity/resource rank.

matched_swarm and benign_explorer use approximately uniform individual resource marginals and the same low diagnostic probability. Collective sampling is stratified for the swarm and independent for the benign control. This is an approximate marginal matching design; no claim is made that every complete individual joint distribution is equal.

swarm_no_diagnostic removes diagnostic access. benign_diagnostic gives legitimate clients access to that channel. camouflaged_swarm mixes hot requests with stratified choices. low_and_slow_swarm adds seeded inter-request delays. mixed_swarm hides a seeded 20% attacker subset inside benign traffic without exposing special attacker identities to the detector.

The three synthetic information channels are ticket-existence/status enumeration, a permit-prefix count oracle and unnecessary zone diagnostic metadata. Cooperative discovery is evaluated on pooled attacker observations; independent discovery uses individual findings. Population-wide findings and received byte counts are separately recorded. These labels measure the synthetic benchmark, not host exploitation.

## Outcome metrics and missed detections

- Detection and benign false alarms are binary complete-run outcomes.
- AUROC and AP use per-run peak detector scores from the fixed online model.
- EBD is namespace coverage at the first alarm window.
- Exposure at alarm **or end** uses final coverage for missed attacks, so missed runs cannot disappear from exposure summaries.
- Detection delay is gateway-event elapsed time to the first alarm window. Misses are censored and counted; their delay is not replaced with zero.
- Request count at alarm, precision, F1, confusion counts and known/unseen policy breakdowns supplement AUROC.
- HTTP latency/throughput, transport errors, telemetry failures and detector CPU time per event describe operational cost.

Namespace coverage counts unique observed resource keys over the known synthetic namespace. It is a proxy, not verified secret-state reconstruction. Delays exclude deployment action latency and the observational detector does not block requests. A low exposure number at small scale must be interpreted alongside miss counts.

Repeated cells report sample SD and Student-t intervals. Detection/FPR proportions use Wilson intervals. Precision/AP depend on the controlled class balance. Run-level independence is an experimental assumption; host/shared-service effects may reduce effective independence.

## Offline cross-validation

Completed-run Gaussian baselines use leave-repeat-out, leave-scale-out and leave-attack-policy-out folds. Inside each outer training set, one benign repetition is reserved for calibration and excluded from fitting and fusion normalization.

Leave-attack-policy-out holds out one attack regime and one benign test repetition; it never tests benign instances used in fitting. The remaining attack policies form the training attack mixture.

Fold scores from separately fitted models need not share a numeric scale. Macro-fold AUROC/AP are therefore primary; pooled metrics are retained as descriptive output. Offline folds use empirical upper calibration quantiles and record calibration resolution. They are smaller than the 299-stream online calibration and do not substantiate a 1% operating-point guarantee.

Gaussian diagnostics pool benign workloads and scales. Normality rejection may reflect this mixture, not a universal property of traffic. Constant features are flagged. Classical Mardia p-values assume independent observations and nonsingular covariance; ridge-stabilized, heterogeneous small samples require cautious interpretation.

## Integrity and replay

Every HTTP run checks expected request count, gateway telemetry failures, detector consumption and transport errors. Strict profiles fail rather than classify incomplete traces as successful measurements. Failed suites preserve an incomplete manifest and partial data.

Compressed raw gateway traces preserve the original Redis stream order. Replay loads the saved detector bundle and window configuration, resets state at each opaque run boundary and verifies peak scores, alarms, request counts and exposure against the recorded online results. Data can be streamed one run at a time.

The HTML report contains predetermined repetition-0 curves, downsampled only for display. It retains links to every full trace and CSV. No representative run is selected based on favorable performance.

## Remaining limits

One synthetic service, scripted policies and supplied trial boundaries do not provide external validity. Production authentication, adaptive learned attackers, multiple independently implemented services, continuous-stream segmentation, authenticated authorization context and active mitigation remain future experiments.
