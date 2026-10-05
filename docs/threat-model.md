# Threat model — v0.3

## Defender

The observer controls an isolated synthetic service boundary and receives service-side gateway telemetry: timestamp, synthetic identity header, endpoint/query-derived semantic metadata, response status/size/latency and an opaque trial stream id.

The defender does not receive scenario labels, policy seeds, attacker membership, agent memory, objectives, prompts, coordinator messages or internal model state. A mixed trial contains both attackers and benign users under one stream id. Trial boundaries are supplied by the experiment, not discovered autonomously.

Synthetic identity headers are not real authentication. They model observed client identifiers. Graph descriptors are invariant to identity renaming, but identity rotation and missing identifiers need additional experiments.

## Adversary and legitimate controls

Attackers control many individually low-budget scripted identities and send allowed GET requests to synthetic resources. Coordination is modeled by randomized stratified assignment, with variants that remove diagnostics, match approximate individual resource marginals, camouflage requests, add delays or hide a subset in benign traffic.

Benign diagnostics, broad exploration and bulk workflows are explicit hard negatives. Coordination is not proof of malicious intent; equality of complete observable distributions makes different intentions indistinguishable without additional trustworthy authorization context.

The benchmark contains no shell execution, malware delivery, credential theft or public-target scanning. Synthetic ticket, prefix and diagnostic channels measure observable information acquisition only.

## Laboratory boundary

Docker Compose uses an internal network, publishes no target ports, mounts no Docker socket or host credentials, drops capabilities and sets no-new-privileges. The runner accepts only lab gateway/detector hosts. Application containers are unprivileged.

Lab control endpoints configure/release detectors and expose telemetry completeness to the evaluator. They are internal experiment controls, not production endpoints.

## Scope

The detector is observational; it does not throttle, challenge or block clients. Measured SLA effects cannot be attributed to a mitigation policy. The per-identity baseline is a simple request-budget rule.

The study does not claim production IDS readiness, real LLM-agent execution, intent inference, full reconstructed-secret measurement, continuous production-stream segmentation or coverage of every multi-agent attack.
