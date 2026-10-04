# Threat model

## Defender knowledge

The defender controls the synthetic service boundary and observes only gateway telemetry: timestamp, authenticated synthetic identity, endpoint, query shape, status code, response size, latency, semantic resource family/key and whether an allowed diagnostic view was requested.

The defender does **not** observe agent prompts, local memory, decision policy, inter-agent messages, coordinator state, model activations or true swarm membership.

## Adversary

The adversary controls many low-rate virtual identities. Every request uses an allowed HTTP GET operation against the synthetic service. No request performs command execution, malware delivery or host exploitation. The coordinated scenario partitions the observable namespace to reduce duplicate work and increase collective information gain.

## Safety boundary

The benchmark is valid only inside its Docker network. The experiment runner validates the configured gateway hostname and refuses arbitrary external targets. Docker Compose declares the lab network `internal: true`, exposes no target ports to the host, drops Linux capabilities and does not mount the Docker socket.

## Non-goals

SwarmReconGuard v0.1 does not claim to model every multi-agent attack, infer human intent, detect covert channels, or provide a production-ready IDS. It is a controlled testbed for one sharply defined question: collective semantic reconnaissance from individually low-risk actions.
