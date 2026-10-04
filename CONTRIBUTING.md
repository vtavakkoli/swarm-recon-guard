# Contributing

Contributions should preserve the benchmark's core safety and reproducibility properties:

- no arbitrary Internet targets;
- no host networking or Docker socket mounts;
- deterministic seeds for benchmark policies;
- explicit ground truth for every synthetic vulnerability;
- separation between attacker-internal state and defender-visible telemetry;
- tests for new metrics and scenario logic.

Run `make test` before opening a pull request.
