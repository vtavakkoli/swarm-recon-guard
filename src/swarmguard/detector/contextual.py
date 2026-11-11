"""Reference-trained, diagnostic-independent context-aware coordination score.

A deliberately low-capacity supervised comparator using ONLY gateway-observable
features: resource-region discrepancy, distinct-key novelty, event horizon and
participating identities. Class labels are used to fit the reference model but
never passed to the online scorer. No tuning on HTTP test traces is permitted.

The one-alarm-per-stream operating point is calibrated independently in
DetectorBundle.calibrate using HELD-OUT benign whole-stream maxima.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit

FEATURES = (
    "information_balance_chi2",
    "information_excess_gain",
    "cumulative_requests",
    "cumulative_identities",
)
REGULARIZATION = 0.02


def feature_vector(row: dict) -> np.ndarray:
    """No diagnostic flag, scenario, identity string, or future state."""
    raw = np.asarray([float(row[key]) for key in FEATURES], dtype=float)
    if not np.all(np.isfinite(raw)) or raw[0] < 0 or raw[2] < 0 or raw[3] < 0:
        raise ValueError("non-finite or negative contextual coordination count")
    vector = np.asarray((
        np.log1p(raw[0]),
        raw[1],
        np.log1p(raw[2]),
        np.log1p(raw[3]),
    ), dtype=float)
    if not np.all(np.isfinite(vector)):
        raise ValueError("non-finite contextual feature transform")
    return vector


@dataclass
class ContextualCoordination:
    mean: np.ndarray
    scale: np.ndarray
    weights: np.ndarray
    bias: float
    regularization: float = REGULARIZATION

    @classmethod
    def fit(cls, streams: list[list[dict]], regularization: float = REGULARIZATION) -> "ContextualCoordination":
        if regularization <= 0:
            raise ValueError("regularization must be strictly positive")
        labels: list[int] = []
        values: list[np.ndarray] = []
        weights: list[float] = []
        positive = sum(bool(stream and int(stream[0]["label"]) == 1) for stream in streams)
        negative = sum(bool(stream and int(stream[0]["label"]) == 0) for stream in streams)
        if min(positive, negative) < 2:
            raise ValueError("COVE contextual training needs at least two independent streams per class")
        for stream in streams:
            if not stream:
                raise ValueError("training streams must not be empty")
            label = int(stream[0]["label"])
            if label not in (0, 1) or any(int(row["label"]) != label for row in stream):
                raise ValueError("mixed or invalid training stream labels")
            # Each independent stream gets equal mass within its class.
            per_window = 0.5 / ((positive if label else negative) * len(stream))
            for row in stream:
                labels.append(label)
                values.append(feature_vector(row))
                weights.append(per_window)
        x = np.vstack(values)
        y = np.asarray(labels, dtype=float)
        masses = np.asarray(weights, dtype=float)
        if not np.isclose(masses.sum(), 1.0):
            raise ValueError("invalid training weights")
        mean = np.average(x, axis=0, weights=masses)
        scale = np.sqrt(np.average((x - mean) ** 2, axis=0, weights=masses))
        scale = np.maximum(scale, 1e-5)
        z = (x - mean) / scale

        def objective(coefficients: np.ndarray):
            linear = z @ coefficients[:-1] + coefficients[-1]
            loss = float(np.dot(masses, np.logaddexp(0.0, linear) - y * linear)
                         + 0.5 * regularization * np.dot(coefficients[:-1], coefficients[:-1]))
            gradient = masses * (expit(linear) - y)
            derivative = np.r_[
                z.T @ gradient + regularization * coefficients[:-1],
                gradient.sum(),
            ]
            return loss, derivative

        optimized = minimize(
            objective, np.zeros(x.shape[1] + 1), jac=True,
            method="L-BFGS-B", options={"maxiter": 800, "ftol": 1e-12},
        )
        if not optimized.success or not np.all(np.isfinite(optimized.x)):
            raise RuntimeError(f"Reference-only contextual model failed to converge: {optimized.message}")
        return cls(mean=mean, scale=scale, weights=optimized.x[:-1],
                   bias=float(optimized.x[-1]), regularization=regularization)

    def score(self, row: dict) -> float:
        x = (feature_vector(row) - self.mean) / self.scale
        return float(x @ self.weights + self.bias)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "features": list(FEATURES),
            "mean": self.mean.tolist(),
            "scale": self.scale.tolist(),
            "weights": self.weights.tolist(),
            "bias": self.bias,
            "regularization": self.regularization,
            "training_scope": "reference windows only; equal independent stream mass per class",
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ContextualCoordination":
        if data.get("schema_version") != 1 or tuple(data.get("features", ())) != FEATURES:
            raise ValueError("invalid contextual detector version/features")
        arrays = [np.asarray(data[k], dtype=float) for k in ("mean", "scale", "weights")]
        if any(a.shape != (len(FEATURES),) or not np.all(np.isfinite(a)) for a in arrays):
            raise ValueError("invalid contextual model shapes or values")
        if np.any(arrays[1] <= 0) or not np.isfinite(float(data["bias"])):
            raise ValueError("invalid contextual model scale or bias")
        return cls(*arrays, float(data["bias"]), float(data["regularization"]))
