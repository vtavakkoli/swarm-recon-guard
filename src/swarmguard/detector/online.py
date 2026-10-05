from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np
from scipy.special import logsumexp

from swarmguard.detector.windows import BASE_FEATURES, EXTENDED_FEATURES, GRAPH_FEATURES, context_vector
from swarmguard.reporting.distributional import GaussianModel

METHODS = ("heuristic", "gaussian_ood", "gaussian_llr", "conditional_ood",
           "conditional_llr", "graph", "kernel_mmd", "hybrid", "cusum", "hybrid_cusum")
ABLATIONS = ("hybrid_no_graph", "hybrid_no_llr", "hybrid_no_heuristic")
ALL_METHODS = METHODS + ABLATIONS


def feature_matrix(rows: list[dict], features: tuple[str, ...]) -> np.ndarray:
    values = np.asarray([[float(row[name]) for name in features] for row in rows])
    values = np.clip(values, 1e-5, 1.0 - 1e-5)
    return np.log(values / (1.0 - values))


def gaussian_dict(model: GaussianModel) -> dict:
    return {name: getattr(model, name).tolist() for name in ("mean", "covariance", "precision")} | {"logdet": model.logdet}


def gaussian_from(data: dict) -> GaussianModel:
    return GaussianModel(*(np.asarray(data[name], dtype=float) for name in ("mean", "covariance", "precision")), float(data["logdet"]))


@dataclass
class ConditionalMixture:
    features: tuple[str, ...]
    coefficients: list[np.ndarray]
    models: list[GaussianModel]
    weights: np.ndarray

    @classmethod
    def fit(cls, rows: list[dict], features: tuple[str, ...], *, conditional: bool = True,
            shrinkage: float = 0.15) -> "ConditionalMixture":
        groups: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            groups[str(row["scenario"])].append(row)
        coefficients, models, counts = [], [], []
        for group in groups.values():
            if len(group) < 2:
                continue
            x = feature_matrix(group, features)
            c = np.vstack([context_vector(row) for row in group])
            if not conditional:
                c[:, 1:] = 0
            penalty = np.eye(c.shape[1]) * 1e-3
            penalty[0, 0] = 0
            coefficient = np.linalg.pinv(c.T @ c + penalty) @ c.T @ x
            coefficients.append(coefficient)
            models.append(GaussianModel.fit(x - c @ coefficient, shrinkage=shrinkage))
            counts.append(len(group))
        if not models:
            raise ValueError("density fitting needs at least two windows in one training regime")
        weights = np.asarray(counts, dtype=float)
        weights /= weights.sum()
        return cls(features, coefficients, models, weights)

    def component_scores(self, row: dict) -> tuple[np.ndarray, np.ndarray]:
        x = feature_matrix([row], self.features)
        c = context_vector(row)
        residuals = [x - c @ coef for coef in self.coefficients]
        ll = np.asarray([model.logpdf(residual)[0] for model, residual in zip(self.models, residuals)])
        distances = np.asarray([model.mahalanobis_sq(residual)[0] for model, residual in zip(self.models, residuals)])
        return ll, distances

    def logpdf(self, row: dict) -> float:
        ll, _ = self.component_scores(row)
        return float(logsumexp(ll + np.log(self.weights)))

    def ood(self, row: dict) -> float:
        return float(np.min(self.component_scores(row)[1]))

    def residual(self, row: dict) -> np.ndarray:
        ll, _ = self.component_scores(row)
        idx = int(np.argmax(ll + np.log(self.weights)))
        model = self.models[idx]
        residual = feature_matrix([row], self.features)[0] - context_vector(row) @ self.coefficients[idx] - model.mean
        return residual / np.sqrt(np.maximum(np.diag(model.covariance), 1e-6))

    def to_dict(self) -> dict:
        return {"features": list(self.features), "coefficients": [c.tolist() for c in self.coefficients],
                "models": [gaussian_dict(m) for m in self.models], "weights": self.weights.tolist()}

    @classmethod
    def from_dict(cls, data: dict) -> "ConditionalMixture":
        return cls(tuple(data["features"]), [np.asarray(c) for c in data["coefficients"]],
                   [gaussian_from(m) for m in data["models"]], np.asarray(data["weights"]))


@dataclass
class DetectorBundle:
    benign: GaussianModel
    attack: ConditionalMixture
    conditional_benign: ConditionalMixture
    conditional_attack: ConditionalMixture
    graph_benign: ConditionalMixture
    normalization: dict[str, tuple[float, float]]
    rff_weights: np.ndarray
    rff_phase: np.ndarray
    rff_reference: np.ndarray
    thresholds: dict[str, float] = field(default_factory=dict)
    mmd_history: int = 8
    cusum_drift: float = 0.5

    @classmethod
    def fit(cls, training_streams: list[list[dict]], *, seed: int = 42,
            shrinkage: float = 0.15, rff_dimensions: int = 64,
            mmd_history: int = 8, cusum_drift: float = 0.5) -> "DetectorBundle":
        rows = [row for stream in training_streams for row in stream]
        benign = [row for row in rows if int(row["label"]) == 0]
        attack = [row for row in rows if int(row["label"]) == 1]
        if len(benign) < 3 or len(attack) < 3:
            raise ValueError("online model needs benign and known-attack training windows")
        if rff_dimensions < 8 or mmd_history < 1 or cusum_drift < 0:
            raise ValueError("invalid random-feature or CUSUM configuration")
        conditional_benign = ConditionalMixture.fit(benign, EXTENDED_FEATURES, shrinkage=shrinkage)
        conditional_attack = ConditionalMixture.fit(attack, EXTENDED_FEATURES, shrinkage=shrinkage)
        graph_benign = ConditionalMixture.fit(benign, GRAPH_FEATURES, shrinkage=shrinkage)
        base_benign = GaussianModel.fit(feature_matrix(benign, BASE_FEATURES), shrinkage=shrinkage)
        base_attack = ConditionalMixture.fit(attack, BASE_FEATURES, conditional=False, shrinkage=shrinkage)
        raw = {
            "heuristic": np.asarray([row["risk_score"] for row in benign], dtype=float),
            "conditional_llr": np.asarray([conditional_attack.logpdf(row) - conditional_benign.logpdf(row) for row in benign]),
            "graph": np.asarray([graph_benign.ood(row) for row in benign]),
        }
        normalization = {name: (float(values.mean()), max(1e-6, float(values.std(ddof=1)))) for name, values in raw.items()}
        rng = np.random.default_rng(seed)
        sample = benign if len(benign) <= 512 else [benign[i] for i in rng.choice(len(benign), 512, replace=False)]
        residuals = np.vstack([conditional_benign.residual(row) for row in sample])
        distance = np.linalg.norm(residuals[:, None, :] - residuals[None, :, :], axis=-1)
        positive = distance[distance > 0]
        bandwidth = max(0.1, float(np.median(positive)) if positive.size else 1.0)
        weights = rng.normal(size=(len(EXTENDED_FEATURES), rff_dimensions)) / bandwidth
        phase = rng.uniform(0, 2 * math.pi, rff_dimensions)
        embedded = math.sqrt(2 / rff_dimensions) * np.cos(residuals @ weights + phase)
        return cls(base_benign, base_attack, conditional_benign, conditional_attack, graph_benign,
                   normalization, weights, phase, embedded.mean(axis=0),
                   mmd_history=mmd_history, cusum_drift=cusum_drift)

    def z(self, name: str, value: float) -> float:
        mu, std = self.normalization[name]
        return (value - mu) / std

    def score(self, row: dict, state: dict) -> dict[str, float]:
        x = feature_matrix([row], BASE_FEATURES)
        llr = self.conditional_attack.logpdf(row) - self.conditional_benign.logpdf(row)
        graph = self.graph_benign.ood(row)
        heuristic = float(row["risk_score"])
        hybrid = (self.z("heuristic", heuristic) + self.z("conditional_llr", llr) + self.z("graph", graph)) / 3
        residual = self.conditional_benign.residual(row)
        phi = math.sqrt(2 / len(self.rff_phase)) * np.cos(residual @ self.rff_weights + self.rff_phase)
        history = state.setdefault("mmd", deque(maxlen=self.mmd_history))
        history.append(phi)
        mmd = float(np.sum((np.mean(history, axis=0) - self.rff_reference) ** 2))
        state["cusum"] = max(0.0, state.get("cusum", 0.0) + llr)
        state["hybrid_cusum"] = max(0.0, state.get("hybrid_cusum", 0.0) + hybrid - self.cusum_drift)
        return {
            "heuristic": heuristic,
            "gaussian_ood": float(self.benign.mahalanobis_sq(x)[0]),
            "gaussian_llr": self.attack.logpdf(row) - float(self.benign.logpdf(x)[0]),
            "conditional_ood": self.conditional_benign.ood(row),
            "conditional_llr": llr, "graph": graph, "kernel_mmd": mmd, "hybrid": hybrid,
            "cusum": state["cusum"], "hybrid_cusum": state["hybrid_cusum"],
            "hybrid_no_graph": (self.z("heuristic", heuristic) + self.z("conditional_llr", llr)) / 2,
            "hybrid_no_llr": (self.z("heuristic", heuristic) + self.z("graph", graph)) / 2,
            "hybrid_no_heuristic": (self.z("conditional_llr", llr) + self.z("graph", graph)) / 2,
        }

    def calibrate(self, streams: list[list[dict]], alpha: float) -> dict:
        if not 0 < alpha < 1 or not streams:
            raise ValueError("calibration requires independent benign streams and 0 < alpha < 1")
        maxima = {name: [] for name in ALL_METHODS}
        for stream in streams:
            if not stream or any(int(row["label"]) != 0 for row in stream):
                raise ValueError("calibration streams must be nonempty and benign")
            state: dict = {}
            peak = {name: -math.inf for name in ALL_METHODS}
            for row in stream:
                for name, value in self.score(row, state).items():
                    peak[name] = max(peak[name], value)
            for name in ALL_METHODS:
                maxima[name].append(peak[name])
        n = len(streams)
        order = math.ceil((n + 1) * (1 - alpha))
        # Inadequate calibration cannot silently masquerade as a finite 1% threshold.
        self.thresholds = {name: float(np.sort(values)[order - 1]) if order <= n else math.inf
                           for name, values in maxima.items()}
        return {
            "alpha": alpha, "n_calibration_streams": n, "rank_order": order,
            "resolution": 1 / (n + 1), "finite_thresholds": order <= n,
            "thresholds": {name: value if math.isfinite(value) else None for name, value in self.thresholds.items()},
            "scope": "one alarm per complete stream; calibrated on stream maxima, including sequential and MMD history",
            "assumption": "Rank validity requires exchangeable benign calibration and test streams of comparable horizon. Synthetic policy references do not certify production FPR or conditional FPR at every scale.",
            "max_calibration_requests": max(row["cumulative_requests"] for stream in streams for row in stream),
            "max_calibration_windows": max(len(stream) for stream in streams),
        }

    def to_dict(self) -> dict:
        return {
            "schema_version": 1, "benign": gaussian_dict(self.benign), "attack": self.attack.to_dict(),
            "conditional_benign": self.conditional_benign.to_dict(),
            "conditional_attack": self.conditional_attack.to_dict(), "graph_benign": self.graph_benign.to_dict(),
            "normalization": self.normalization, "rff_weights": self.rff_weights.tolist(),
            "rff_phase": self.rff_phase.tolist(), "rff_reference": self.rff_reference.tolist(),
            "thresholds": {name: value if math.isfinite(value) else None for name, value in self.thresholds.items()},
            "mmd_history": self.mmd_history, "cusum_drift": self.cusum_drift,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DetectorBundle":
        if data.get("schema_version") != 1:
            raise ValueError("unsupported detector bundle schema")
        return cls(
            gaussian_from(data["benign"]), ConditionalMixture.from_dict(data["attack"]),
            ConditionalMixture.from_dict(data["conditional_benign"]),
            ConditionalMixture.from_dict(data["conditional_attack"]), ConditionalMixture.from_dict(data["graph_benign"]),
            {key: tuple(value) for key, value in data["normalization"].items()},
            np.asarray(data["rff_weights"]), np.asarray(data["rff_phase"]), np.asarray(data["rff_reference"]),
            {key: math.inf if value is None else float(value) for key, value in data["thresholds"].items()},
            int(data["mmd_history"]), float(data["cusum_drift"]),
        )
