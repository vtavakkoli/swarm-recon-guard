from __future__ import annotations

import csv
import json
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scipy.stats import chi2, norm, shapiro

from swarmguard.reporting.stats import auroc, average_precision, wilson_interval

FEATURES = (
    "novelty_ratio",
    "namespace_span",
    "gap_uniformity",
    "diagnostic_ratio",
    "family_entropy",
    "semantic_coverage",
)

DEFAULT_BOUNDED = frozenset(FEATURES)


def _logit(x: np.ndarray, eps: float = 1e-5) -> np.ndarray:
    x = np.clip(x, eps, 1.0 - eps)
    return np.log(x / (1.0 - x))


def vectorize(rows: list[dict[str, object]], features: tuple[str, ...] = FEATURES) -> np.ndarray:
    data = np.asarray([[float(r[f]) for f in features] for r in rows], dtype=float)
    return _logit(data)


@dataclass
class GaussianModel:
    mean: np.ndarray
    covariance: np.ndarray
    precision: np.ndarray
    logdet: float

    @classmethod
    def fit(cls, x: np.ndarray, shrinkage: float = 0.10, ridge: float = 1e-6) -> "GaussianModel":
        if x.ndim != 2 or len(x) < 2:
            raise ValueError("Gaussian fit requires at least two observations")
        mean = np.mean(x, axis=0)
        cov = np.cov(x, rowvar=False, ddof=1)
        cov = np.atleast_2d(cov)
        p = cov.shape[0]
        avg_var = float(np.trace(cov) / max(1, p))
        cov = (1.0 - shrinkage) * cov + shrinkage * avg_var * np.eye(p)
        cov = cov + ridge * np.eye(p)
        sign, logdet = np.linalg.slogdet(cov)
        if sign <= 0:
            raise ValueError("regularized covariance is not positive definite")
        precision = np.linalg.pinv(cov)
        return cls(mean=mean, covariance=cov, precision=precision, logdet=float(logdet))

    def mahalanobis_sq(self, x: np.ndarray) -> np.ndarray:
        delta = x - self.mean
        return np.einsum("...i,ij,...j->...", delta, self.precision, delta)

    def logpdf(self, x: np.ndarray) -> np.ndarray:
        p = x.shape[1]
        return -0.5 * (p * math.log(2.0 * math.pi) + self.logdet + self.mahalanobis_sq(x))


@dataclass
class GaussianMixture:
    models: list[GaussianModel]
    weights: np.ndarray

    @classmethod
    def fit_by_group(
        cls,
        rows: list[dict[str, object]],
        features: tuple[str, ...] = FEATURES,
        shrinkage: float = 0.10,
    ) -> "GaussianMixture":
        groups: dict[str, list[dict[str, object]]] = defaultdict(list)
        for row in rows:
            groups[str(row["scenario"])].append(row)
        models, counts = [], []
        for _, group in sorted(groups.items()):
            if len(group) < 2:
                continue
            models.append(GaussianModel.fit(vectorize(group, features), shrinkage=shrinkage))
            counts.append(len(group))
        if not models:
            raise ValueError("attack mixture requires at least one group with two observations")
        weights = np.asarray(counts, dtype=float)
        weights /= np.sum(weights)
        return cls(models=models, weights=weights)

    def logpdf(self, x: np.ndarray) -> np.ndarray:
        stacked = np.vstack([m.logpdf(x) + math.log(w) for m, w in zip(self.models, self.weights)])
        m = np.max(stacked, axis=0)
        return m + np.log(np.sum(np.exp(stacked - m), axis=0))


def _quantile_higher(values: np.ndarray, q: float) -> float:
    return float(np.quantile(values, q, method="higher"))


def _z(values: np.ndarray, mean: float, std: float) -> np.ndarray:
    return (values - mean) / max(std, 1e-9)


def _score_set(
    rows: list[dict[str, object]],
    benign_model: GaussianModel,
    attack_model: GaussianMixture,
    h_mu: float,
    h_std: float,
    llr_mu: float,
    llr_std: float,
    hybrid_weight: float,
) -> dict[str, np.ndarray]:
    x = vectorize(rows)
    heuristic = np.asarray([float(r["detector_score_peak"]) for r in rows], dtype=float)
    ood = benign_model.mahalanobis_sq(x)
    llr = attack_model.logpdf(x) - benign_model.logpdf(x)
    hybrid = hybrid_weight * _z(heuristic, h_mu, h_std) + (1.0 - hybrid_weight) * _z(llr, llr_mu, llr_std)
    return {"heuristic": heuristic, "gaussian_ood": ood, "gaussian_llr": llr, "hybrid": hybrid}


def _splits(rows: list[dict[str, object]], mode: str) -> list[tuple[str, list[dict[str, object]], list[dict[str, object]]]]:
    if mode == "leave_repeat_out":
        values = sorted({int(r["repeat"]) for r in rows})
        return [(f"repeat={v}", [r for r in rows if int(r["repeat"]) != v], [r for r in rows if int(r["repeat"]) == v]) for v in values]
    if mode == "leave_scale_out":
        values = sorted({int(r["agent_count"]) for r in rows})
        return [(f"agents={v}", [r for r in rows if int(r["agent_count"]) != v], [r for r in rows if int(r["agent_count"]) == v]) for v in values]
    if mode == "leave_attack_out":
        attacks = sorted({str(r["scenario"]) for r in rows if int(r["label"]) == 1})
        repeats = sorted({int(r["repeat"]) for r in rows})
        return [
            (f"attack={attack}",
             [r for r in rows if r["scenario"] != attack and not (int(r["label"]) == 0 and int(r["repeat"]) == repeats[i % len(repeats)])],
             [r for r in rows if r["scenario"] == attack or (int(r["label"]) == 0 and int(r["repeat"]) == repeats[i % len(repeats)])])
            for i, attack in enumerate(attacks)
        ]
    raise ValueError(f"unknown validation mode: {mode}")


def evaluate_distributional(
    rows: list[dict[str, object]],
    out: Path,
    *,
    alpha: float = 0.01,
    shrinkage: float = 0.10,
    hybrid_weight: float = 0.50,
    validation_modes: tuple[str, ...] = ("leave_repeat_out", "leave_scale_out"),
) -> dict[str, object]:
    score_rows: list[dict[str, object]] = []
    summary_rows: list[dict[str, object]] = []

    for mode in validation_modes:
        mode_rows: list[dict[str, object]] = []
        for fold_name, train, test in _splits(rows, mode):
            all_benign = [r for r in train if int(r["label"]) == 0]
            # Nested, run-grouped calibration is disjoint from density fitting.
            repeat_values = sorted({int(r["repeat"]) for r in all_benign})
            if len(repeat_values) < 2:
                continue
            calibration_repeat = repeat_values[-1]
            calibration_benign = [r for r in all_benign if int(r["repeat"]) == calibration_repeat]
            train_benign = [r for r in all_benign if int(r["repeat"]) != calibration_repeat]
            train_attack = [r for r in train if int(r["label"]) == 1]
            if len(train_benign) < 3 or len(train_attack) < 3:
                continue

            benign_model = GaussianModel.fit(vectorize(train_benign), shrinkage=shrinkage)
            attack_model = GaussianMixture.fit_by_group(train_attack, shrinkage=shrinkage)

            train_x = vectorize(train_benign)
            train_h = np.asarray([float(r["detector_score_peak"]) for r in train_benign], dtype=float)
            train_llr = attack_model.logpdf(train_x) - benign_model.logpdf(train_x)
            h_mu, h_std = float(np.mean(train_h)), float(np.std(train_h, ddof=1))
            llr_mu, llr_std = float(np.mean(train_llr)), float(np.std(train_llr, ddof=1))

            train_scores = _score_set(train_benign, benign_model, attack_model, h_mu, h_std, llr_mu, llr_std, hybrid_weight)
            calibration_scores = _score_set(calibration_benign, benign_model, attack_model, h_mu, h_std, llr_mu, llr_std, hybrid_weight)
            thresholds = {name: _quantile_higher(values, 1.0 - alpha) for name, values in calibration_scores.items()}
            test_scores = _score_set(test, benign_model, attack_model, h_mu, h_std, llr_mu, llr_std, hybrid_weight)

            for i, row in enumerate(test):
                for detector, values in test_scores.items():
                    rec = {
                        "validation": mode,
                        "fold": fold_name,
                        "detector": detector,
                        "scenario": row["scenario"],
                        "agent_count": row["agent_count"],
                        "repeat": row["repeat"],
                        "label": int(row["label"]),
                        "score": float(values[i]),
                        "threshold": float(thresholds[detector]),
                        "detected": bool(values[i] > thresholds[detector]),
                        "n_calibration": len(calibration_benign),
                        "calibration_resolution": 1.0 / (len(calibration_benign) + 1),
                    }
                    score_rows.append(rec)
                    mode_rows.append(rec)

        for detector in ("heuristic", "gaussian_ood", "gaussian_llr", "hybrid"):
            subset = [r for r in mode_rows if r["detector"] == detector]
            if not subset:
                continue
            labels = [int(r["label"]) for r in subset]
            scores = [float(r["score"]) for r in subset]
            benign = [r for r in subset if int(r["label"]) == 0]
            attack = [r for r in subset if int(r["label"]) == 1]
            fp = sum(bool(r["detected"]) for r in benign)
            tp = sum(bool(r["detected"]) for r in attack)
            fpl, fph = wilson_interval(fp, len(benign))
            tpl, tph = wilson_interval(tp, len(attack))
            fold_aurocs = []
            fold_aps = []
            for fold in sorted({str(r["fold"]) for r in subset}):
                fold_rows = [r for r in subset if str(r["fold"]) == fold]
                fold_labels = [int(r["label"]) for r in fold_rows]
                fold_scores = [float(r["score"]) for r in fold_rows]
                if len(set(fold_labels)) == 2:
                    fold_aurocs.append(auroc(fold_labels, fold_scores))
                    fold_aps.append(average_precision(fold_labels, fold_scores))
            summary_rows.append({
                "validation": mode,
                "detector": detector,
                "n": len(subset),
                "auroc": auroc(labels, scores),
                "average_precision": average_precision(labels, scores),
                "macro_auroc_mean": statistics.fmean(fold_aurocs) if fold_aurocs else float("nan"),
                "macro_auroc_std": statistics.stdev(fold_aurocs) if len(fold_aurocs) > 1 else 0.0,
                "macro_ap_mean": statistics.fmean(fold_aps) if fold_aps else float("nan"),
                "macro_ap_std": statistics.stdev(fold_aps) if len(fold_aps) > 1 else 0.0,
                "false_positive_rate": fp / len(benign) if benign else float("nan"),
                "false_positive_wilson_low": fpl,
                "false_positive_wilson_high": fph,
                "detection_rate": tp / len(attack) if attack else float("nan"),
                "detection_wilson_low": tpl,
                "detection_wilson_high": tph,
            })

    if score_rows:
        with (out / "distributional_scores.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(score_rows[0]))
            w.writeheader()
            w.writerows(score_rows)

        fold_summary_rows = []
        keys = sorted({(str(r["validation"]), str(r["fold"]), str(r["detector"])) for r in score_rows})
        for validation, fold, detector in keys:
            subset = [r for r in score_rows if r["validation"] == validation and r["fold"] == fold and r["detector"] == detector]
            labels = [int(r["label"]) for r in subset]
            scores = [float(r["score"]) for r in subset]
            benign = [r for r in subset if int(r["label"]) == 0]
            attack = [r for r in subset if int(r["label"]) == 1]
            fp = sum(bool(r["detected"]) for r in benign)
            tp = sum(bool(r["detected"]) for r in attack)
            fold_summary_rows.append({
                "validation": validation,
                "fold": fold,
                "detector": detector,
                "n": len(subset),
                "auroc": auroc(labels, scores) if len(set(labels)) == 2 else float("nan"),
                "average_precision": average_precision(labels, scores) if len(set(labels)) == 2 else float("nan"),
                "false_positive_rate": fp / len(benign) if benign else float("nan"),
                "detection_rate": tp / len(attack) if attack else float("nan"),
            })
        with (out / "distributional_folds.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(fold_summary_rows[0]))
            w.writeheader()
            w.writerows(fold_summary_rows)
    if summary_rows:
        with (out / "distributional_summary.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(summary_rows[0]))
            w.writeheader()
            w.writerows(summary_rows)

    diagnostics = gaussian_diagnostics([r for r in rows if int(r["label"]) == 0])
    (out / "gaussian_diagnostics.json").write_text(json.dumps(diagnostics, indent=2), encoding="utf-8")

    return {"summary": summary_rows, "diagnostics": diagnostics}


def gaussian_diagnostics(benign_rows: list[dict[str, object]]) -> dict[str, object]:
    if len(benign_rows) < 3:
        return {"n_benign": len(benign_rows), "interpretation": "Insufficient independent benign runs for normality diagnostics."}
    x = vectorize(benign_rows)
    n, p = x.shape
    feature_tests = {}
    for idx, feature in enumerate(FEATURES):
        if np.ptp(x[:, idx]) < 1e-10:
            feature_tests[feature] = {"shapiro_w": None, "p_value": None, "constant": True}
        else:
            stat, pvalue = shapiro(x[:, idx])
            feature_tests[feature] = {"shapiro_w": float(stat), "p_value": float(pvalue), "constant": False}

    model = GaussianModel.fit(x, shrinkage=0.0, ridge=1e-8)
    centered = x - model.mean
    cross = centered @ model.precision @ centered.T
    b1p = float(np.sum(cross ** 3) / (n ** 2))
    skew_df = p * (p + 1) * (p + 2) // 6
    skew_stat = n * b1p / 6.0
    skew_p = float(chi2.sf(skew_stat, skew_df))

    d2 = model.mahalanobis_sq(x)
    b2p = float(np.mean(d2 ** 2))
    expected = p * (p + 2)
    z = (b2p - expected) / math.sqrt(8.0 * p * (p + 2) / n)
    kurt_p = float(2.0 * norm.sf(abs(z)))

    return {
        "n_benign": n,
        "dimension": p,
        "transform": "logit on bounded collective features",
        "univariate_shapiro": feature_tests,
        "mardia_skewness": {"b1p": b1p, "chi_square": skew_stat, "df": skew_df, "p_value": skew_p},
        "mardia_kurtosis": {"b2p": b2p, "expected": expected, "z": float(z), "p_value": kurt_p},
        "interpretation": "Pooled diagnostics mix workload regimes and population scales. Small p-values can reflect this heterogeneity; Gaussian LLR/OOD are approximation baselines. Classical Mardia p-values also assume independent observations and nonsingular covariance.",
    }
