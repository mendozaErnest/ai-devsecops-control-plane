"""ML Risk Scorer — XGBoost-based per-finding risk score.

score_finding(finding) → float [0.0–1.0]
train_model(findings)  → {precision, recall, roc_auc, n_samples}

Both functions degrade gracefully when xgboost/scikit-learn are absent or
when no persisted model exists, using a deterministic severity-based fallback
(same pattern as src/metrics/security_metrics.py with prometheus_client).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)

# ── optional dependencies ─────────────────────────────────────────────────────
try:
    import joblib
    import numpy as np
    from sklearn.metrics import precision_score, recall_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from xgboost import XGBClassifier
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

# ── model persistence path ───────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MODEL_PATH = _PROJECT_ROOT / "models" / "risk_model.joblib"

def _model_path() -> Path:
    raw = os.getenv("RISK_MODEL_PATH")
    return Path(raw) if raw else _DEFAULT_MODEL_PATH

# ── severity fallback (used when no model is trained) ────────────────────────
_SEVERITY_FALLBACK: dict[str, float] = {
    "CRITICAL": 0.9,
    "HIGH":     0.7,
    "MEDIUM":   0.4,
    "LOW":      0.2,
}

# ── tool encoding ─────────────────────────────────────────────────────────────
_TOOL_ENCODE: dict[str, int] = {
    "bandit":    1,
    "semgrep":   2,
    "zap":       3,
    "eslint":    4,
    "pylint":    5,
    "sonarqube": 6,
    "pip-audit": 7,
    "odc":       8,
}

# ── status encoding ───────────────────────────────────────────────────────────
_STATUS_ENCODE: dict[str, int] = {
    "open":           0,
    "regression":     1,
    "fixed":          2,
    "accepted_risk":  3,
    "false_positive": 4,
}

# ── severity encoding ─────────────────────────────────────────────────────────
_SEVERITY_ENCODE: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
}


def _get_attr(obj: Any, key: str, default: Any = None) -> Any:
    """Uniform attribute access for Finding ORM objects and plain dicts."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _features_from_finding(finding: Any) -> list[float]:
    """Extract a fixed-length numeric feature vector from a finding.

    Features (6 total):
    0. severity_enc    — CRITICAL=4 … LOW=1, unknown=1
    1. tool_enc        — tool identity integer (unknown=0)
    2. regression_count — direct int (0 if absent)
    3. days_age        — days since first_seen_at (capped at 365)
    4. days_to_deadline — days until SLA deadline; negative = overdue (capped ±365)
    5. status_enc      — open=0 … false_positive=4, unknown=0
    """
    sev = str(_get_attr(finding, "severity") or "LOW").upper()
    tool = str(_get_attr(finding, "tool") or "").lower()
    regression_count = int(_get_attr(finding, "regression_count") or 0)
    status = str(_get_attr(finding, "status") or "open").lower()

    sev_enc = _SEVERITY_ENCODE.get(sev, 1)
    tool_enc = _TOOL_ENCODE.get(tool, 0)
    status_enc = _STATUS_ENCODE.get(status, 0)

    # age in days
    now = datetime.now(timezone.utc)
    first_seen = _get_attr(finding, "first_seen_at")
    if first_seen is None:
        days_age = 0.0
    else:
        if isinstance(first_seen, str):
            try:
                first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            except ValueError:
                first_seen = None
        if first_seen is not None:
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            days_age = min((now - first_seen).days, 365)
        else:
            days_age = 0.0

    # days to SLA deadline (negative = overdue)
    sla_deadline = _get_attr(finding, "sla_deadline")
    if sla_deadline is None:
        days_to_deadline = 30.0
    else:
        if isinstance(sla_deadline, str):
            try:
                sla_deadline = datetime.fromisoformat(sla_deadline.replace("Z", "+00:00"))
            except ValueError:
                sla_deadline = None
        if sla_deadline is not None:
            if sla_deadline.tzinfo is None:
                sla_deadline = sla_deadline.replace(tzinfo=timezone.utc)
            days_to_deadline = max(min((sla_deadline - now).days, 365), -365)
        else:
            days_to_deadline = 30.0

    return [
        float(sev_enc),
        float(tool_enc),
        float(regression_count),
        float(days_age),
        float(days_to_deadline),
        float(status_enc),
    ]


def _fallback_score(finding: Any) -> float:
    sev = str(_get_attr(finding, "severity") or "LOW").upper()
    return _SEVERITY_FALLBACK.get(sev, 0.2)


def score_finding(finding: Any) -> float:
    """Return a risk score in [0.0–1.0] for the given finding.

    Uses the persisted XGBoost model when available; falls back to a
    deterministic severity-based score (critical=0.9, high=0.7,
    medium=0.4, low=0.2) when no model is persisted or ML libs absent.
    """
    if not _ML_AVAILABLE:
        return _fallback_score(finding)

    model_file = _model_path()
    if not model_file.exists():
        return _fallback_score(finding)

    try:
        model: XGBClassifier = joblib.load(model_file)
        features = _features_from_finding(finding)
        prob = float(model.predict_proba([features])[0][1])
        return round(max(0.0, min(1.0, prob)), 4)
    except Exception as exc:
        _logger.warning("score_finding: model inference failed, using fallback: %s", exc)
        return _fallback_score(finding)


def train_model(findings: list[Any]) -> dict:
    """Train an XGBClassifier on the given findings list.

    Label definition: high-risk = severity in {CRITICAL, HIGH} AND
    status in {open, regression}.

    Persists the model to ``_model_path()`` with joblib.

    Returns:
        {precision: float, recall: float, roc_auc: float, n_samples: int}

    Raises:
        RuntimeError if xgboost/sklearn are not installed.
        ValueError  if fewer than 10 findings are provided or if the
                    label distribution has only one class.
    """
    if not _ML_AVAILABLE:
        raise RuntimeError(
            "xgboost and scikit-learn must be installed to train the risk model. "
            "Run: pip install xgboost>=2.0.0 scikit-learn>=1.4.0 joblib>=1.3.0"
        )

    if len(findings) < 10:
        raise ValueError(
            f"Need at least 10 findings to train the model, got {len(findings)}."
        )

    X = [_features_from_finding(f) for f in findings]
    y = [
        1
        if (
            str(_get_attr(f, "severity") or "").upper() in {"CRITICAL", "HIGH"}
            and str(_get_attr(f, "status") or "open").lower() in {"open", "regression"}
        )
        else 0
        for f in findings
    ]

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    if len(set(y_arr)) < 2:
        raise ValueError(
            "Training data has only one risk class. "
            "Ensure there are both high-risk (CRITICAL/HIGH open) and "
            "low-risk findings in the dataset."
        )

    test_size = max(0.2, min(0.4, 5 / len(findings)))
    X_train, X_test, y_train, y_test = train_test_split(
        X_arr, y_arr, test_size=test_size, random_state=42, stratify=y_arr
    )

    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        verbosity=0,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    try:
        roc_auc = float(roc_auc_score(y_test, y_prob))
    except ValueError:
        roc_auc = 0.0

    model_file = _model_path()
    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_file)
    _logger.info("risk_scorer: model trained on %d samples, saved to %s", len(findings), model_file)

    return {
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "roc_auc":   round(roc_auc, 4),
        "n_samples": len(findings),
    }
