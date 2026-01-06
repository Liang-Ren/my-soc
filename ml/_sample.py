from __future__ import annotations
import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

LABEL_COLUMN = "escalate"

@dataclass
class TriageConfig:
    n_samples: int = 5000
    train_size: float = 0.8
    random_state: int = 42
    n_estimators: int = 200
    max_depth: int | None = None
    model_path: Path = Path("model.joblib")

def generate_synthetic_alerts(cfg: TriageConfig) -> pd.DataFrame:
    rng = np.random.default_rng(cfg.random_state)
    n = cfg.n_samples
    severities = rng.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], size=n, p=[0.4, 0.3, 0.2, 0.1])
    asset_criticality = rng.choice(["LOW", "MEDIUM", "HIGH"], size=n, p=[0.3, 0.4, 0.3])
    source_type = rng.choice(["CLOUD", "ENDPOINT", "IDENTITY"], size=n)
    past_24h_alerts = rng.integers(0, 50, size=n)
    user_risk_score = rng.uniform(0, 1, size=n)
    is_privileged_user = rng.integers(0, 2, size=n)
    geo_anomaly_score = rng.uniform(0, 1, size=n)
    login_failure_rate = rng.uniform(0, 1, size=n)
    correlated_alert_count = rng.integers(0, 10, size=n)
    time_since_last_seen_hours = rng.exponential(scale=24, size=n)
    base_risk = np.zeros(n)
    severity_weight = {"LOW": 0.1, "MEDIUM": 0.4, "HIGH": 0.8, "CRITICAL": 1.0}
    criticality_weight = {"LOW": 0.0, "MEDIUM": 0.3, "HIGH": 0.6}

    for i in range(n):
        base_risk[i] = (
            severity_weight[severities[i]]
            + criticality_weight[asset_criticality[i]]
            + 0.8 * user_risk_score[i]
            + 0.4 * is_privileged_user[i]
            + 0.3 * geo_anomaly_score[i]
            + 0.2 * login_failure_rate[i]
            + 0.02 * past_24h_alerts[i]
            + 0.05 * correlated_alert_count[i]
        )

        if source_type[i] == "IDENTITY":
            base_risk[i] += 0.2
        base_risk[i] += 0.1 * np.tanh((time_since_last_seen_hours[i] - 48) / 24.0)

    noisy_risk = base_risk + rng.normal(0, 0.3, size=n)
    risk_min, risk_max = noisy_risk.min(), noisy_risk.max()
    if risk_max == risk_min:
        raise ValueError("Risk range collapsed; synthetic data not informative")

    scaled_risk = (noisy_risk - risk_min) / (risk_max - risk_min)
    threshold = 0.6
    escalate = (scaled_risk >= threshold).astype(int)
    data = pd.DataFrame(
        {
            "severity": severities,
            "asset_criticality": asset_criticality,
            "source_type": source_type,
            "past_24h_alerts": past_24h_alerts,
            "user_risk_score": user_risk_score,
            "is_privileged_user": is_privileged_user,
            "geo_anomaly_score": geo_anomaly_score,
            "login_failure_rate": login_failure_rate,
            "correlated_alert_count": correlated_alert_count,
            "time_since_last_seen_hours": time_since_last_seen_hours,
            LABEL_COLUMN: escalate,
        }
    )
    return data

def build_pipeline(cfg: TriageConfig) -> Pipeline:
    categorical_features = ["severity", "asset_criticality", "source_type"]
    numeric_features = [
        "past_24h_alerts",
        "user_risk_score",
        "is_privileged_user",
        "geo_anomaly_score",
        "login_failure_rate",
        "correlated_alert_count",
        "time_since_last_seen_hours",
    ]
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("num", StandardScaler(), numeric_features),
        ]
    )
    clf = RandomForestClassifier(
        n_estimators=cfg.n_estimators,
        max_depth=cfg.max_depth,
        random_state=cfg.random_state,
        n_jobs=-1,
    )
    return Pipeline(steps=[("preprocess", preprocessor), ("model", clf)])

def train_and_evaluate(cfg: TriageConfig) -> Tuple[Pipeline, Mapping[str, float]]:
    logging.info("Generating synthetic alerts", extra={"n_samples": cfg.n_samples})
    data = generate_synthetic_alerts(cfg)
    if LABEL_COLUMN not in data:
        raise KeyError(f"Missing label column: {LABEL_COLUMN}")
    X = data.drop(columns=[LABEL_COLUMN])
    y = data[LABEL_COLUMN]
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        train_size=cfg.train_size,
        random_state=cfg.random_state,
        stratify=y,
    )
    logging.info("Building pipeline")
    pipeline = build_pipeline(cfg)
    logging.info("Fitting model", extra={"n_train": len(X_train)})
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    report = classification_report(y_test, y_pred, output_dict=True)
    roc_auc = roc_auc_score(y_test, y_proba)
    metrics = {
        "roc_auc": float(roc_auc),
        "precision_escalate": float(report["1"]["precision"]),
        "recall_escalate": float(report["1"]["recall"]),
        "f1_escalate": float(report["1"]["f1-score"]),
    }
    logging.info("Finished training", extra=metrics)
    return pipeline, metrics

def save_model(pipeline: Pipeline, path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, path)
    except Exception:
        logging.exception("Failed to save model", extra={"path": str(path)})
        raise

def load_model(path: Path) -> Pipeline:
    if not path.exists():
        raise FileNotFoundError(f"Model file not found: {path}")
    try:
        return joblib.load(path)
    except Exception:
        logging.exception("Failed to load model", extra={"path": str(path)})
        raise

def demo_prediction(pipeline: Pipeline) -> None:
    sample = pd.DataFrame(
        [
            {
                "severity": "HIGH",
                "asset_criticality": "HIGH",
                "source_type": "IDENTITY",
                "past_24h_alerts": 12,
                "user_risk_score": 0.85,
                "is_privileged_user": 1,
                "geo_anomaly_score": 0.75,
                "login_failure_rate": 0.6,
                "correlated_alert_count": 4,
                "time_since_last_seen_hours": 72.0,
            }
        ]
    )
    proba = pipeline.predict_proba(sample)[0, 1]
    label = int(proba >= 0.5)
    logging.info(
        "Demo prediction",
        extra={"proba": float(proba), "label": int(label)},
    )
    print("Example alert:")
    print(sample.to_json(orient="records", indent=2))
    print(f"\nModel escalation probability: {proba:.3f}")
    print(f"Recommended action: {'ESCALATE' if label == 1 else 'SUPPRESS'}")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a SOC alert triage model.")
    parser.add_argument("--n-samples", type=int, default=5000)
    parser.add_argument("--train-size", type=float, default=0.8)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=None)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--model-path", type=str, default="model.joblib")
    parser.add_argument("--demo-prediction", action="store_true")
    parser.add_argument("--log-level", type=str, default="INFO")
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    cfg = TriageConfig(
        n_samples=args.n_samples,
        train_size=args.train_size,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        random_state=args.random_state,
        model_path=Path(args.model_path),
    )
    try:
        pipeline, metrics = train_and_evaluate(cfg)
    except Exception:
        logging.exception("Training failed")
        raise
    print("Training complete. Metrics:")
    print(json.dumps(metrics, indent=2))
    save_model(pipeline, cfg.model_path)
    logging.info("Saved model", extra={"path": str(cfg.model_path.resolve())})
    if args.demo_prediction:
        demo_prediction(pipeline)

if __name__ == "__main__":
    main()
