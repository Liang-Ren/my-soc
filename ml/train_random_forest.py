import argparse
import os

from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=None)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main():
    args = parse_args()

    # 1) Generate synthetic classification data
    #  - 10 numeric features
    #  - 2 informative, 2 redundant, binary label
    X, y = make_classification(
        n_samples=5000,
        n_features=10,
        n_informative=4,
        n_redundant=2,
        n_repeated=0,
        n_classes=2,
        random_state=args.random_state,
    )

    # 2) Train RandomForestClassifier
    clf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        random_state=args.random_state,
        n_jobs=-1,
    )
    clf.fit(X, y)

    # 3) Simple training summary (helps debug in CloudWatch Logs)
    y_pred = clf.predict(X)
    report = classification_report(y, y_pred)
    print("RandomForestClassifier trained on synthetic data")
    print(report)

    # 4) Save model to SageMaker expected path
    # SageMaker will tar.gz everything under /opt/ml/model and upload to S3
    model_dir = os.environ.get("SM_MODEL_DIR", "/opt/ml/model")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "model.joblib")

    joblib.dump(clf, model_path)
    print(f"Saved model to {model_path}")


if __name__ == "__main__":
    main()
