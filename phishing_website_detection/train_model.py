"""
train_model.py
--------------
Trains a Random Forest classifier on URL features, evaluates it on held-out
data, and saves the model + real evaluation numbers.

Usage (from the project folder):
    python train_model.py                              # uses dataset/sample_urls.csv
    python train_model.py --data my_dataset.csv        # a real dataset (see dataset/README.md)
    python train_model.py --data phiusiil.csv --url-column URL --label-column label --invert-labels

The CSV needs a URL column and a label column where 1 = phishing, 0 = legitimate
(use --invert-labels if your dataset uses the opposite meaning).
All metrics are computed by this script - nothing is typed in by hand.
"""

import argparse
import json
import os
from datetime import datetime

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score
from sklearn.model_selection import train_test_split

from feature_extraction import FEATURE_NAMES, features_to_dataframe

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA = os.path.join(BASE_DIR, "dataset", "sample_urls.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
CONFIG_PATH = os.path.join(MODEL_DIR, "model_config.json")


def main():
    parser = argparse.ArgumentParser(description="Train the phishing URL classifier.")
    parser.add_argument("--data", default=DEFAULT_DATA, help="Path to a CSV file with URLs and labels.")
    parser.add_argument("--url-column", default="url")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--invert-labels", action="store_true",
                        help="Use if the dataset has 1 = legitimate and 0 = phishing.")
    parser.add_argument("--test-size", type=float, default=0.25)
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    df = df[[args.url_column, args.label_column]].dropna().drop_duplicates(subset=args.url_column)
    labels = df[args.label_column].astype(int)
    if args.invert_labels:
        labels = 1 - labels

    X = features_to_dataframe(df[args.url_column])
    y = labels.reset_index(drop=True)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    is_sample = os.path.abspath(args.data) == os.path.abspath(DEFAULT_DATA)
    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision_phishing": float(precision_score(y_test, pred, zero_division=0)),
        "recall_phishing": float(recall_score(y_test, pred, zero_division=0)),
        "confusion_matrix": cm.tolist(),  # rows = actual [legit, phishing], cols = predicted
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
    }
    config = {
        "feature_names": FEATURE_NAMES,
        "model_type": "RandomForestClassifier",
        "dataset_file": os.path.basename(args.data),
        "used_sample_dataset": is_sample,
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "label_meaning": {"0": "legitimate", "1": "phishing"},
        "metrics": metrics,
    }

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(f"Dataset: {args.data} ({len(df)} unique URLs)")
    print(f"Train/Test sizes: {len(X_train)}/{len(X_test)}")
    print(f"Accuracy on test set: {metrics['accuracy']:.3f}")
    print(f"Precision (phishing): {metrics['precision_phishing']:.3f}")
    print(f"Recall (phishing):    {metrics['recall_phishing']:.3f}")
    print("Confusion matrix [rows=actual legit/phishing, cols=predicted legit/phishing]:")
    print(cm)
    if is_sample:
        print("\nNOTE: trained on the tiny hand-written sample dataset. These numbers are a demo,"
              " NOT a validation of phishing detection.")
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved config to {CONFIG_PATH}")


if __name__ == "__main__":
    main()
