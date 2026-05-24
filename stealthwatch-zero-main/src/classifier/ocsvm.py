# src/classifier/ocsvm.py
"""
One-Class SVM classifier for STEALTHWATCH-ZERO.

Two execution paths:
  1. Real CTU-13 data  — run with a .labeled CSV file present at
                         'data/raw/CTU-13/scenario1.labeled'
                         Uses optimized_load_and_group() to extract per-flow
                         timing sequences, then computes 5-feature entropy vectors.

  2. Synthetic fallback — no data file needed; trains on procedurally generated
                          benign (exponential IAT) and malicious (bounded uniform
                          jitter) timing sequences.  Used by run_demo.py and CI.

Feature vector (5-dimensional):
  [CV, ApEn, NPE, Skewness, Kurtosis]

  CV is the primary discriminant — provably bounded for any reliable C2 beaconer:
      CV = J/sqrt(3) <= 0.5/sqrt(3) ≈ 0.289   (for J <= 50% jitter)
  Human traffic (Poisson):  CV ≈ 1.0
"""

import os
import sys
import random
import numpy as np
import pandas as pd
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             roc_auc_score, confusion_matrix)
import joblib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from src.entropy.feature_extractor import EntropyFeatureExtractor


# ---------------------------------------------------------------------------
# Real CTU-13 data loader
# ---------------------------------------------------------------------------

def optimized_load_and_group(path: str):
    """
    Load a CTU-13 .labeled CSV file and return a DataFrame of per-flow
    timing delta arrays with binary labels.

    Each row represents one (SrcAddr, DstAddr, Dport) connection group
    with columns:
        deltas : np.ndarray of inter-arrival time differences (seconds)
        label  : int  1 = Botnet/malicious, 0 = benign

    Only groups with >= 20 packets are kept (minimum for entropy computation).
    """
    print(f"  Reading {os.path.basename(path)} ...")
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]

    df['is_malicious'] = df['Label'].str.contains('Botnet', na=False).astype(int)
    df['timestamp']    = pd.to_datetime(df['StartTime']).view('int64') // 10**9

    print(f"  Processing {len(df):,} flows ...")
    grouped = df.sort_values('timestamp').groupby(['SrcAddr', 'DstAddr', 'Dport'])

    records = []
    for _, grp in grouped:
        if len(grp) < 20:
            continue
        deltas = np.diff(grp['timestamp'].values).astype(float)
        deltas = deltas[deltas > 0]
        if len(deltas) >= 15:
            records.append({
                'deltas': deltas,
                'label':  int(grp['is_malicious'].max()),
            })

    result = pd.DataFrame(records)
    print(f"  Found {len(result):,} eligible flows "
          f"({result['label'].sum()} malicious, "
          f"{(result['label']==0).sum()} benign)")
    return result


# ---------------------------------------------------------------------------
# Synthetic data generator (used when no real data is available)
# ---------------------------------------------------------------------------

def generate_synthetic_features(n_samples: int = 1000,
                                 mode: str = 'benign') -> np.ndarray:
    """
    Generate synthetic 5-dimensional feature vectors.

    Benign   : exponential IAT (CV~1.0, Skew~2.0) — Poisson/human browsing.
    Malicious: bounded uniform jitter (CV<0.35, Skew~0) — C2 beaconing.
    """
    extractor = EntropyFeatureExtractor(window=50)
    features  = []

    for _ in range(n_samples):
        if mode == 'benign':
            scale  = random.uniform(0.5, 10.0)
            deltas = np.random.exponential(scale=scale, size=100)

        elif mode == 'malicious':
            base   = random.uniform(5.0, 120.0)
            # Bounded uniform jitter: CV = jitter/sqrt(3) <= 0.289
            jitter = random.uniform(0.0, 0.35)
            lo, hi = -jitter * base, jitter * base
            deltas = base + np.random.uniform(lo, hi, size=100)

        else:
            raise ValueError(f"Unknown mode: {mode!r}. Use 'benign' or 'malicious'.")

        feat = extractor.compute_features(deltas)
        if feat is not None:
            features.append(feat)

    return np.array(features)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class StealthwatchClassifier:
    """
    One-Class SVM trained exclusively on benign traffic.

    Flags connections whose 5-feature entropy vector falls outside the
    learned benign region as potential C2 beaconers.

    Parameters
    ----------
    nu : float    Upper bound on FPR in training (~5%). Tune with nu_sweep.
    kernel : str  'rbf' recommended for 5-D feature space.
    gamma         RBF bandwidth. 'scale' = 1/(n_features * X.var()).
    """

    def __init__(self, nu: float = 0.05, kernel: str = 'rbf', gamma='scale'):
        self.nu     = nu
        self.ocsvm  = OneClassSVM(nu=nu, kernel=kernel, gamma=gamma)
        self.scaler = StandardScaler()
        self.trained = False

    def fit(self, X_benign: np.ndarray) -> 'StealthwatchClassifier':
        """Train only on benign samples. X_benign must be shape (n, 5)."""
        if X_benign.ndim != 2 or X_benign.shape[1] != 5:
            raise ValueError(f"Expected (n, 5) array, got {X_benign.shape}")
        X_scaled = self.scaler.fit_transform(X_benign)
        self.ocsvm.fit(X_scaled)
        self.trained = True
        print(f"[OCSVM] Trained on {X_benign.shape[0]} benign samples "
              f"(nu={self.nu})")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns 0 = benign, 1 = anomaly (possible C2)."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        raw = self.ocsvm.predict(self.scaler.transform(X))
        return (raw == -1).astype(int)

    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        """Decision function. Lower (more negative) = more anomalous."""
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.ocsvm.decision_function(self.scaler.transform(X))

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray,
                 label: str = 'Test') -> dict:
        """Evaluate on a labelled set. y=1 means C2/botnet, y=0 means benign."""
        y_pred = self.predict(X_test)
        scores = self.decision_scores(X_test)

        try:
            auc = float(roc_auc_score(y_test, -scores))
        except ValueError:
            auc = float('nan')

        metrics = {
            'label':            label,
            'precision':        float(precision_score(y_test, y_pred, zero_division=0)),
            'recall':           float(recall_score(y_test, y_pred, zero_division=0)),
            'f1':               float(f1_score(y_test, y_pred, zero_division=0)),
            'auc':              auc,
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        }

        print(f"\n{'='*50}")
        print(f"  {label}")
        print(f"{'='*50}")
        print(f"  Precision : {metrics['precision']:.4f}")
        print(f"  Recall    : {metrics['recall']:.4f}")
        print(f"  F1        : {metrics['f1']:.4f}")
        print(f"  ROC-AUC   : {metrics['auc']:.4f}")
        cm = metrics['confusion_matrix']
        print(f"  Confusion : TN={cm[0][0]}  FP={cm[0][1]}  "
              f"FN={cm[1][0]}  TP={cm[1][1]}")
        return metrics

    def save(self, path: str = 'experiments/stealthwatch_model.pkl') -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({'ocsvm': self.ocsvm, 'scaler': self.scaler,
                     'nu': self.nu}, path)
        print(f"[OCSVM] Model saved → {path}")

    @classmethod
    def load(cls, path: str = 'experiments/stealthwatch_model.pkl') -> 'StealthwatchClassifier':
        data = joblib.load(path)
        obj  = cls(nu=data['nu'])
        obj.ocsvm   = data['ocsvm']
        obj.scaler  = data['scaler']
        obj.trained = True
        return obj


# ---------------------------------------------------------------------------
# Script entry-point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    extractor  = EntropyFeatureExtractor(window=50)
    data_path  = 'data/raw/CTU-13/scenario1.labeled'

    if os.path.exists(data_path):
        # ---- Real CTU-13 data path ----
        agg_df = optimized_load_and_group(data_path)

        benign_feats, malicious_feats = [], []
        print("Extracting entropy features from real CTU-13 data...")
        for _, row in agg_df.iterrows():
            deltas = row['deltas'][row['deltas'] > 0]
            if len(deltas) < 15:
                continue
            feat = extractor.compute_features(deltas)
            if feat is not None:
                if row['label'] == 1:
                    malicious_feats.append(feat)
                else:
                    benign_feats.append(feat)

        print(f"  Benign flows : {len(benign_feats)}")
        print(f"  Malicious    : {len(malicious_feats)}")

        X_benign = np.array(benign_feats)
        split    = int(0.8 * len(X_benign))
        X_train, X_test_benign = X_benign[:split], X_benign[split:]

        X_test = np.vstack([X_test_benign, np.array(malicious_feats)])
        y_test = np.hstack([np.zeros(len(X_test_benign)),
                            np.ones(len(malicious_feats))])

    else:
        # ---- Synthetic fallback ----
        print(f"[INFO] {data_path} not found — using synthetic data.")
        print("       To train on real data, download CTU-13 and place")
        print("       .labeled files in data/raw/CTU-13/\n")

        X_train  = generate_synthetic_features(n_samples=1000, mode='benign')
        X_test_b = generate_synthetic_features(n_samples=300,  mode='benign')
        X_test_m = generate_synthetic_features(n_samples=300,  mode='malicious')
        X_test   = np.vstack([X_test_b, X_test_m])
        y_test   = np.hstack([np.zeros(len(X_test_b)), np.ones(len(X_test_m))])

    clf = StealthwatchClassifier(nu=0.05)
    clf.fit(X_train)
    clf.evaluate(X_test, y_test, label='OCSVM Detection Test')
    clf.save()
    print("\n[Done] Model saved to experiments/stealthwatch_model.pkl")
