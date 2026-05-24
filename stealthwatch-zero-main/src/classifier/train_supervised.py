# src/classifier/train_supervised.py
"""
Supervised Random Forest classifier for STEALTHWATCH-ZERO.

Uses REAL CTU-13 .labeled CSV data to train a Random Forest on 6
flow-level features.  This is the SUPERVISED complement to the
One-Class SVM — it provides a performance upper bound when labelled
malware data is available.

Feature vector (6-dimensional, per connection group):
  ent      : Shannon entropy of 10-bin IAT histogram
  iat_mean : mean inter-arrival time (seconds)
  iat_var  : variance of inter-arrival times
  dur      : mean flow duration
  pkts     : total packet count for the group
  bytes    : total byte count for the group

Usage:
  # With real CTU-13 data:
  python src/classifier/train_supervised.py

  # Saved model used by run_demo.py and experiments/final_evaluation.py
  # as the 'supervised baseline' comparison point.

Saved artefact:
  experiments/stealthwatch_supervised.pkl  — joblib-serialised RF model
"""

import os
import sys
import glob
import numpy as np
import pandas as pd
from scipy.stats import entropy
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import joblib


# ---------------------------------------------------------------------------
# Feature extraction from a per-flow group
# ---------------------------------------------------------------------------

def extract_features(group: pd.DataFrame):
    """
    Extract 6 flow-level features from a connection group DataFrame.

    Parameters
    ----------
    group : DataFrame
        Rows for a single (SrcAddr, DstAddr, Dport) connection group,
        must contain columns: timestamp, Dur, TotPkts, TotBytes.

    Returns
    -------
    list of 6 floats, or None if the group is too small.
    """
    deltas = np.diff(group['timestamp'].values).astype(float)
    deltas = deltas[deltas > 0]
    if len(deltas) < 5:
        return None

    # Shannon entropy of 10-bin IAT histogram
    hist_counts, _ = np.histogram(deltas, bins=10, density=True)
    ent_val = float(entropy(hist_counts + 1e-9))

    return [
        ent_val,                       # ent      — timing regularity
        float(np.mean(deltas)),        # iat_mean
        float(np.var(deltas)),         # iat_var
        float(group['Dur'].mean()),    # dur      — average flow duration
        int(group['TotPkts'].sum()),   # pkts     — total packets
        int(group['TotBytes'].sum()),  # bytes    — total bytes
    ]


# ---------------------------------------------------------------------------
# Dataset loader
# ---------------------------------------------------------------------------

def load_all_scenarios(file_paths: list) -> pd.DataFrame:
    """
    Load one or more CTU-13 .labeled CSV files and extract per-flow
    feature rows.

    Parameters
    ----------
    file_paths : list of str
        Paths to .labeled files (e.g. from glob.glob('data/raw/CTU-13/*.labeled')).

    Returns
    -------
    DataFrame with columns: ent, iat_mean, iat_var, dur, pkts, bytes, label
    """
    rows = []

    for path in file_paths:
        print(f"  Processing {os.path.basename(path)} ...")
        try:
            df = pd.read_csv(path)
            df.columns = [c.strip() for c in df.columns]

            # Binary label: 1 = Botnet, 0 = benign
            df['is_malicious'] = (
                df['Label'].str.contains('Botnet', na=False).astype(int)
            )

            # Epoch timestamps in seconds
            df['timestamp'] = (
                pd.to_datetime(df['StartTime']).view('int64') // 10**9
            )

            for _, group in df.groupby(['SrcAddr', 'DstAddr', 'Dport']):
                if len(group) < 10:
                    continue
                feats = extract_features(group)
                if feats is not None:
                    label = int(group['is_malicious'].max())
                    rows.append(feats + [label])

        except Exception as e:
            print(f"  [WARN] Skipped {path}: {e}")

    if not rows:
        return pd.DataFrame(columns=['ent', 'iat_mean', 'iat_var',
                                     'dur', 'pkts', 'bytes', 'label'])

    return pd.DataFrame(
        rows,
        columns=['ent', 'iat_mean', 'iat_var', 'dur', 'pkts', 'bytes', 'label']
    )


# ---------------------------------------------------------------------------
# Synthetic fallback (no CTU-13 data available)
# ---------------------------------------------------------------------------

def generate_synthetic_supervised(n_samples: int = 500) -> pd.DataFrame:
    """
    Generate synthetic 6-feature rows for local validation when CTU-13
    data is not available.

    Benign : exponential IAT → high Shannon entropy, high variance
    C2     : bounded uniform jitter → low entropy, low variance
    """
    rows = []
    for _ in range(n_samples):
        # Benign
        scale  = np.random.uniform(0.5, 10.0)
        deltas = np.random.exponential(scale, size=50)
        hist, _ = np.histogram(deltas, bins=10, density=True)
        ent = float(entropy(hist + 1e-9))
        rows.append([ent, float(np.mean(deltas)), float(np.var(deltas)),
                     float(np.random.uniform(0.1, 5.0)),
                     int(np.random.randint(10, 200)),
                     int(np.random.randint(500, 50000)), 0])

        # C2 beaconer
        base   = np.random.uniform(5.0, 120.0)
        jitter = np.random.uniform(0.0, 0.30)
        deltas = base + np.random.uniform(-jitter * base, jitter * base, size=50)
        hist, _ = np.histogram(deltas, bins=10, density=True)
        ent = float(entropy(hist + 1e-9))
        rows.append([ent, float(np.mean(deltas)), float(np.var(deltas)),
                     float(np.random.uniform(0.5, 30.0)),
                     int(np.random.randint(10, 100)),
                     int(np.random.randint(200, 10000)), 1])

    return pd.DataFrame(
        rows,
        columns=['ent', 'iat_mean', 'iat_var', 'dur', 'pkts', 'bytes', 'label']
    )


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=" * 55)
    print("  STEALTHWATCH-ZERO: Supervised RF Training")
    print("=" * 55)

    files = sorted(glob.glob('data/raw/CTU-13/*.labeled'))

    if files:
        print(f"\n[DATA] Found {len(files)} CTU-13 scenario file(s):")
        for f in files:
            print(f"       {f}")
        data = load_all_scenarios(files)
    else:
        print("\n[INFO] No CTU-13 data found in data/raw/CTU-13/")
        print("       Falling back to synthetic data for local validation.")
        print("       Results on synthetic data are illustrative only.\n")
        data = generate_synthetic_supervised(n_samples=500)

    if data.empty:
        print("[ERROR] No data extracted. Exiting.")
        sys.exit(1)

    print(f"\n[DATA] Dataset shape : {data.shape}")
    print(f"       Malicious rows : {data['label'].sum()}")
    print(f"       Benign rows    : {(data['label'] == 0).sum()}")

    X = data.drop('label', axis=1).values
    y = data['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=42
    )

    print(f"\n[TRAIN] Training Random Forest on {len(X_train)} samples ...")
    clf = RandomForestClassifier(
        n_estimators=100,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    probs  = clf.predict_proba(X_test)[:, 1]

    print("\n=== Supervised Random Forest Results ===")
    print(classification_report(y_test, y_pred,
                                target_names=['Benign', 'C2/Botnet']))
    try:
        auc = roc_auc_score(y_test, probs)
        print(f"  ROC-AUC : {auc:.4f}")
    except ValueError:
        print("  ROC-AUC : N/A (only one class in test set)")

    # Feature importance
    feature_names = ['ent', 'iat_mean', 'iat_var', 'dur', 'pkts', 'bytes']
    importances   = clf.feature_importances_
    print("\n  Feature importances:")
    for name, imp in sorted(zip(feature_names, importances),
                             key=lambda x: -x[1]):
        bar = '█' * int(imp * 40)
        print(f"    {name:<10} {imp:.4f}  {bar}")

    os.makedirs('experiments', exist_ok=True)
    out_path = 'experiments/stealthwatch_supervised.pkl'
    joblib.dump(clf, out_path)
    print(f"\n[Done] Supervised model saved → {out_path}")
    print("       Use this as the supervised upper-bound baseline in")
    print("       experiments/final_evaluation.py (Table II of the paper).")
