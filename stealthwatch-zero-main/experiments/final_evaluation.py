# experiments/final_evaluation.py
"""
Phase 8: Final Comparative Evaluation — Table II of the paper.

Compares three detection methods on the same synthetic benchmark:
  1. STEALTHWATCH-ZERO (OCSVM, 5-feature [CV,ApEn,NPE,Skew,Kurt])
     — one-class; trains on benign only; no labelled malware needed
  2. Supervised Random Forest (6-feature Shannon+IAT)
     — upper bound when labelled C2 data IS available
  3. Baseline: Interval CV threshold (naive single-statistic detector)
  4. Baseline: Shannon entropy of IAT bins

Also loads and prints the per-scenario adversarial robustness table
from experiments/adversarial_results.json (produced by adversarial_eval.py).
"""

import os
import sys
import json
import random
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.classifier.ocsvm import (StealthwatchClassifier,
                                   generate_synthetic_features)
from src.entropy.feature_extractor import EntropyFeatureExtractor
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from baselines.simple_interval import interval_baseline, shannon_baseline
import joblib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def rebuild_benign_deltas(seed_offset=0):
    random.seed(42 + seed_offset)
    np.random.seed(42 + seed_offset)
    scale = random.uniform(0.5, 10.0)
    return np.random.exponential(scale=scale, size=100)


def rebuild_malicious_deltas(seed_offset=0):
    random.seed(99 + seed_offset)
    np.random.seed(99 + seed_offset)
    base   = random.uniform(5.0, 120.0)
    jitter = random.uniform(0.0, 0.35)
    return base + np.random.uniform(-jitter * base, jitter * base, size=100)


def compute_supervised_features_for_deltas(deltas):
    """
    Compute the 6 supervised RF features from a raw delta array.
    Matches the feature extraction in train_supervised.py.
    """
    from scipy.stats import entropy as scipy_entropy
    if len(deltas) < 5:
        return None
    hist, _ = np.histogram(deltas, bins=10, density=True)
    ent = float(scipy_entropy(hist + 1e-9))
    return np.array([
        ent,
        float(np.mean(deltas)),
        float(np.var(deltas)),
        float(np.mean(deltas) * 0.1),   # dur approximation
        float(len(deltas)),              # pkts approximation
        float(np.sum(deltas) * 1500),   # bytes approximation
    ])


def compute_metrics(y_true, y_pred, scores=None):
    m = {
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall':    float(recall_score(y_true, y_pred, zero_division=0)),
        'f1':        float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if scores is not None:
        try:
            m['auc'] = float(roc_auc_score(y_true, -scores))
        except Exception:
            m['auc'] = float('nan')
    else:
        m['auc'] = float('nan')
    return m


# ---------------------------------------------------------------------------
# Full synthetic benchmark
# ---------------------------------------------------------------------------

def run_full_benchmark(n_train=1000, n_test=400, seed=42):
    np.random.seed(seed); random.seed(seed)
    extractor = EntropyFeatureExtractor(window=50)

    # ---- Build test sets ----
    X_test_b = generate_synthetic_features(n_test, 'benign')
    X_test_m = generate_synthetic_features(n_test, 'malicious')
    X_test_5 = np.vstack([X_test_b, X_test_m])          # 5-feature for OCSVM
    y_test   = np.hstack([np.zeros(n_test), np.ones(n_test)])

    # Raw deltas for baselines and supervised RF
    deltas_b = [rebuild_benign_deltas(i)    for i in range(n_test)]
    deltas_m = [rebuild_malicious_deltas(i) for i in range(n_test)]
    all_deltas = deltas_b + deltas_m

    # ---- OCSVM (one-class) ----
    model_path = 'experiments/stealthwatch_model.pkl'
    if os.path.exists(model_path):
        clf_ocsvm = StealthwatchClassifier.load(model_path)
    else:
        X_train = generate_synthetic_features(n_train, 'benign')
        clf_ocsvm = StealthwatchClassifier(nu=0.05)
        clf_ocsvm.fit(X_train)
        clf_ocsvm.save(model_path)

    y_pred_ocsvm = clf_ocsvm.predict(X_test_5)
    scores_ocsvm = clf_ocsvm.decision_scores(X_test_5)
    results = {'STEALTHWATCH (OCSVM, 5-feat)':
               compute_metrics(y_test, y_pred_ocsvm, scores_ocsvm)}

    # ---- Supervised RF (if model exists) ----
    rf_path = 'experiments/stealthwatch_supervised.pkl'
    if os.path.exists(rf_path):
        clf_rf = joblib.load(rf_path)
        X_test_6 = np.array([f for d in all_deltas
                              for f in [compute_supervised_features_for_deltas(d)]
                              if f is not None])
        if len(X_test_6) == len(y_test):
            y_pred_rf  = clf_rf.predict(X_test_6)
            probs_rf   = clf_rf.predict_proba(X_test_6)[:, 1]
            m_rf = compute_metrics(y_test, y_pred_rf)
            try:
                m_rf['auc'] = float(roc_auc_score(y_test, probs_rf))
            except Exception:
                m_rf['auc'] = float('nan')
            results['Supervised RF (6-feat, labelled)'] = m_rf
        else:
            print("[WARN] Supervised RF feature count mismatch — skipping.")
    else:
        print("[INFO] No supervised model found. Run src/classifier/train_supervised.py")

    # ---- Baselines ----
    y_pred_iv = np.array([interval_baseline(d) for d in all_deltas])
    y_pred_sh = np.array([shannon_baseline(d)  for d in all_deltas])
    results['Baseline: Interval CV']     = compute_metrics(y_test, y_pred_iv)
    results['Baseline: Shannon Entropy'] = compute_metrics(y_test, y_pred_sh)

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_summary_table():
    print("=" * 60)
    print("  Phase 8: Final Comparative Evaluation")
    print("=" * 60)

    # ---- Per-scenario adversarial table ----
    adv_path = 'experiments/adversarial_results.json'
    if os.path.exists(adv_path):
        with open(adv_path) as f:
            adv = json.load(f)
        df = pd.DataFrame(adv)
        tbl = df[['config', 'CV', 'Skewness', 'SampEn',
                  'detected_ocsvm', 'detected_interval',
                  'detected_shannon']].copy()
        tbl.columns = ['Scenario', 'CV', 'Skewness', 'SampEn',
                       'STEALTHWATCH', 'Baseline:CV', 'Baseline:Shannon']
        for col in ['STEALTHWATCH', 'Baseline:CV', 'Baseline:Shannon']:
            tbl[col] = tbl[col].map({1: 'DETECTED ✓', 0: 'MISSED ✗'})
        print("\n  Per-Scenario Adversarial Detection:")
        print(tbl.to_string(index=False))
        tbl.to_csv('experiments/final_comparison_table.csv', index=False)
        print("\n[OK] → experiments/final_comparison_table.csv")
    else:
        print("[WARN] Run experiments/adversarial_eval.py first.")

    # ---- Full benchmark ----
    print("\n  Running full synthetic benchmark ...")
    bench = run_full_benchmark(n_train=1000, n_test=400)

    print()
    print("  === Table II: Comparative Performance (Synthetic Benchmark) ===")
    print(f"  {'Method':<38} {'Precision':>10} {'Recall':>8} "
          f"{'F1':>8} {'AUC':>8}")
    print("  " + "─" * 76)
    for method, m in bench.items():
        auc_s = f"{m['auc']:.4f}" if m['auc'] == m['auc'] else '   N/A'
        print(f"  {method:<38} {m['precision']:>10.4f} {m['recall']:>8.4f} "
              f"{m['f1']:>8.4f} {auc_s:>8}")

    with open('experiments/benchmark_results.json', 'w') as f:
        json.dump(bench, f, indent=2)
    print("\n[OK] → experiments/benchmark_results.json")


if __name__ == '__main__':
    generate_summary_table()
