# experiments/adversarial_eval.py
"""
Phase 6: Adversarial Robustness Evaluation.

Tests six evasion strategies against STEALTHWATCH-ZERO and two baselines.

Detection strategy comparison:
  - STEALTHWATCH (OCSVM on 5-feature [CV,ApEn,NPE,Skew,Kurt])
  - Baseline: Interval CV threshold (flags CV < 0.15 only)
  - Baseline: Shannon entropy of binned IAT histogram

Adversarial configurations:
  AE1: Fixed (0% jitter)      — trivially detected by all
  AE2: Mild (10% jitter)      — baselines start missing
  AE3: Standard (30% jitter)  — baselines miss; STEALTHWATCH detects
  AE4: Gaussian (30%)         — different distribution, same CV range
  AE5: Bounded Exp (50%)      — realistic exponential with keepalive bound
  AE6: Max-Entropy Beta (50%) — hardest adversarial mode (U-shaped beta)

Note on unbounded exponential: expovariate(1/B) produces CV~1.0, identical
to human traffic AND violates C2 keepalive constraints (max Δt >> timeout).
Real C2 tools cap exponential jitter — we model that with bounded exponential.
"""

import os
import sys
import json
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.classifier.ocsvm import StealthwatchClassifier, generate_synthetic_features
from src.entropy.feature_extractor import EntropyFeatureExtractor
from src.beaconer.beaconer import C2Beaconer
from baselines.simple_interval import interval_baseline, shannon_baseline


# Set seed for reproducibility
np.random.seed(42)
import random as _rand; _rand.seed(42)

def simulate_beaconer_deltas(interval, jitter, jitter_mode, n_beacons):
    """Generate timing deltas without real TCP connections."""
    b = C2Beaconer('127.0.0.1', 8443,
                   interval=interval, jitter=jitter,
                   jitter_mode=jitter_mode, n_beacons=n_beacons)
    return np.array([b._compute_sleep_time() for _ in range(n_beacons)])


def run_adversarial_eval():
    print("=" * 65)
    print("  Phase 6: Adversarial Robustness Evaluation")
    print("=" * 65)

    # Load or train model
    model_path = 'experiments/stealthwatch_model.pkl'
    if os.path.exists(model_path):
        clf = StealthwatchClassifier.load(model_path)
    else:
        print("[INFO] Training model on synthetic benign data...")
        X_train = generate_synthetic_features(1500, 'benign')
        clf = StealthwatchClassifier(nu=0.05)
        clf.fit(X_train)
        clf.save(model_path)

    extractor = EntropyFeatureExtractor(window=50)

    ADVERSARIAL_CONFIGS = [
        ('AE1: Fixed (0% jitter)',       dict(interval=60, jitter=0.00, jitter_mode='uniform',        n_beacons=150)),
        ('AE2: Mild (10% uniform)',      dict(interval=60, jitter=0.10, jitter_mode='uniform',        n_beacons=150)),
        ('AE3: Standard (30% uniform)',  dict(interval=60, jitter=0.30, jitter_mode='uniform',        n_beacons=150)),
        ('AE4: Gaussian (30%)',          dict(interval=60, jitter=0.30, jitter_mode='gaussian',       n_beacons=150)),
        ('AE5: Bounded-Exp 50% [limit]', dict(interval=60, jitter=0.50, jitter_mode='exponential',   n_beacons=150)),
        ('AE6: Max-Entropy Beta (50%)',  dict(interval=60, jitter=0.50, jitter_mode='adversarial_max',n_beacons=150)),
    ]

    results = []

    print(f"\n  {'Scenario':<32} {'CV':>5} {'Skew':>6}  STEALTHWATCH  Interval-CV  Shannon")
    print("  " + "─" * 78)

    for name, params in ADVERSARIAL_CONFIGS:
        deltas = simulate_beaconer_deltas(**params)

        feat = extractor.compute_features(deltas)
        if feat is None:
            print(f"  {name:<32}  [WARN: too few samples]")
            continue

        pred_ocsvm    = int(clf.predict(feat.reshape(1, -1))[0])
        score         = float(clf.decision_scores(feat.reshape(1, -1))[0])
        pred_interval = int(interval_baseline(deltas))
        pred_shannon  = int(shannon_baseline(deltas))

        sw_str = 'DETECTED ✓' if pred_ocsvm    else 'MISSED   ✗'
        iv_str = 'DETECTED ✓' if pred_interval else 'MISSED   ✗'
        sh_str = 'DETECTED ✓' if pred_shannon  else 'MISSED   ✗'

        print(f"  {name:<32} {feat[0]:>5.3f} {feat[3]:>6.2f}  {sw_str:<14}{iv_str:<13}{sh_str}")

        results.append({
            'config':            name,
            'CV':                round(float(feat[0]), 4),
            'ApEn':              round(float(feat[1]), 4),
            'NPE':               round(float(feat[2]), 4),
            'Skewness':          round(float(feat[3]), 4),
            'Kurtosis':          round(float(feat[4]), 4),
            'SampEn':            round(extractor.compute_sampen(deltas), 4),
            'ocsvm_score':       round(score, 4),
            'detected_ocsvm':    pred_ocsvm,
            'detected_interval': pred_interval,
            'detected_shannon':  pred_shannon,
        })

    # Summary
    total = len(results)
    dr_sw = sum(r['detected_ocsvm']    for r in results)
    dr_iv = sum(r['detected_interval'] for r in results)
    dr_sh = sum(r['detected_shannon']  for r in results)

    print(f"\n  {'─'*50}")
    print(f"  STEALTHWATCH (OCSVM)  : {dr_sw}/{total}  ({dr_sw/total:.0%})")
    print(f"  Baseline Interval-CV  : {dr_iv}/{total}  ({dr_iv/total:.0%})")
    print(f"  Baseline Shannon      : {dr_sh}/{total}  ({dr_sh/total:.0%})")
    print(f"  {'─'*50}")

    
    print()
    print("  Note: AE5 (Bounded-Exp 50%) is the fundamental detection limit.")
    print("  At J=50%, bounded-exp produces CV~0.7-0.9, overlapping the benign")
    print("  region. The theoretical bound (CV <= J/sqrt(3) <= 0.289) still holds")
    print("  for the uniform-jitter threat model — this is the honest edge case.")

    out = 'experiments/adversarial_results.json'
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[OK] Results saved → {out}")
    return results


if __name__ == '__main__':
    run_adversarial_eval()
