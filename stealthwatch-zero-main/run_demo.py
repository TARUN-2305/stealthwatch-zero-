#!/usr/bin/env python3
# run_demo.py
"""
STEALTHWATCH-ZERO — Live Proof-of-Concept Demo
==============================================
Simulates a C2 attack with adversarial jitter and shows real-time detection.

Usage:
    python run_demo.py [--interval N] [--jitter F] [--mode MODE] [--beacons N]

Examples:
    python run_demo.py                         # default: 5s interval, 30% jitter
    python run_demo.py --jitter 0.5            # hard: 50% jitter
    python run_demo.py --mode adversarial_max  # hardest: max-entropy adversarial

How it works (no root/admin needed):
  1. Simulates beaconer timing deltas using the exact same algorithm as a
     real C2 implant (without real TCP connections, for portability).
  2. Runs the STEALTHWATCH entropy engine on the simulated timing sequence.
  3. Classifies using the trained One-Class SVM.
  4. Compares against two naive baselines to show the research advantage.
"""

import os
import sys
import time
import json
import argparse
import numpy as np

# Ensure imports work from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.entropy.feature_extractor import EntropyFeatureExtractor
from src.beaconer.beaconer import C2Beaconer
from src.classifier.ocsvm import StealthwatchClassifier, generate_synthetic_features
from src.theory.entropy_bound import cv_upper_bound, sampen_upper_bound
from baselines.simple_interval import interval_baseline, shannon_baseline


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

BANNER = r"""
 ____  _                  _ _   ___          __    _       _     ______
/ ___|| |_ ___  __ _ _ __| | |_| \ \        / /_ _| |_ ___| |__ |__  / ___ _ __ ___
\___ \| __/ _ \/ _` | '__| | __| |\ \ /\ / / _` | __/ __| '_ \  / / / _ \ '__/ _ \
 ___) | ||  __/ (_| | |  | | |_| | \ V  V / (_| | || (__| | | |/ /__|  __/ | | (_) |
|____/ \__\___|\__,_|_|  |_|\__|_|  \_/\_/ \__,_|\__\___|_| |_/____|\___| |  \___/
                                                                          |_|
 Adversarially-Robust C2 Beaconing Detection via Temporal Entropy Analysis
 CS362IA — Network Programming and Security  |  RV College of Engineering
"""

def banner():
    print(BANNER)

def section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")

def ok(msg):   print(f"  [✓] {msg}")
def info(msg): print(f"  [·] {msg}")
def warn(msg): print(f"  [!] {msg}")


# ---------------------------------------------------------------------------
# Core demo logic
# ---------------------------------------------------------------------------

def ensure_model(model_path: str, n_train: int = 1500) -> StealthwatchClassifier:
    """Load existing model or train fresh on synthetic benign data."""
    if os.path.exists(model_path):
        clf = StealthwatchClassifier.load(model_path)
        ok(f"Model loaded from {model_path}")
    else:
        info(f"Model not found at {model_path} — training on {n_train} synthetic benign samples...")
        X_train = generate_synthetic_features(n_train, 'benign')
        clf = StealthwatchClassifier(nu=0.05)
        clf.fit(X_train)
        clf.save(model_path)
        ok(f"Model trained and saved to {model_path}")
    return clf


def simulate_attack(interval: float, jitter: float,
                    jitter_mode: str, n_beacons: int,
                    verbose: bool = True) -> np.ndarray:
    """Generate beaconer timing deltas (simulated, no real TCP needed)."""
    b = C2Beaconer('127.0.0.1', 8443,
                   interval=interval, jitter=jitter,
                   jitter_mode=jitter_mode, n_beacons=n_beacons)
    deltas = []
    for i in range(n_beacons):
        dt = b._compute_sleep_time()
        deltas.append(dt)
        if verbose and (i % 10 == 0 or i == n_beacons - 1):
            bar = '█' * (i * 30 // n_beacons) + '░' * (30 - i * 30 // n_beacons)
            print(f"\r  Simulating beacons [{bar}] {i+1}/{n_beacons}  Δt={dt:.2f}s ", end='', flush=True)
    print()
    return np.array(deltas)


def simulate_human() -> np.ndarray:
    """Generate human-like traffic timing (Poisson/exponential)."""
    scale = np.random.uniform(1.0, 5.0)
    return np.random.exponential(scale=scale, size=120)


def print_detection_report(label: str, deltas: np.ndarray,
                            clf: StealthwatchClassifier,
                            extractor: EntropyFeatureExtractor,
                            ground_truth: int):
    """
    Print a formatted detection report for one timing sequence.
    ground_truth: 1 = actually C2, 0 = actually benign
    """
    feat = extractor.compute_features(deltas)
    if feat is None:
        warn(f"Could not extract features for {label} (too few samples).")
        return

    desc = extractor.describe(deltas)
    pred = int(clf.predict(feat.reshape(1, -1))[0])
    score = float(clf.decision_scores(feat.reshape(1, -1))[0])

    # Baselines
    pred_interval = interval_baseline(deltas)
    pred_shannon  = shannon_baseline(deltas)

    status_sw  = 'MALICIOUS BEACONING DETECTED' if pred     else 'BENIGN (not flagged)'
    status_iv  = 'MALICIOUS BEACONING DETECTED' if pred_interval else 'BENIGN (not flagged)'
    status_sh  = 'MALICIOUS BEACONING DETECTED' if pred_shannon  else 'BENIGN (not flagged)'
    correct    = (pred == ground_truth)

    icon_sw = '✓' if correct else '✗'

    W = 62  # inner box width (between the ║ chars)
    def row(label, val, w=W):
        inner = f"  {label}: {str(val)}"
        return f"  ║{inner:<{w}}║"
    def row_val(label, val, label_w=18, val_w=40):
        inner = f"  {label:<{label_w}}: {str(val):<{val_w}}"
        return f"  ║{inner:<{W}}║"
    def sep():
        return f"  ╠{'═'*W}╣"
    def blank():
        return f"  ║{' '*W}║"

    interp = desc['interpretation']
    # Wrap interpretation if too long
    if len(interp) > 56:
        interp = interp[:56] + '…'

    lines = [
        f"  ╔{'═'*W}╗",
        f"  ║  DETECTION REPORT — {label:<{W-22}}║",
        sep(),
        row_val('Ground Truth   ', 'C2 BEACONER' if ground_truth else 'BENIGN TRAFFIC'),
        row_val('n_samples      ', desc['n_samples']),
        row_val('Mean IAT (s)   ', desc['mean_delta_s']),
        blank(),
        row_val('CV  (primary)  ', desc['CV']),
        row_val('Skewness       ', desc['Skewness']),
        row_val('ApEn           ', desc['ApEn']),
        row_val('NPE            ', desc['NPE']),
        row_val('Kurtosis       ', desc['Kurtosis']),
        row_val('SampEn (info)  ', desc['SampEn']),
        blank(),
        row_val('Interpretation ', interp),
        sep(),
        row_val(f'STEALTHWATCH [{icon_sw}]', status_sw),
        row_val(f"Baseline CV  [{'✓' if pred_interval==ground_truth else '✗'}]", status_iv),
        row_val(f"Baseline Sh  [{'✓' if pred_shannon==ground_truth else '✗'}]", status_sh),
        f"  ╚{'═'*W}╝",
    ]
    print("\n".join(lines))


def print_theory_summary(interval: float, jitter: float):
    """Print the theoretical bound for the chosen beaconer config."""
    section("Theoretical Bound (§IV of research paper)")
    cv_bound = cv_upper_bound(jitter)
    s_star   = sampen_upper_bound(interval, jitter)
    print(f"  Beaconer config  : B={interval}s, J={jitter*100:.0f}% uniform jitter")
    print(f"  CV upper bound   : J/√3 = {jitter:.2f}/√3 = {cv_bound:.4f}")
    print(f"  SampEn bound S*  : {s_star:.4f}")
    print(f"  Human traffic CV : ~1.000 (exponential distribution)")
    print(f"  Detection margin : {1.0 - cv_bound:.3f}  ({(1.0/cv_bound):.1f}× ratio)")
    print()
    print("  Result: ANY reliable C2 beaconer (J ≤ 50%) has CV ≤ 0.289,")
    print("  well below human traffic CV ~1.0. The OCSVM boundary at CV~0.40")
    print("  provably separates all reliable C2 from organic human traffic.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='STEALTHWATCH-ZERO: Live PoC Demo',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--interval', type=float, default=5.0,
                        help='Beaconer base interval in seconds')
    parser.add_argument('--jitter',   type=float, default=0.30,
                        help='Jitter fraction 0.0–0.5 (0.3 = 30%%)')
    parser.add_argument('--mode',     default='uniform',
                        choices=['uniform', 'gaussian', 'exponential', 'adversarial_max'],
                        help='Jitter distribution mode')
    parser.add_argument('--beacons',  type=int, default=80,
                        help='Number of beacon intervals to simulate')
    parser.add_argument('--seed',     type=int, default=42)
    args = parser.parse_args()

    np.random.seed(args.seed)

    # ----------------------------------------------------------------
    banner()

    section("Step 1: Loading / Training Classifier")
    model_path = 'experiments/stealthwatch_model.pkl'
    clf = ensure_model(model_path)

    extractor = EntropyFeatureExtractor(window=50)

    # ----------------------------------------------------------------
    section("Step 2: Simulating C2 Attack Traffic")
    info(f"Beaconer: interval={args.interval}s, jitter={args.jitter*100:.0f}%, "
         f"mode={args.mode}, n_beacons={args.beacons}")
    info("(Simulated — no real TCP connections needed)")

    c2_deltas = simulate_attack(
        interval=args.interval, jitter=args.jitter,
        jitter_mode=args.mode, n_beacons=args.beacons)
    ok(f"Generated {len(c2_deltas)} C2 timing intervals")

    # ----------------------------------------------------------------
    section("Step 3: Simulating Benign Human Traffic")
    human_deltas = simulate_human()
    ok(f"Generated {len(human_deltas)} human timing intervals (Poisson process)")

    # ----------------------------------------------------------------
    section("Step 4: Detection Reports")

    print_detection_report(
        f"C2 Beacon (J={args.jitter*100:.0f}%, {args.mode})",
        c2_deltas, clf, extractor, ground_truth=1)

    print_detection_report(
        "Benign Human Traffic",
        human_deltas, clf, extractor, ground_truth=0)

    # ----------------------------------------------------------------
    section("Step 5: Adversarial Stress Test")
    info("Testing 6 evasion strategies in one shot...")
    print()

    CONFIGS = [
        ('Fixed (0% jitter)',     0.00, 'uniform'),
        ('Mild (10% jitter)',     0.10, 'uniform'),
        ('Standard (30% jitter)', 0.30, 'uniform'),
        ('Gaussian (30%)',        0.30, 'gaussian'),
        ('Exponential (50%)',     0.50, 'exponential'),
        ('Max-Entropy (50%)',     0.50, 'adversarial_max'),
    ]

    print(f"  {'Scenario':<30} {'CV':>6} {'Skew':>6}  STEALTHWATCH   Interval-CV   Shannon")
    print("  " + "─" * 80)

    sw_correct = 0
    for name, j, mode in CONFIGS:
        d = simulate_attack(args.interval, j, mode, 80, verbose=False)
        feat = extractor.compute_features(d)
        if feat is None:
            continue
        cv = feat[0]; sk = feat[3]
        pred = int(clf.predict(feat.reshape(1, -1))[0])
        pi   = interval_baseline(d)
        ps   = shannon_baseline(d)

        sw_str = 'DETECTED ✓' if pred else 'MISSED   ✗'
        iv_str = 'DETECTED ✓' if pi   else 'MISSED   ✗'
        sh_str = 'DETECTED ✓' if ps   else 'MISSED   ✗'

        if pred == 1:
            sw_correct += 1

        print(f"  {name:<30} {cv:>6.3f} {sk:>6.2f}  {sw_str:<15}{iv_str:<14}{sh_str}")

    print()
    print(f"  STEALTHWATCH detection rate : {sw_correct}/{len(CONFIGS)}")

    # ----------------------------------------------------------------
    print_theory_summary(args.interval, args.jitter)

    # ----------------------------------------------------------------
    section("Demo Complete")
    print("  Outputs produced:")
    print(f"    experiments/stealthwatch_model.pkl — trained OCSVM model")
    print()
    print("  Next steps:")
    print("    python experiments/validate_entropy.py   — feature validation plots")
    print("    python experiments/adversarial_eval.py   — detailed adversarial results")
    print("    python experiments/final_evaluation.py   — full benchmark table")
    print("    python src/theory/entropy_bound.py       — theoretical bound analysis")
    print()
    print("  Documentation:")
    print("    README.md                               — quick start")
    print("    STEALTHWATCH_ZERO_Full_Research_Plan.md — full 12-week blueprint")
    print()


if __name__ == '__main__':
    main()
