# experiments/validate_entropy.py
"""
Phase 3 Validation: Entropy Feature Engine.

Verifies that the 5-feature vector [CV, ApEn, NPE, Skewness, Kurtosis]
correctly separates C2 beaconer timing from organic human traffic.

Expected results
----------------
Signal Type      | CV     | Skewness | Interpretation
-----------------|--------|----------|---------------------------
Regular (0% jit) | ~0.00  | ~0.0     | HIGHLY_REGULAR
Jitter 10%       | ~0.06  | ~0.0     | MODERATELY_REGULAR
Jitter 30%       | ~0.18  | ~0.0     | MODERATELY_REGULAR
Jitter 50%       | ~0.29  | ~0.0     | MODERATELY_REGULAR
Human (Poisson)  | ~1.00  | ~2.0     | HIGH_COMPLEXITY
Adversarial beta | ~0.58  | ~0.0     | AMBIGUOUS / detectable
"""

import os
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.entropy.feature_extractor import EntropyFeatureExtractor


def run_validation(seed: int = 42):
    np.random.seed(seed)
    extractor = EntropyFeatureExtractor(m=2, r_factor=0.2, order=3, window=50)

    print("=" * 60)
    print("  STEALTHWATCH-ZERO: Entropy Feature Engine Validation")
    print("=" * 60)
    print(f"{'Signal':<22} {'CV':>6} {'ApEn':>6} {'NPE':>6} {'Skew':>6} {'Kurt':>6}  Interpretation")
    print("-" * 100)

    # Signal definitions
    signals = [
        ("Regular (0% jit)",  np.ones(200) * 60.0 + np.random.normal(0, 0.05, 200)),
        ("Jitter 10% unif",   60.0 + np.random.uniform(-6, 6, 200)),
        ("Jitter 30% unif",   60.0 + np.random.uniform(-18, 18, 200)),
        ("Jitter 50% unif",   60.0 + np.random.uniform(-30, 30, 200)),
        ("Jitter 30% gauss",  np.maximum(0.1, np.random.normal(60, 18, 200))),
        ("Adversarial (beta)", 60.0 * np.random.beta(0.5, 0.5, 200) + 1.0),
        ("Human (Poisson)",   np.random.exponential(scale=2.0, size=200)),
    ]

    results = {}
    for name, sig in signals:
        desc = extractor.describe(sig)
        results[name] = desc
        print(f"{name:<22} {desc['CV']:>6.3f} {desc['ApEn']:>6.3f} "
              f"{desc['NPE']:>6.4f} {desc['Skewness']:>6.3f} "
              f"{desc['Kurtosis']:>6.3f}  {desc['interpretation']}")

    # ----------------------------------------------------------------
    # Plot 1: CV comparison (primary discriminant)
    # ----------------------------------------------------------------
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('STEALTHWATCH-ZERO: Feature Separation by Signal Type', fontsize=14, fontweight='bold')

    names  = list(results.keys())
    colors = ['#d62728', '#ff7f0e', '#e6a817', '#f5d400',
              '#bcbd22', '#9467bd', '#2ca02c']

    # CV bar
    cv_vals = [results[n]['CV'] for n in names]
    bars = axes[0].bar(range(len(names)), cv_vals, color=colors, edgecolor='black', linewidth=0.8)
    axes[0].axhline(y=0.40, color='navy', linestyle='--', linewidth=2,
                    label='CV threshold = 0.40')
    axes[0].set_xticks(range(len(names)))
    axes[0].set_xticklabels([n.replace(' ', '\n') for n in names], fontsize=8)
    axes[0].set_ylabel('Coefficient of Variation (CV)', fontsize=11)
    axes[0].set_title('CV — Primary Discriminant\n(C2: CV < 0.40 | Human: CV > 0.70)', fontsize=10)
    axes[0].legend(fontsize=9)
    axes[0].set_ylim(0, max(cv_vals) * 1.25)
    for bar, val in zip(bars, cv_vals):
        axes[0].text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                     f'{val:.2f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

    # Skewness bar
    sk_vals = [results[n]['Skewness'] for n in names]
    bars2 = axes[1].bar(range(len(names)), sk_vals, color=colors, edgecolor='black', linewidth=0.8)
    axes[1].axhline(y=1.0, color='navy', linestyle='--', linewidth=2,
                    label='Skewness threshold = 1.0')
    axes[1].set_xticks(range(len(names)))
    axes[1].set_xticklabels([n.replace(' ', '\n') for n in names], fontsize=8)
    axes[1].set_ylabel('Skewness', fontsize=11)
    axes[1].set_title('Skewness — Secondary Discriminant\n(C2: Skew≈0 | Human: Skew≈2)', fontsize=10)
    axes[1].legend(fontsize=9)
    for bar, val in zip(bars2, sk_vals):
        axes[1].text(bar.get_x() + bar.get_width() / 2,
                     bar.get_height() + (0.03 if val >= 0 else -0.15),
                     f'{val:.2f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

    plt.tight_layout()
    os.makedirs('experiments', exist_ok=True)
    plot_path = 'experiments/entropy_validation.png'
    plt.savefig(plot_path, dpi=200, bbox_inches='tight')
    print(f"\n[OK] Validation plot saved → {plot_path}")

    # ----------------------------------------------------------------
    # Key assertion checks
    # ----------------------------------------------------------------
    print("\n--- Assertion Checks ---")
    human_cv    = results['Human (Poisson)']['CV']
    c2_cv_max   = max(results[n]['CV'] for n in names if 'jit' in n.lower() or 'Reg' in n or 'Adv' in n.lower())
    c2_cv_max   = max(results['Regular (0% jit)']['CV'],
                      results['Jitter 30% unif']['CV'],
                      results['Adversarial (beta)']['CV'])

    ok_sep = human_cv > c2_cv_max
    print(f"  Human CV ({human_cv:.3f}) > Max C2 CV ({c2_cv_max:.3f}): "
          f"{'PASS ✓' if ok_sep else 'WARN — overlap detected'}")

    human_skew = results['Human (Poisson)']['Skewness']
    c2_skew    = results['Regular (0% jit)']['Skewness']
    ok_skew    = human_skew > 1.0 and c2_skew < 0.5
    print(f"  Human Skew ({human_skew:.2f}) > 1.0 and C2 Skew ({c2_skew:.2f}) < 0.5: "
          f"{'PASS ✓' if ok_skew else 'WARN'}")

    print("\n[Validation complete]")
    return results


if __name__ == '__main__':
    run_validation()
