# baselines/simple_interval.py
import numpy as np

def interval_baseline(deltas, threshold_cv=0.15):
    """
    Coefficient of Variation (CV) baseline.
    Low CV = regular = C2.
    """
    if len(deltas) == 0:
        return 0
    cv = np.std(deltas) / np.mean(deltas) if np.mean(deltas) > 0 else 0
    return 1 if cv < threshold_cv else 0

def shannon_baseline(deltas, n_bins=20, threshold=2.0):
    """
    Shannon entropy of binned inter-arrival times.
    """
    if len(deltas) < 2:
        return 0
    hist, _ = np.histogram(deltas, bins=n_bins, density=True)
    hist = hist[hist > 0]
    shannon = -np.sum(hist * np.log2(hist))
    return 1 if shannon < threshold else 0
