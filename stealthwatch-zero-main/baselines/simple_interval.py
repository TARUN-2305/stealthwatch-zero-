# baselines/simple_interval.py
"""
Baseline detectors for STEALTHWATCH-ZERO comparative evaluation.

These represent the state of practice BEFORE entropy-based detection:
  - interval_baseline: Flags low coefficient of variation (simple statistics)
  - shannon_baseline:  Flags low Shannon entropy of binned IAT distribution

Both fail on heavy jitter because they use single-distribution statistics
rather than the complexity structure of the timing sequence.
"""

import numpy as np


def interval_baseline(deltas: np.ndarray,
                      threshold_cv: float = 0.15) -> int:
    """
    Coefficient of Variation (CV) baseline.

    Flags traffic as C2 if cv = std(deltas)/mean(deltas) < threshold_cv.
    Threshold 0.15 from Netskope C2 Beaconing white paper (2024).

    Limitation: a 30% jitter beaconer produces CV ≈ 0.17, which is ABOVE
    the threshold → missed detection. This is exactly the adversarial gap
    that STEALTHWATCH-ZERO's OCSVM closes by using multi-feature context.

    Returns
    -------
    int  1 = detected C2, 0 = benign
    """
    if len(deltas) == 0:
        return 0
    mean = np.mean(deltas)
    if mean < 1e-12:
        return 0
    cv = np.std(deltas) / mean
    return 1 if cv < threshold_cv else 0


def shannon_baseline(deltas: np.ndarray,
                     n_bins: int = 20,
                     threshold: float = 2.0) -> int:
    """
    Shannon entropy of binned inter-arrival time distribution.

    Flags traffic as C2 if the entropy of the IAT histogram is low,
    indicating a concentrated (regular) distribution.

    Limitation: a 30% uniform jitter beaconer fills all bins roughly
    equally → HIGH Shannon entropy → missed detection.

    Returns
    -------
    int  1 = detected C2, 0 = benign
    """
    if len(deltas) < 2:
        return 0
    hist, _ = np.histogram(deltas, bins=n_bins, density=True)
    hist = hist[hist > 0]
    shannon = -np.sum(hist * np.log2(hist + 1e-12))
    return 1 if shannon < threshold else 0


def ja3_baseline(ja3_hash: str,
                 known_malicious: set) -> int:
    """
    JA3 TLS fingerprint hash lookup.

    Flags traffic as C2 if the JA3 hash matches a known-malicious signature.
    Trivially bypassed by spoofing TLS ClientHello fields.

    Returns
    -------
    int  1 = detected, 0 = not detected
    """
    return 1 if ja3_hash in known_malicious else 0
