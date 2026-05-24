# src/entropy/feature_extractor.py
"""
Entropy Feature Extractor for STEALTHWATCH-ZERO.

Computes a 5-dimensional feature vector from a timing delta sequence.

  CV    : Coefficient of Variation = std/mean (PRIMARY discriminant).
          C2 beacons (bounded jitter): CV ≤ J/√3 ≤ 0.289 for J≤50%.
          Human traffic (Poisson):     CV ≈ 1.0.
          Scale-invariant; parameter-free; provably bounded for any C2.

  ApEn  : Approximate Entropy (Pincus 1991) — regularity of temporal patterns.
          Lower → more regular → more automated. Computed with antropy.

  NPE   : Normalized Permutation Entropy (Bandt & Pompe 2002) — ordinal
          pattern diversity. O(N log N), robust to noise.

  Skew  : Skewness of the IAT distribution.
          Exponential (human): Skew ≈ 2.  Bounded uniform (C2): Skew ≈ 0.

  Kurt  : Excess kurtosis.
          Exponential (human): Kurt ≈ 6.  Bounded uniform (C2): Kurt ≈ −1.2.

NOTE ON SampEn: antropy.sample_entropy uses absolute Chebyshev distance.
For sequences with different absolute magnitudes (2s vs 120s intervals)
the values are incomparable without explicit tolerance. SampEn is exposed
via compute_sampen() for the theoretical bound section (§IV) with explicit
r=r_factor*std, but is NOT part of the 5-feature classifier vector.
CV is the provably correct primary discriminant.
"""

import warnings
import numpy as np
import antropy as ant
from scipy.stats import skew as scipy_skew, kurtosis as scipy_kurtosis
from typing import Optional


class EntropyFeatureExtractor:
    """
    5-dimensional temporal entropy feature extractor.

    Parameters
    ----------
    m : int         ApEn/SampEn template length (embedding dimension). Default: 2.
    r_factor : float  Tolerance factor for SampEn: r = r_factor * std. Default: 0.2.
    order : int     Permutation entropy order (window of ordinal patterns). Default: 3.
    window : int    Number of timing deltas per feature computation. Default: 50.
    """

    FEATURE_NAMES = ['CV', 'ApEn', 'NPE', 'Skewness', 'Kurtosis']
    N_FEATURES    = 5

    def __init__(self, m: int = 2, r_factor: float = 0.2,
                 order: int = 3, window: int = 50):
        self.m        = m
        self.r_factor = r_factor
        self.order    = order
        self.window   = window

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def compute_features(self, deltas: np.ndarray) -> Optional[np.ndarray]:
        """
        Compute the 5-dimensional feature vector [CV, ApEn, NPE, Skew, Kurt].

        Returns None if len(deltas) < self.window.
        Returns all-zeros for degenerate (near-constant) sequences, with
        CV=0 correctly flagging them as highly regular (C2).
        """
        if len(deltas) < self.window:
            return None

        seq  = np.asarray(deltas[-self.window:], dtype=float)
        mean = float(np.mean(seq))
        std  = float(np.std(seq))

        if mean < 1e-12:
            return np.zeros(self.N_FEATURES)

        cv = std / mean

        # Degenerate case: near-constant sequence (e.g. fixed-interval beaconer)
        # scipy.stats.skew/kurtosis raise catastrophic cancellation warnings here.
        # Return analytically correct values: CV≈0, Skew=0, Kurt=-1.2 (uniform limit)
        if std / mean < 1e-4:
            apen = 0.0
            try:
                npe = float(ant.perm_entropy(seq, order=self.order, normalize=True))
            except Exception:
                npe = 0.0
            features = np.array([cv, apen, npe, 0.0, -1.2], dtype=float)
            return np.nan_to_num(features, nan=0.0, posinf=10.0, neginf=-10.0)

        # 2. ApEn
        try:
            apen = float(ant.app_entropy(seq, order=self.m))
        except Exception:
            apen = 0.0

        # 3. NPE
        try:
            npe = float(ant.perm_entropy(seq, order=self.order, normalize=True))
        except Exception:
            npe = 0.0

        # 4. Skewness
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', RuntimeWarning)
            try:
                sk = float(scipy_skew(seq))
            except Exception:
                sk = 0.0

        # 5. Excess Kurtosis
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', RuntimeWarning)
            try:
                kurt = float(scipy_kurtosis(seq, fisher=True))
            except Exception:
                kurt = 0.0

        features = np.array([cv, apen, npe, sk, kurt], dtype=float)
        features = np.nan_to_num(features, nan=0.0, posinf=10.0, neginf=-10.0)
        return features

    def compute_sampen(self, deltas: np.ndarray) -> float:
        """
        Sample Entropy with explicit tolerance r = r_factor * std.
        For theoretical bound validation ONLY — not used in classifier.
        """
        if len(deltas) < self.window:
            return 0.0
        seq = np.asarray(deltas[-self.window:], dtype=float)
        std = np.std(seq)
        tol = self.r_factor * std
        try:
            se = float(ant.sample_entropy(
                seq, order=self.m,
                tolerance=float(tol) if tol > 0 else None))
        except Exception:
            se = 0.0
        return float(np.nan_to_num(se, nan=0.0, posinf=10.0))

    def compute_sliding_features(self, deltas: np.ndarray,
                                 step: int = 10) -> np.ndarray:
        """Feature vectors over a sliding window. Returns (T, 5) array."""
        features = []
        for i in range(self.window, len(deltas) + 1, step):
            feat = self.compute_features(deltas[max(0, i - self.window):i])
            if feat is not None:
                features.append(feat)
        return np.array(features) if features else np.empty((0, self.N_FEATURES))

    def describe(self, deltas: np.ndarray) -> dict:
        """Human-readable dict of all features for a timing sequence."""
        feat = self.compute_features(deltas)
        if feat is None:
            return {'error': f'Too short: need {self.window}, got {len(deltas)}'}
        sampen = self.compute_sampen(deltas)
        return {
            'CV':           round(float(feat[0]), 4),
            'ApEn':         round(float(feat[1]), 4),
            'NPE':          round(float(feat[2]), 4),
            'Skewness':     round(float(feat[3]), 4),
            'Kurtosis':     round(float(feat[4]), 4),
            'SampEn':       round(sampen, 4),
            'n_samples':    len(deltas),
            'mean_delta_s': round(float(np.mean(deltas)), 4),
            'std_delta_s':  round(float(np.std(deltas)), 4),
            'interpretation': self._interpret(feat),
        }

    def _interpret(self, feat: np.ndarray) -> str:
        cv = feat[0]; sk = feat[3]
        if cv < 0.15:
            return 'HIGHLY_REGULAR — almost certainly automated (C2/bot)'
        elif cv < 0.40 and sk < 0.8:
            return 'MODERATELY_REGULAR — probable beaconing (verify)'
        elif cv > 0.70 and sk > 1.0:
            return 'HIGH_COMPLEXITY — consistent with organic human traffic'
        else:
            return 'AMBIGUOUS — further context needed'
