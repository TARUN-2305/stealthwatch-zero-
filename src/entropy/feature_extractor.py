# src/entropy/feature_extractor.py
import numpy as np
import antropy as ant
from typing import Optional, Tuple

class EntropyFeatureExtractor:
    """
    Computes a 3-dimensional entropy feature vector for a timing delta sequence.
    
    Features:
        ApEn  : Approximate Entropy (Pincus 1991)
        SampEn: Sample Entropy (Richman & Moorman 2000)
        NPE   : Normalized Permutation Entropy (Bandt & Pompe 2002)
    """
    
    def __init__(self, m=2, r_factor=0.2, order=3, window=50):
        self.m = m
        self.r_factor = r_factor
        self.order = order
        self.window = window
    
    def compute_features(self, deltas: np.ndarray) -> Optional[np.ndarray]:
        """
        Compute entropy feature vector for a timing delta array.
        """
        if len(deltas) < self.window:
            return None
        
        # Use last `window` samples for sliding window computation
        seq = deltas[-self.window:]
        
        # Normalize to avoid issues with absolute values
        seq_std = np.std(seq)
        if seq_std < 1e-10:
            # Constant sequence (perfectly regular)
            return np.array([0.0, 0.0, 0.0])
        
        # Compute tolerance r for ApEn/SampEn
        r = self.r_factor * seq_std
        
        try:
            # Using antropy library
            apen = ant.app_entropy(seq, order=self.m)
        except Exception:
            apen = 0.0
        
        try:
            sampen = ant.sample_entropy(seq, order=self.m)
        except Exception:
            sampen = 0.0
        
        try:
            npe = ant.perm_entropy(seq, order=self.order, normalize=True)
        except Exception:
            npe = 0.0
        
        # Handle NaN/Inf values
        features = np.array([apen, sampen, npe])
        features = np.nan_to_num(features, nan=0.0, posinf=10.0, neginf=0.0)
        
        return features
    
    def compute_sliding_features(self, deltas: np.ndarray, step: int = 10) -> np.ndarray:
        """
        Compute entropy features over a sliding window across the full sequence.
        """
        features = []
        for i in range(self.window, len(deltas) + 1, step):
            window_seq = deltas[max(0, i - self.window):i]
            feat = self.compute_features(window_seq)
            if feat is not None:
                features.append(feat)
        
        return np.array(features) if features else np.empty((0, 3))
    
    def describe(self, deltas: np.ndarray) -> dict:
        """Return human-readable description of features."""
        feat = self.compute_features(deltas)
        if feat is None:
            return {'error': 'Sequence too short'}
        
        return {
            'ApEn': round(float(feat[0]), 4),
            'SampEn': round(float(feat[1]), 4),
            'NPE': round(float(feat[2]), 4),
            'n_samples': len(deltas),
            'mean_delta_s': round(float(np.mean(deltas)), 3),
            'std_delta_s': round(float(np.std(deltas)), 3),
            'interpretation': self._interpret(feat)
        }
    
    def _interpret(self, feat: np.ndarray) -> str:
        sampen = feat[1]
        if sampen < 0.3:
            return 'HIGHLY_REGULAR (likely automated/C2)'
        elif sampen < 0.8:
            return 'MODERATE_REGULARITY (possible beaconing)'
        else:
            return 'HIGH_COMPLEXITY (likely organic traffic)'
