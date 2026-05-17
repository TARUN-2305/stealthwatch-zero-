# src/classifier/ocsvm.py
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             roc_auc_score, confusion_matrix)
import joblib
import os
import sys

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.entropy.feature_extractor import EntropyFeatureExtractor

def optimized_load_and_group(path):
    print("Reading CSV...")
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    df['is_malicious'] = df['Label'].str.contains('Botnet', na=False).astype(int)
    df['timestamp'] = pd.to_datetime(df['StartTime']).view('int64') // 10**9

    print(f"Processing {len(df)} flows...")
    # Group by Host and Connection, then collect timestamps into lists
    grouped = df.sort_values('timestamp').groupby(['SrcAddr', 'DstAddr', 'Dport'])

    # Filter connection groups with enough packets (minimum 20)
    agg_df = grouped.agg(
        deltas=('timestamp', lambda x: np.diff(x.values) if len(x) >= 20 else None),
        label=('is_malicious', 'max')
    ).dropna()

    return agg_df

class StealthwatchClassifier:
    """
    One-Class SVM trained exclusively on benign traffic.
    """
    
    def __init__(self, nu=0.05, kernel='rbf', gamma='scale'):
        self.nu = nu
        self.ocsvm = OneClassSVM(nu=nu, kernel=kernel, gamma=gamma)
        self.scaler = StandardScaler()
        self.trained = False
    
    def fit(self, X_benign: np.ndarray):
        """Train only on benign samples."""
        X_scaled = self.scaler.fit_transform(X_benign)
        self.ocsvm.fit(X_scaled)
        self.trained = True
        return self
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict: 0 = benign, 1 = anomaly (C2)
        """
        X_scaled = self.scaler.transform(X)
        raw_pred = self.ocsvm.predict(X_scaled)
        return (raw_pred == -1).astype(int)
    
    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        """Return raw decision scores (lower = more anomalous)."""
        X_scaled = self.scaler.transform(X)
        return self.ocsvm.decision_function(X_scaled)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, label: str = 'Test'):
        y_pred = self.predict(X_test)
        scores = self.decision_scores(X_test)
        
        # ROC-AUC: invert scores because lower score = more likely anomaly
        auc = roc_auc_score(y_test, -scores)
        
        metrics = {
            'label': label,
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1': float(f1_score(y_test, y_pred, zero_division=0)),
            'auc': float(auc),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
        }
        
        print(f"\n=== {label} ===")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1:        {metrics['f1']:.4f}")
        print(f"  ROC-AUC:   {metrics['auc']:.4f}")
        
        return metrics
    
    def save(self, path='experiments/stealthwatch_model.pkl'):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({'ocsvm': self.ocsvm, 'scaler': self.scaler, 'nu': self.nu}, path)
    
    @classmethod
    def load(cls, path='experiments/stealthwatch_model.pkl'):
        data = joblib.load(path)
        obj = cls(nu=data['nu'])
        obj.ocsvm = data['ocsvm']
        obj.scaler = data['scaler']
        obj.trained = True
        return obj

if __name__ == "__main__":
    data_path = 'data/raw/CTU-13/scenario1.labeled'
    
    if os.path.exists(data_path):
        agg_df = optimized_load_and_group(data_path)
        extractor = EntropyFeatureExtractor(window=50)
        benign_feats, malicious_feats = [], []

        print("Extracting entropy features...")
        for _, row in agg_df.iterrows():
            deltas = row['deltas']
            deltas = deltas[deltas > 0]
            if len(deltas) >= 15:
                f = extractor.compute_features(deltas)
                if f is not None:
                    if row['label'] == 1: malicious_feats.append(f)
                    else: benign_feats.append(f)

        print(f"Extracted Benign: {len(benign_feats)}, Malicious: {len(malicious_feats)}")
        X_benign = np.array(benign_feats)
        split = int(0.8 * len(X_benign))
        X_train, X_test_benign = X_benign[:split], X_benign[split:]
        X_test = np.vstack([X_test_benign, malicious_feats])
        y_test = np.hstack([np.zeros(len(X_test_benign)), np.ones(len(malicious_feats))])
    else:
        print(f"Data file {data_path} not found. Running on synthetic data.")
        def generate_synthetic_features(n_samples=500, mode='benign'):
            extractor = EntropyFeatureExtractor(window=50)
            features = []
            for _ in range(n_samples):
                if mode == 'benign':
                    deltas = np.random.exponential(scale=random.uniform(0.1, 5.0), size=100)
                else:
                    interval = random.uniform(10.0, 60.0)
                    jitter = random.uniform(0.0, 0.3)
                    deltas = interval + np.random.uniform(-jitter*interval, jitter*interval, size=100)
                feat = extractor.compute_features(deltas)
                if feat is not None: features.append(feat)
            return np.array(features)
        
        import random
        X_train = generate_synthetic_features(mode='benign')
        X_test_benign = generate_synthetic_features(n_samples=100, mode='benign')
        X_test_malicious = generate_synthetic_features(n_samples=100, mode='malicious')
        X_test = np.vstack([X_test_benign, X_test_malicious])
        y_test = np.hstack([np.zeros(len(X_test_benign)), np.ones(len(X_test_malicious))])

    clf = StealthwatchClassifier(nu=0.05)
    clf.fit(X_train)
    clf.evaluate(X_test, y_test, label='Detection Test Set')
    clf.save()
    print("\nModel saved to experiments/stealthwatch_model.pkl")
