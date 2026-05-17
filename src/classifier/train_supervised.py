# src/classifier/train_supervised.py
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, roc_auc_score
import joblib
import os
import glob
from scipy.stats import entropy

def extract_features(group):
    # Inter-arrival timing deltas
    deltas = np.diff(group['timestamp'].values)
    deltas = deltas[deltas > 0]
    if len(deltas) < 5: 
        return None

    # Compute features matching the breakthrough notebook
    # 1. Shannon Entropy of 10-bin timing histogram
    hist_counts, _ = np.histogram(deltas, bins=10, density=True)
    ent_val = entropy(hist_counts + 1e-9)
    
    return [
        ent_val,                # ent
        np.mean(deltas),        # iat_mean
        np.var(deltas),         # iat_var
        group['Dur'].mean(),    # dur
        group['TotPkts'].sum(), # pkts
        group['TotBytes'].sum() # bytes
    ]

def load_all_scenarios(file_paths):
    rows = []
    for path in file_paths:
        print(f"Processing {path}...")
        try:
            # Note: Using standard read_csv, assuming Colab-style preprocessed or standard format
            df = pd.read_csv(path)
            
            # Ensure required columns exist (case sensitivity check)
            df.columns = [c.strip() for c in df.columns]
            
            # Handle label
            df['is_malicious'] = df['Label'].str.contains('Botnet', na=False).astype(int)
            
            # Handle StartTime conversion
            df['timestamp'] = pd.to_datetime(df['StartTime']).view('int64') // 10**9

            for _, group in df.groupby(['SrcAddr', 'DstAddr', 'Dport']):
                if len(group) >= 10:
                    f = extract_features(group)
                    if f:
                        rows.append(f + [int(group['is_malicious'].max())])
        except Exception as e:
            print(f"Error processing {path}: {e}")
            
    return pd.DataFrame(rows, columns=['ent', 'iat_mean', 'iat_var', 'dur', 'pkts', 'bytes', 'label'])

if __name__ == '__main__':
    # Default path for CTU-13 data
    files = sorted(glob.glob('data/raw/CTU-13/*.labeled'))
    
    if not files:
        print("No data files found in data/raw/CTU-13/. Running on synthetic data for validation.")
        # Minimal synthetic generator for local test
        X = np.random.rand(100, 6)
        y = np.random.randint(0, 2, 100)
    else:
        data = load_all_scenarios(files)
        X = data.drop('label', axis=1)
        y = data['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

    print(f"Training Random Forest on {len(X_train)} samples...")
    clf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]

    print("\n=== Supervised Random Forest Results ===")
    print(classification_report(y_test, y_pred))
    print(f"  AUC: {roc_auc_score(y_test, probs):.4f}")

    os.makedirs('experiments', exist_ok=True)
    joblib.dump(clf, 'experiments/stealthwatch_supervised.pkl')
    print("Supervised model saved to experiments/stealthwatch_supervised.pkl")
