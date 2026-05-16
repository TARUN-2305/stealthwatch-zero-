# experiments/adversarial_eval.py
import numpy as np
import sys
import os
import json

# Add src and baselines to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.classifier.ocsvm import StealthwatchClassifier
from src.entropy.feature_extractor import EntropyFeatureExtractor
from src.beaconer.beaconer import C2Beaconer
from baselines.simple_interval import interval_baseline, shannon_baseline

def run_adversarial_eval():
    print("--- Phase 6: Adversarial Robustness Evaluation ---")
    
    # Load trained model
    model_path = 'experiments/stealthwatch_model.pkl'
    if not os.path.exists(model_path):
        print(f"Model {model_path} not found. Please run src/classifier/ocsvm.py first.")
        return
    
    clf = StealthwatchClassifier.load(model_path)
    extractor = EntropyFeatureExtractor(window=50)
    
    ADVERSARIAL_CONFIGS = [
        ('AE1_Mild_Uniform',   dict(interval=60, jitter=0.1, jitter_mode='uniform', n_beacons=100)),
        ('AE2_Heavy_Uniform',  dict(interval=60, jitter=0.3, jitter_mode='uniform', n_beacons=100)),
        ('AE3_Gaussian',       dict(interval=60, jitter=0.3, jitter_mode='gaussian', n_beacons=100)),
        ('AE4_Exponential',    dict(interval=60, jitter=0.5, jitter_mode='exponential', n_beacons=100)),
        ('AE5_MaxEntropy',     dict(interval=60, jitter=0.5, jitter_mode='adversarial_max', n_beacons=100)),
    ]
    
    results = []
    
    for name, params in ADVERSARIAL_CONFIGS:
        print(f"\nTesting {name}...")
        
        # Simulate beaconing timing
        beaconer = C2Beaconer(host='127.0.0.1', port=8443, **params)
        # Instead of real sleep/send, we'll just compute the deltas for speed
        deltas = []
        for _ in range(params['n_beacons']):
            deltas.append(beaconer._compute_sleep_time())
        deltas = np.array(deltas)
        
        # Entropy features
        features = extractor.compute_features(deltas)
        if features is None:
            print("  Error: Could not extract features.")
            continue
            
        # Predictions
        is_anomaly = clf.predict(features.reshape(1, -1))[0]
        score = clf.decision_scores(features.reshape(1, -1))[0]
        
        # Baselines
        det_interval = interval_baseline(deltas)
        det_shannon = shannon_baseline(deltas)
        
        res = {
            'config': name,
            'SampEn': round(float(features[1]), 4),
            'detected_ocsvm': int(is_anomaly),
            'detected_interval': int(det_interval),
            'detected_shannon': int(det_shannon),
            'score': round(float(score), 4)
        }
        results.append(res)
        
        print(f"  SampEn:   {res['SampEn']:.4f}")
        print(f"  OCSVM:    {'DETECTED' if res['detected_ocsvm'] else 'MISSED'}")
        print(f"  Interval: {'DETECTED' if res['detected_interval'] else 'MISSED'}")
        print(f"  Shannon:  {'DETECTED' if res['detected_shannon'] else 'MISSED'}")

    # Save results
    with open('experiments/adversarial_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results saved to experiments/adversarial_results.json")

if __name__ == "__main__":
    run_adversarial_eval()
