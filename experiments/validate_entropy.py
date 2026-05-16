# experiments/validate_entropy.py
import numpy as np
import matplotlib.pyplot as plt
import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.entropy.feature_extractor import EntropyFeatureExtractor

def run_validation():
    extractor = EntropyFeatureExtractor(m=2, r_factor=0.2, order=3, window=50)

    print("--- Entropy Feature Engine Validation ---")

    # Test 1: Perfectly regular signal (fixed interval = C2 beaconer, 0% jitter)
    regular = np.ones(200) * 60.0 + np.random.normal(0, 0.01, 200)  # 60s ± 10ms noise
    feat_regular = extractor.describe(regular)
    print(f"REGULAR (fixed-interval): {feat_regular}")

    # Test 2: Gaussian noise (human browsing inter-arrival approximation)
    random_signal = np.random.exponential(scale=2.0, size=200)  # Poisson-like human traffic
    feat_random = extractor.describe(random_signal)
    print(f"RANDOM (human-like):     {feat_random}")

    # Test 3: Uniform jitter beaconer (Cobalt Strike style, 30% jitter)
    jitter_signal = 60.0 + np.random.uniform(-18, 18, 200)
    feat_jitter = extractor.describe(jitter_signal)
    print(f"JITTER 30% uniform:      {feat_jitter}")

    # Test 4: Adversarial max-entropy beaconer
    # Uses beta distribution to create high-complexity timing
    adv_signal = 60.0 * np.random.beta(0.5, 0.5, 200)
    feat_adv = extractor.describe(adv_signal)
    print(f"ADVERSARIAL max-entropy: {feat_adv}")

    # Visualization
    labels = ['Regular\n(C2, 0% jitter)', 'Jitter 30%\n(uniform)', 
              'Adversarial\n(max entropy)', 'Human\n(Poisson)']
    sampen_values = [feat_regular['SampEn'], feat_jitter['SampEn'], 
                     feat_adv['SampEn'], feat_random['SampEn']]

    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, sampen_values, color=['red', 'orange', 'gold', 'green'], edgecolor='black')
    plt.axhline(y=1.2, color='blue', linestyle='--', linewidth=2, label='Proposed threshold S*')
    plt.ylabel('Sample Entropy (SampEn)', fontsize=13)
    plt.title('SampEn Values Across Signal Types', fontsize=14)
    plt.legend()
    plt.tight_layout()
    
    os.makedirs('experiments', exist_ok=True)
    plot_path = 'experiments/entropy_validation.png'
    plt.savefig(plot_path, dpi=300)
    print(f"\nSaved entropy validation plot to {plot_path}")

if __name__ == "__main__":
    run_validation()
