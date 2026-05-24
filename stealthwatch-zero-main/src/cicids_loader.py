# src/cicids_loader.py
import pandas as pd
import numpy as np

# CICIDS2017 benign-only extraction
TIMING_FEATURES = [
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min'
]

def load_cicids2017_benign(filepath):
    """
    Load CICIDS2017 CSV file and extract BENIGN flows only.
    Returns DataFrame with timing features.
    """
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()  # Remove whitespace from column names
    
    if 'Label' not in df.columns:
        # Some versions of the dataset might have different column names
        label_col = [c for c in df.columns if 'Label' in c][0]
        df['Label'] = df[label_col]

    benign_df = df[df['Label'] == 'BENIGN'].copy()
    
    # Handle infinite and NaN values (common in CICIDS)
    benign_df = benign_df.replace([np.inf, -np.inf], np.nan).dropna(
        subset=TIMING_FEATURES
    )
    
    # Filter to flows with sufficient packets
    if 'Total Fwd Packets' in benign_df.columns:
        benign_df = benign_df[benign_df['Total Fwd Packets'] >= 20]
    
    return benign_df[TIMING_FEATURES + (['Total Fwd Packets'] if 'Total Fwd Packets' in benign_df.columns else []) + ['Flow Duration']]

def reconstruct_delta_sequence(row, n_samples=50):
    """
    Reconstruct a plausible inter-arrival timing sequence from summary statistics.
    Uses a log-normal distribution fitted to the summary stats.
    
    This is necessary because CICIDS2017 provides flow summaries, not raw timestamps.
    """
    mean = max(row['Fwd IAT Mean'], 1e-6)
    std = max(row['Fwd IAT Std'], 1e-6)
    
    # Log-normal parameters from method of moments
    var = std ** 2
    # mu = ln(mean^2 / sqrt(var + mean^2))
    # sigma = sqrt(ln(1 + var / mean^2))
    mu = np.log(mean**2 / np.sqrt(var + mean**2))
    sigma = np.sqrt(np.log(1 + var / mean**2))
    
    # Generate samples
    samples = np.random.lognormal(mu, sigma, n_samples)
    
    # Clamp samples between Min and Max provided in the dataset
    samples = np.clip(samples, row['Fwd IAT Min'], row['Fwd IAT Max'])
    
    return samples
