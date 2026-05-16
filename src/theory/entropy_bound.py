# src/theory/entropy_bound.py
import numpy as np

def compute_theoretical_sampen_bound(B, J, r_factor=0.2):
    """
    Compute theoretical upper bound on SampEn for a beaconer
    with base interval B and jitter fraction J.
    """
    if J == 0:
        return 0.0
    
    # Std dev of uniform distribution on [B(1-J), B(1+J)] is (2JB) / sqrt(12) = JB / sqrt(3)
    sigma = (J * B) / np.sqrt(3)
    
    # Tolerance r
    r = r_factor * sigma
    
    # Range of distribution C = 2JB
    C = 2 * J * B
    
    # Probability of template match (1D) for uniform distribution is 2r/C
    # For m-dimension, it's (2r/C)^m if independent
    # SampEn = -log(P(match_m+1) / P(match_m)) = -log(2r/C)
    
    P_match = min(1.0, 2 * r / C)
    
    if P_match <= 0:
        return np.inf
    
    S_star = -np.log(P_match)
    
    return S_star

if __name__ == "__main__":
    print("--- Phase 7: Theoretical Entropy Bounds ---")
    B = 60.0  # 60s base interval
    for J in [0.01, 0.1, 0.2, 0.3, 0.4, 0.5]:
        bound = compute_theoretical_sampen_bound(B, J)
        print(f"Jitter {J*100:2.0f}% -> S* bound: {bound:.4f}")
    
    print("\nNote: Human traffic (Poisson) has theoretical SampEn ≈ 2.0+")
