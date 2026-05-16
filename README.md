# STEALTHWATCH-ZERO: Adversarially-Robust C2 Beaconing Detection

![Detection Precision](https://img.shields.io/badge/Precision-91%25-green)
![Dataset](https://img.shields.io/badge/Dataset-CTU--13-blue)
![Methodology](https://img.shields.io/badge/Method-Temporal%20Entropy-orange)

**STEALTHWATCH-ZERO** is a network security research project focused on detecting encrypted Command-and-Control (C2) beaconing that evades traditional detection through randomized timing (jitter). By using information-theoretic entropy analysis, the system identifies automated communication patterns even when they are heavily obfuscated.

## 🌟 Key Features

- **91% Detection Precision:** Proven effective across 13 diverse real-world botnet scenarios (CTU-13 dataset).
- **Adversarial Robustness:** Designed specifically to defeat "jitter" evasion techniques used by advanced persistent threats (APTs).
- **Socket-Level Analysis:** Operates on inter-arrival timing deltas, bypassing the need for TLS decryption or Deep Packet Inspection (DPI).
- **Mathematically Grounded:** Uses Approximate Entropy (ApEn), Sample Entropy (SampEn), and Permutation Entropy (NPE) to quantify network behavior.

## 🛠️ Project Architecture

- `src/`: Core implementation including data loaders, entropy engine, and classifiers.
- `src/entropy/`: The heart of the project—feature extraction for temporal complexity.
- `src/beaconer/`: A configurable C2 simulator for generating adversarial traffic.
- `experiments/`: Pre-trained models and evaluation scripts.
- `baselines/`: Traditional detection methods used for comparative benchmarking.

## 🚀 Quick Start & Demo

Experience the detection in action with our live Proof-of-Concept demonstration:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/TARUN-2305/stealthwatch-zero-.git
   cd stealthwatch-zero-
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Live Demo:**
   ```bash
   python run_demo.py
   ```
   *This script simulates a C2 attack with 30% jitter and demonstrates how STEALTHWATCH-ZERO's entropy engine identifies the malicious behavior.*

## 📊 Results Summary

The system was evaluated against the full CTU-13 dataset, which includes 13 scenarios representing various botnet families (Neris, Rbot, Virut, etc.).

| Metric | Result |
| :--- | :--- |
| **Precision** | **91%** |
| **Recall** | **52%** |
| **Model** | Supervised Random Forest |
| **Entropy Feature Signal** | Exceptional (Lower complexity detected in all C2 variants) |

For a deeper dive into the results, see [experiments/final_comparison_table.csv](experiments/final_comparison_table.csv).

## 📄 Documentation

- [demo.md](demo.md): Detailed explanation of the demonstration workflow.
- [NPS_Research_Proposal.md](NPS_Research_Proposal.md): High-level academic proposal.
- [STEALTHWATCH_ZERO_Full_Research_Plan.md](STEALTHWATCH_ZERO_Full_Research_Plan.md): Comprehensive 12-week action plan and literature review.
- [SESSION_LOG.md](SESSION_LOG.md): Full history of the implementation and validation phases.

## 🎓 Academic Context

This project was developed as part of the CS362IA (Network Programming and Security) research track. It addresses the critical "detection gap" in modern encrypted traffic classification and provides a formal information-theoretic bound for C2 reliability vs. entropy.

---
Developed by [TARUN-2305](https://github.com/TARUN-2305)
