# STEALTHWATCH-ZERO: Adversarially-Robust C2 Beaconing Detection

This directory contains the research project **STEALTHWATCH-ZERO**, which focuses on detecting adversarially-obfuscated malware Command-and-Control (C2) beaconing using socket-level temporal entropy analysis.

## Project Overview

**STEALTHWATCH-ZERO** is a network security research project designed to identify encrypted C2 channels that evade traditional detection methods (like JA3 fingerprinting or simple frequency analysis) by randomizing beacon intervals. The core innovation lies in using **Approximate Entropy (ApEn)**, **Sample Entropy (SampEn)**, and **Normalized Permutation Entropy (NPE)** to quantify the second-order temporal structure of TCP socket write/read sequences.

### Key Technologies
- **Languages:** Python (Analysis, Entropy Engine, Classifier), C (Socket Tap/Hooking)
- **Networking:** UNIX Network Programming APIs, `libpcap`, raw sockets, `LD_PRELOAD`
- **Machine Learning:** One-Class SVM (Scikit-learn)
- **Math/Information Theory:** Approximate Entropy (ApEn), Sample Entropy (SampEn), Permutation Entropy (PE)
- **Datasets:** CTU-13, CICIDS2017

## Directory Structure

- `NPS_Research_Proposal.md`: High-level research proposal outlining the problem, novelty, and mapping to the CS362IA syllabus.
- `STEALTHWATCH_ZERO_Full_Research_Plan.md`: Comprehensive execution blueprint including a deep literature review and a 12-week action plan.
- `src/`: (Planned) Implementation source code for the socket monitor, entropy engine, and classifier.
- `data/`: (Planned) Storage for raw and processed datasets.
- `experiments/`: (Planned) Validation scripts and results for entropy measurements and adversarial robustness.

## Usage & Execution Plan

This is currently a research and planning repository. The execution follows these phases (detailed in `STEALTHWATCH_ZERO_Full_Research_Plan.md`):

1.  **Environment Setup:** Provisioning Ubuntu with Python 3.11, `libpcap`, and relevant libraries.
2.  **Dataset Acquisition:** Downloading and preprocessing CTU-13 and CICIDS2017.
3.  **Synthetic Beaconer:** Building a configurable C2 simulator to generate adversarial traffic.
4.  **Entropy Feature Engine:** Implementing the core entropy computation logic.
5.  **Passive Socket Monitor:** Developing a `libpcap`-based or eBPF-based traffic tap.
6.  **Classifier Training:** Training the One-Class SVM on benign traffic.
7.  **Evaluation:** Testing against adversarial variants and comparing with baselines.

## Key Files to Reference

- **`STEALTHWATCH_ZERO_Full_Research_Plan.md`**: The primary guide for the entire project lifecycle, including environment setup and mathematical derivations.
- **`NPS_Research_Proposal.md`**: Best for a quick summary of the project's novelty and academic context.

## TODOs & Missing Components
- [ ] Implement `src/beaconer/beaconer.py` (Phase 2)
- [ ] Implement `src/entropy/feature_extractor.py` (Phase 3)
- [ ] Implement `src/tap/pcap_tap.py` (Phase 4)
- [ ] Implement `src/classifier/ocsvm.py` (Phase 5)
- [ ] Conduct final evaluation and write the IEEE format paper draft (Phases 8-9)
