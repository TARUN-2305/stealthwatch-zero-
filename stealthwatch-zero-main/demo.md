# STEALTHWATCH-ZERO: Live Demonstration Guide

## Overview

This demo simulates a complete cyberattack scenario — a compromised host beaconing to a C2 server with **adversarial jitter** — and shows the entropy engine detecting it in real-time. No root access, no real TCP connections required.

---

## Running the Demo

```bash
python run_demo.py
```

**Options:**

| Flag | Default | Meaning |
|------|---------|---------|
| `--interval` | `5.0` | Beacon base interval in seconds |
| `--jitter` | `0.30` | Jitter fraction (0.30 = ±30%) |
| `--mode` | `uniform` | Jitter distribution mode |
| `--beacons` | `80` | Number of beacon intervals to simulate |

**Preset scenarios:**

```bash
# Standard (Cobalt Strike default style)
python run_demo.py --interval 60 --jitter 0.3 --mode uniform

# Harder: Gaussian jitter (more natural-looking)
python run_demo.py --jitter 0.3 --mode gaussian

# Hardest: Adversarial max-entropy (U-shaped beta distribution)
python run_demo.py --jitter 0.5 --mode adversarial_max
```

---

## What Happens Step by Step

### Step 1: Model Loading
The pre-trained One-Class SVM is loaded from `experiments/stealthwatch_model.pkl`.
If not found, it trains automatically on 1500 synthetic benign timing sequences
(exponential inter-arrivals, mimicking organic human browsing).

### Step 2: C2 Attack Simulation
The `C2Beaconer` class generates a sequence of inter-arrival timing deltas
using exactly the same algorithm a real C2 implant would use:
- Base interval B (e.g. 60s)
- Jitter applied per chosen distribution (uniform / gaussian / exponential / beta)
- No real TCP sockets — just timing computation, so it runs anywhere

### Step 3: Human Traffic Simulation
A Poisson-process timing sequence (exponential inter-arrivals) is generated
to represent organic user web browsing.

### Step 4: Detection Reports
For each sequence, the system computes the 5-feature vector and prints:

```
╔══════════════════════════════════════════════════════╗
║  DETECTION REPORT — C2 Beacon (J=30%, uniform)      ║
╠══════════════════════════════════════════════════════╣
║  Ground Truth    : C2 BEACONER                      ║
║  CV (primary)    : 0.1732                            ║
║  Skewness        : 0.0214                            ║
║  ApEn            : 0.5124                            ║
║  NPE             : 0.9978                            ║
║  Kurtosis        : -1.1983                           ║
║  SampEn (info)   : 2.1832                            ║
║                                                      ║
║  Interpretation  : MODERATELY_REGULAR — probable    ║
║                    beaconing (verify)                ║
╠══════════════════════════════════════════════════════╣
║  STEALTHWATCH    [✓] : MALICIOUS BEACONING DETECTED  ║
║  Baseline CV     [✗] : BENIGN (not flagged)          ║
║  Baseline Shannon[✗] : BENIGN (not flagged)          ║
╚══════════════════════════════════════════════════════╝
```

The key numbers to watch:
- **CV < 0.40** → flagged as potential C2 (any reliable beaconer has CV ≤ 0.289)
- **Skewness ≈ 0** → bounded distribution → not human
- Baselines MISS the detection at 30% jitter; STEALTHWATCH catches it

### Step 5: Adversarial Stress Test
All 6 evasion strategies are tested back-to-back, showing the detection rate.

### Step 6: Theoretical Bound
Prints the formal CV bound:
```
CV_bound = J / √3  ≤  0.5 / √3  ≈  0.289
```
Any reliable C2 beaconer must have CV below this threshold,
while human traffic sits at CV ≈ 1.0.

---

## Other Scripts

```bash
# Phase 3: Feature engine validation with plots
python experiments/validate_entropy.py
# → Saves experiments/entropy_validation.png

# Phase 6: Detailed adversarial robustness evaluation
python experiments/adversarial_eval.py
# → Saves experiments/adversarial_results.json

# Phase 8: Full benchmark comparison table
python experiments/final_evaluation.py
# → Saves experiments/final_comparison_table.csv
#   Saves experiments/benchmark_results.json

# Phase 7: Theoretical bound derivation
python src/theory/entropy_bound.py

# Real TCP demo (requires two terminals)
# Terminal 1:
python src/beaconer/listener.py --port 8443
# Terminal 2:
python src/beaconer/beaconer.py --interval 5 --jitter 0.3 --n-beacons 30
```

---

## Interpreting Results

| CV value | Likely source |
|----------|--------------|
| 0.00 – 0.15 | Fixed-interval beaconer (trivially detected by all methods) |
| 0.15 – 0.30 | C2 beaconer with 30–50% jitter (baselines fail; STEALTHWATCH detects) |
| 0.30 – 0.40 | Borderline (adversarial beaconer near reliability limit) |
| 0.40 – 0.70 | Ambiguous region (rare in practice) |
| > 0.70 + Skew > 1.0 | Organic human traffic (Poisson / HTTP browsing) |

---

## Why It Works

The core insight: **C2 beaconers are finite-state machines operating under timing constraints.**

1. A beaconer must call back within the server's keepalive timeout or lose the session.
2. This forces the jitter range to be bounded: the maximum useful jitter is ~50%.
3. For a bounded uniform distribution: `CV = J/√3 ≤ 0.5/√3 ≈ 0.289`.
4. Human traffic (Poisson process) has `CV = 1.0` (exponential distribution).
5. The **3× gap** between max C2 CV and human CV is the detection margin.
6. Increasing jitter beyond 50% breaks C2 reliability — it's a fundamental tradeoff.

This is why the system is **adversarially robust by construction**, not just empirically.
