# STEALTHWATCH-ZERO: Live Demonstration

This guide explains how to run the interactive Proof-of-Concept (PoC) demonstration for the STEALTHWATCH-ZERO project. 

The demo simulates an active cyberattack scenario where an infected machine communicates with a Command and Control (C2) server using an evasive, randomized beaconing technique, and shows how our entropy-based engine catches it in real-time.

## 🚀 Running the Demo

To launch the automated demonstration, open a terminal in the project's root directory and run:

```bash
python run_demo.py
```

## ⚙️ What Happens Under the Hood?

When you run the script, the following sequence occurs automatically:

1. **C2 Listener Initialization (The Server):**
   - The script starts `src/beaconer/listener.py` on port `8443`. This represents the attacker's remote infrastructure waiting for incoming connections.

2. **Adversarial Beaconer Launch (The Malware):**
   - The script launches `src/beaconer/beaconer.py`.
   - **Crucial Detail:** It uses a **30% Uniform Jitter** (`--jitter 0.3 --jitter-mode uniform`). This means instead of calling back exactly every 2 seconds, it randomly varies the interval (e.g., 1.6s, 2.3s, 1.8s). This is the exact evasion technique used by advanced malware like Cobalt Strike to defeat simple statistical detectors.

3. **Data Collection (The Monitor):**
   - The system records the precise inter-arrival times (timing deltas) of the network packets as the malware beacons out. It collects a sequence of these timing gaps over approximately 60 seconds.

4. **Entropy Analysis & Detection (The Defense):**
   - The script feeds the collected timing sequence into our `EntropyFeatureExtractor`.
   - It computes the **Sample Entropy (SampEn)**. Because the beaconer is driven by a finite-state machine (code), its timing sequence—despite the 30% random jitter—lacks the deep mathematical complexity of human-driven traffic (like web browsing).
   - The classifier evaluates the SampEn score. If the score indicates low temporal complexity, it flags the traffic as malicious.

## 📊 Interpreting the Output

At the end of the script, you will see a detection report similar to this:

```text
========================================
         DETECTION REPORT
========================================
Target Flow:  localhost:8443
Mean IAT:     2.01s
SampEn:       1.6842 (Complexity Score)
STATUS:       [!] MALICIOUS BEACONING DETECTED
CONFIDENCE:   HIGH (Low Temporal Complexity)
========================================
```

- **SampEn Score:** This is the core metric. Human/organic traffic typically scores `> 2.0`. Scores below `1.8` (like the `1.68` above) reveal the underlying regularity of the automated script, regardless of the jitter applied.
- **Status:** The system successfully bypassed the attacker's 30% jitter obfuscation and correctly identified the connection as an automated C2 beacon.
