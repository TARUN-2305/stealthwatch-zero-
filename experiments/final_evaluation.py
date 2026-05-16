# experiments/final_evaluation.py
import json
import pandas as pd
import os

def generate_summary_table():
    results_path = 'experiments/adversarial_results.json'
    if not os.path.exists(results_path):
        print(f"Results file {results_path} not found.")
        return

    with open(results_path, 'r') as f:
        results = json.load(f)

    df = pd.DataFrame(results)
    
    # Calculate Detection Rates
    summary = df[['config', 'detected_ocsvm', 'detected_interval', 'detected_shannon']].copy()
    summary.columns = ['Scenario', 'STEALTHWATCH (OCSVM)', 'Baseline (Interval CV)', 'Baseline (Shannon)']
    
    # Map 1/0 to Yes/No
    for col in summary.columns[1:]:
        summary[col] = summary[col].map({1: 'DETECTED', 0: 'MISSED'})
        
    print("\n=== Phase 8: Final Comparative Evaluation ===")
    print(summary.to_string(index=False))
    
    summary.to_csv('experiments/final_comparison_table.csv', index=False)
    print("\nSummary table saved to experiments/final_comparison_table.csv")

if __name__ == "__main__":
    generate_summary_table()
