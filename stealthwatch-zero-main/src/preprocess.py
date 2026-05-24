# src/preprocess.py
import numpy as np
import pandas as pd
import pickle
from pathlib import Path
from src.cicids_loader import load_cicids2017_benign, reconstruct_delta_sequence
from src.data_loader import load_ctu13_scenario, group_flows_by_host

def build_benign_dataset(cicids_dir, output_path):
    """Build training dataset from CICIDS2017 BENIGN flows."""
    all_sequences = []
    
    csv_files = list(Path(cicids_dir).glob('*.csv'))
    if not csv_files:
        print(f"No CSV files found in {cicids_dir}")
        return []

    for f in csv_files:
        print(f"Processing {f.name}...")
        try:
            df = load_cicids2017_benign(str(f))
            for _, row in df.iterrows():
                seq = reconstruct_delta_sequence(row)
                all_sequences.append({'deltas': seq, 'label': 0, 'source': f.name})
        except Exception as e:
            print(f"Error processing {f.name}: {e}")
    
    with open(output_path, 'wb') as f:
        pickle.dump(all_sequences, f)
    
    print(f"Saved {len(all_sequences)} benign sequences to {output_path}")
    return all_sequences

def build_botnet_dataset(ctu13_dir, output_path):
    """Build evaluation dataset from CTU-13 botnet flows."""
    all_sequences = []
    
    ctu13_path = Path(ctu13_dir)
    if not ctu13_path.exists():
        print(f"CTU-13 directory {ctu13_dir} does not exist.")
        return []

    # Search for .labeled files recursively or in scenario subdirs
    label_files = list(ctu13_path.rglob('*.labeled'))
    if not label_files:
        print(f"No .labeled files found in {ctu13_dir}")
        return []

    for lf in label_files:
        print(f"Processing {lf.name}...")
        try:
            df = load_ctu13_scenario(str(lf))
            hosts = group_flows_by_host(df)
            
            for src_ip, conns in hosts.items():
                for conn in conns:
                    all_sequences.append(conn)
        except Exception as e:
            print(f"Error processing {lf.name}: {e}")
    
    with open(output_path, 'wb') as f:
        pickle.dump(all_sequences, f)
    
    print(f"Saved {len(all_sequences)} sequences (botnet + benign) to {output_path}")
    return all_sequences

if __name__ == "__main__":
    # Example usage
    # build_benign_dataset('data/raw/CICIDS2017', 'data/processed/benign_sequences.pkl')
    # build_botnet_dataset('data/raw/CTU-13', 'data/processed/ctu13_sequences.pkl')
    pass
