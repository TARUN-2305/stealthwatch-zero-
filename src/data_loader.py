# src/data_loader.py
import pandas as pd
import numpy as np

CTU_COLUMNS = [
    'StartTime', 'Dur', 'Proto', 'SrcAddr', 'Sport', 'Dir',
    'DstAddr', 'Dport', 'State', 'sTos', 'dTos', 'TotPkts',
    'TotBytes', 'SrcBytes', 'Label'
]

def load_ctu13_scenario(filepath):
    """
    Load a CTU-13 labeled bidirectional NetFlow file.
    Returns a DataFrame with timing features extracted.
    """
    # Note: Some CTU-13 files use fixed-width or space-separated format
    df = pd.read_csv(filepath, sep=r'\s+', names=CTU_COLUMNS, 
                     parse_dates=['StartTime'], skiprows=1, on_bad_lines='skip')
    
    # Create binary label: 1 = botnet, 0 = benign
    df['is_malicious'] = df['Label'].apply(
        lambda x: 1 if ('Botnet' in str(x) or 'From-Botnet' in str(x)) else 0
    )
    
    # Convert StartTime to Unix timestamp
    df['timestamp'] = pd.to_datetime(df['StartTime']).view('int64') / 1e9
    
    return df

def extract_flow_timing_sequence(df, src_ip, dst_ip, dst_port):
    """
    Extract inter-arrival timing deltas for a specific flow (connection pair).
    Returns array of delta_t values in seconds.
    """
    flow_mask = (
        (df['SrcAddr'] == src_ip) & 
        (df['DstAddr'] == dst_ip) & 
        (df['Dport'] == str(dst_port))
    )
    flow_df = df[flow_mask].sort_values('timestamp')
    
    if len(flow_df) < 20:  # Minimum 20 packets for entropy computation
        return None
    
    timestamps = flow_df['timestamp'].values
    deltas = np.diff(timestamps)  # Inter-arrival time differences
    deltas = deltas[deltas > 0]   # Remove zero deltas (simultaneous packets)
    
    return deltas

def group_flows_by_host(df):
    """
    For each unique SrcAddr, extract all its connection timing sequences.
    Returns dict: {src_ip: [{'deltas': delta_array, 'label': label}, ...]}
    """
    hosts = {}
    for src_ip in df['SrcAddr'].unique():
        host_df = df[df['SrcAddr'] == src_ip]
        label = host_df['is_malicious'].max()  # If any flow is botnet, host is botnet
        
        connections = []
        for (dst_ip, dst_port), conn_df in host_df.groupby(['DstAddr', 'Dport']):
            conn_df = conn_df.sort_values('timestamp')
            if len(conn_df) < 20:
                continue
            deltas = np.diff(conn_df['timestamp'].values)
            deltas = deltas[deltas > 0]
            if len(deltas) >= 15:
                connections.append({'deltas': deltas, 'label': int(label)})
        
        if connections:
            hosts[src_ip] = connections
    
    return hosts
