# src/tap/pcap_tap.py
import dpkt
import socket
import time
import numpy as np
import os
from collections import defaultdict
from src.entropy.feature_extractor import EntropyFeatureExtractor

class PCAPFlowExtractor:
    """
    Extracts per-flow inter-arrival timing sequences from PCAP files.
    """
    
    def __init__(self, window=50, min_packets=30):
        self.window = window
        self.min_packets = min_packets
        self.extractor = EntropyFeatureExtractor(window=window)
        self.flows = defaultdict(list)  # flow_key -> list of timestamps
    
    def _ip_to_str(self, ip_bytes):
        try:
            return socket.inet_ntoa(ip_bytes)
        except Exception:
            return str(ip_bytes)
    
    def process_pcap(self, pcap_path):
        """
        Process a PCAP file and extract per-flow timing sequences.
        """
        self.flows.clear()
        
        if not os.path.exists(pcap_path):
            print(f"File {pcap_path} not found.")
            return []

        with open(pcap_path, 'rb') as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except ValueError:
                # Try pcapng
                try:
                    f.seek(0)
                    pcap = dpkt.pcapng.Reader(f)
                except Exception as e:
                    print(f"Could not read PCAP file {pcap_path}: {e}")
                    return []

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    
                    tcp = ip.data
                    src_ip = self._ip_to_str(ip.src)
                    dst_ip = self._ip_to_str(ip.dst)
                    dst_port = tcp.dport
                    
                    # Flow key: (src_ip, dst_ip, dst_port, 'tcp')
                    flow_key = (src_ip, dst_ip, dst_port, 'tcp')
                    self.flows[flow_key].append(ts)
                    
                except Exception:
                    continue
        
        return self._extract_features()
    
    def _extract_features(self):
        """Extract entropy features for all flows with sufficient packets."""
        results = []
        
        for flow_key, timestamps in self.flows.items():
            if len(timestamps) < self.min_packets:
                continue
            
            timestamps = sorted(timestamps)
            deltas = np.diff(timestamps)
            deltas = deltas[deltas > 1e-6]
            
            if len(deltas) < self.window:
                continue
            
            features = self.extractor.compute_features(deltas)
            if features is None:
                continue
            
            results.append({
                'flow_key': flow_key,
                'src_ip': flow_key[0],
                'dst_ip': flow_key[1],
                'dst_port': flow_key[2],
                'n_packets': len(timestamps),
                'duration_s': timestamps[-1] - timestamps[0],
                'ApEn': float(features[0]),
                'SampEn': float(features[1]),
                'NPE': float(features[2]),
                'features': features.tolist()
            })
        
        return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        extractor = PCAPFlowExtractor()
        results = extractor.process_pcap(sys.argv[1])
        for r in results:
            print(f"Flow {r['src_ip']} -> {r['dst_ip']}:{r['dst_port']} | SampEn: {r['SampEn']:.4f}")
