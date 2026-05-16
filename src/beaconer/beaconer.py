# src/beaconer/beaconer.py
import socket
import time
import random
import argparse
import logging
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class C2Beaconer:
    """
    Configurable C2 beaconer simulator.
    """
    
    def __init__(self, host, port, interval=60.0, jitter=0.0,
                 jitter_mode='uniform', padding_mode='fixed',
                 protocol='tcp', n_beacons=200):
        self.host = host
        self.port = port
        self.interval = interval
        self.jitter = jitter
        self.jitter_mode = jitter_mode
        self.padding_mode = padding_mode
        self.protocol = protocol
        self.n_beacons = n_beacons
        self.beacon_log = []  # Log actual inter-arrival times for analysis
    
    def _compute_sleep_time(self):
        """Compute sleep time for next beacon based on jitter mode."""
        base = self.interval
        
        if self.jitter == 0.0:
            return base  # Fixed interval (no jitter)
        
        jitter_range = base * self.jitter
        
        if self.jitter_mode == 'uniform':
            # Cobalt Strike default: uniform jitter
            return base + random.uniform(-jitter_range, jitter_range)
        
        elif self.jitter_mode == 'gaussian':
            # Gaussian jitter
            return max(1.0, random.gauss(base, jitter_range / 2))
        
        elif self.jitter_mode == 'exponential':
            # Exponential inter-arrivals (mimics Poisson process)
            return random.expovariate(1.0 / base)
        
        elif self.jitter_mode == 'adversarial_max':
            # Maximum entropy adversarial: uses beta distribution
            a, b = 0.5, 0.5
            return base * (1 - self.jitter) + self.jitter * 2 * base * random.betavariate(a, b)
        
        else:
            raise ValueError(f"Unknown jitter mode: {self.jitter_mode}")
    
    def _build_payload(self):
        """Build a beacon payload."""
        if self.padding_mode == 'fixed':
            return b'GET /beacon HTTP/1.1\r\nHost: c2.example.com\r\n\r\n'
        
        elif self.padding_mode == 'random':
            size = random.randint(50, 1400)
            return bytes(random.getrandbits(8) for _ in range(size))
        
        elif self.padding_mode == 'browser_size':
            # Browser-like sizes: bimodal distribution
            if random.random() < 0.7:
                size = random.choice([512, 768, 1024, 1280, 1400])
            else:
                size = random.choice([64, 128, 256])
            return b'A' * size
    
    def send_beacon(self):
        """Send a single beacon to the C2 server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            payload = self._build_payload()
            sock.sendall(payload)
            response = sock.recv(4096)
            sock.close()
            return True
        except Exception as e:
            logging.warning(f"Beacon failed: {e}")
            return False
    
    def run(self):
        """Main beacon loop."""
        logging.info(f"Starting beaconer: interval={self.interval}s, jitter={self.jitter*100}%, mode={self.jitter_mode}")
        
        prev_time = time.time()
        
        for i in range(self.n_beacons):
            success = self.send_beacon()
            
            current_time = time.time()
            actual_delta = current_time - prev_time
            self.beacon_log.append({
                'beacon_num': i,
                'timestamp': current_time,
                'actual_delta': actual_delta,
                'success': success
            })
            prev_time = current_time
            
            sleep_time = self._compute_sleep_time()
            logging.info(f"Beacon {i+1}/{self.n_beacons}: delta={actual_delta:.2f}s, next_sleep={sleep_time:.2f}s")
            # In a real simulation, we sleep. For data generation, we can just compute.
            # But the plan implies running it.
            time.sleep(max(0.1, sleep_time))
        
        # Save beacon log
        log_file = f'experiments/beacon_log_{self.jitter_mode}_{self.jitter:.2f}.json'
        with open(log_file, 'w') as f:
            json.dump(self.beacon_log, f, indent=2)
        
        return self.beacon_log

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Configurable C2 Beaconer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--interval', type=float, default=60.0)
    parser.add_argument('--jitter', type=float, default=0.0)
    parser.add_argument('--jitter-mode', default='uniform',
                        choices=['uniform', 'gaussian', 'exponential', 'adversarial_max'])
    parser.add_argument('--n-beacons', type=int, default=200)
    args = parser.parse_args()
    
    beaconer = C2Beaconer(
        host=args.host, port=args.port,
        interval=args.interval, jitter=args.jitter,
        jitter_mode=args.jitter_mode, n_beacons=args.n_beacons
    )
    beaconer.run()
