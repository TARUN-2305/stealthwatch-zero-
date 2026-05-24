# src/beaconer/beaconer.py
"""
Configurable C2 Beaconer Simulator — STEALTHWATCH-ZERO Red Team Tool.

Implements five jitter modes matching real C2 framework configurations:

  uniform        : Cobalt Strike default. Δt ~ Uniform[B(1-J), B(1+J)].
                   Most common in real deployments.

  gaussian       : Gaussian jitter. Δt ~ Normal(B, (J*B/2)²), clipped > 0.
                   More "natural" looking, used by some Sliver profiles.

  exponential    : Bounded exponential jitter. Δt ~ Exp(B), clipped to
                   [B*(1-J*2), B*(1+J*2)]. The UNBOUNDED exponential mode
                   is NOT used because expovariate(1/B) produces inter-arrivals
                   that are indistinguishable from human traffic (CV≈1.0) AND
                   violate C2 keepalive constraints (max Δt can be >>B).
                   Bounded exponential is what real tools implement.

  adversarial_max: U-shaped Beta distribution. Δt ~ Beta(0.5,0.5) scaled.
                   Maximizes timing entropy while staying within [B/2, 3B/2].
                   Designed to defeat simple histogram-based detectors.

  fixed          : J=0 baseline. No jitter. Trivially detected by all methods.

Usage (standalone):
    python src/beaconer/beaconer.py --interval 60 --jitter 0.3 --n-beacons 100
"""

import socket
import time
import random
import argparse
import logging
import json
import numpy as np

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')


class C2Beaconer:
    """
    Configurable C2 beaconer simulator.

    Parameters
    ----------
    host : str         Target C2 listener IP/hostname
    port : int         Target C2 listener port
    interval : float   Base beacon interval in seconds (B)
    jitter : float     Jitter fraction in [0, 0.5] (0.3 = ±30%)
    jitter_mode : str  Timing distribution (see module docstring)
    padding_mode : str Payload size strategy ('fixed'|'random'|'browser_size')
    protocol : str     Socket protocol ('tcp')
    n_beacons : int    Number of beacons to simulate
    """

    JITTER_MODES = ['uniform', 'gaussian', 'exponential', 'adversarial_max']

    def __init__(self, host: str = '127.0.0.1', port: int = 8443,
                 interval: float = 60.0, jitter: float = 0.0,
                 jitter_mode: str = 'uniform', padding_mode: str = 'fixed',
                 protocol: str = 'tcp', n_beacons: int = 200):
        self.host         = host
        self.port         = port
        self.interval     = interval
        self.jitter       = max(0.0, min(jitter, 0.9))   # hard cap at 90%
        self.jitter_mode  = jitter_mode
        self.padding_mode = padding_mode
        self.protocol     = protocol
        self.n_beacons    = n_beacons
        self.beacon_log   = []

    # ------------------------------------------------------------------
    # Timing
    # ------------------------------------------------------------------

    def _compute_sleep_time(self) -> float:
        """
        Compute next inter-arrival delay using the configured jitter mode.
        All modes keep the delay strictly positive.
        """
        B = self.interval
        J = self.jitter

        if J == 0.0:
            return B

        jitter_abs = B * J        # absolute jitter budget

        if self.jitter_mode == 'uniform':
            # Cobalt Strike style: uniform draw within ±J*B
            return B + random.uniform(-jitter_abs, jitter_abs)

        elif self.jitter_mode == 'gaussian':
            # Gaussian with sigma = J*B/2; clipped to stay > 0.1s
            return max(0.1, random.gauss(B, jitter_abs / 2.0))

        elif self.jitter_mode == 'exponential':
            # Bounded exponential: draw from Exp(B), clip to [B*(1-2J), B*(1+2J)]
            # Avoids session-breaking outliers while producing curved distribution
            lo = max(0.1, B * (1.0 - 2.0 * J))
            hi = B * (1.0 + 2.0 * J)
            while True:
                v = random.expovariate(1.0 / B)
                if lo <= v <= hi:
                    return v

        elif self.jitter_mode == 'adversarial_max':
            # U-shaped Beta(0.5, 0.5): spends time at extremes to maximize entropy
            # Scaled to [B*(1-J), B*(1+J)]
            lo = B * (1.0 - J)
            hi = B * (1.0 + J)
            return lo + (hi - lo) * random.betavariate(0.5, 0.5)

        else:
            raise ValueError(f"Unknown jitter_mode: {self.jitter_mode!r}. "
                             f"Choose from {self.JITTER_MODES}")

    # ------------------------------------------------------------------
    # Payload
    # ------------------------------------------------------------------

    def _build_payload(self) -> bytes:
        """Build a beacon HTTP-like payload."""
        if self.padding_mode == 'fixed':
            return b'GET /beacon HTTP/1.1\r\nHost: c2.example.com\r\n\r\n'

        elif self.padding_mode == 'random':
            size = random.randint(50, 1400)
            return bytes(random.getrandbits(8) for _ in range(size))

        elif self.padding_mode == 'browser_size':
            # Bimodal: 70% large (mimics HTTPS data), 30% small (keep-alive)
            if random.random() < 0.7:
                size = random.choice([512, 768, 1024, 1280, 1400])
            else:
                size = random.choice([64, 128, 256])
            return b'B' * size

        else:
            return b'BEACON'

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def send_beacon(self) -> bool:
        """Open a TCP connection, send payload, receive response, close."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            sock.sendall(self._build_payload())
            _ = sock.recv(4096)
            sock.close()
            return True
        except Exception as e:
            logging.warning(f"Beacon failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> list:
        """
        Execute the beacon loop.

        Returns
        -------
        list of dicts with keys: beacon_num, timestamp, actual_delta, success
        """
        logging.info(f"Starting beaconer: B={self.interval}s, J={self.jitter*100:.0f}%, "
                     f"mode={self.jitter_mode}, n={self.n_beacons}")

        self.beacon_log = []
        prev_time = time.time()

        for i in range(self.n_beacons):
            success = self.send_beacon()

            current_time  = time.time()
            actual_delta  = current_time - prev_time
            sleep_time    = self._compute_sleep_time()

            self.beacon_log.append({
                'beacon_num':   i,
                'timestamp':    current_time,
                'actual_delta': actual_delta,
                'success':      success,
            })

            logging.info(f"Beacon {i+1}/{self.n_beacons}: "
                         f"Δt={actual_delta:.3f}s  next_sleep={sleep_time:.3f}s  "
                         f"{'OK' if success else 'FAIL'}")

            prev_time = current_time
            time.sleep(max(0.05, sleep_time))

        # Persist log
        os.makedirs('experiments', exist_ok=True)
        log_file = f'experiments/beacon_log_{self.jitter_mode}_{self.jitter:.2f}.json'
        with open(log_file, 'w') as f:
            json.dump(self.beacon_log, f, indent=2)
        logging.info(f"Log saved → {log_file}")

        return self.beacon_log


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='STEALTHWATCH-ZERO: Configurable C2 Beaconer Simulator',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host',        default='127.0.0.1')
    parser.add_argument('--port',        type=int,   default=8443)
    parser.add_argument('--interval',    type=float, default=60.0,
                        help='Base interval in seconds (B)')
    parser.add_argument('--jitter',      type=float, default=0.0,
                        help='Jitter fraction 0.0-0.5 (0.3 = 30%%)')
    parser.add_argument('--jitter-mode', default='uniform',
                        choices=C2Beaconer.JITTER_MODES)
    parser.add_argument('--padding',     default='fixed',
                        choices=['fixed', 'random', 'browser_size'])
    parser.add_argument('--n-beacons',   type=int,   default=100)
    args = parser.parse_args()

    beaconer = C2Beaconer(
        host=args.host, port=args.port,
        interval=args.interval, jitter=args.jitter,
        jitter_mode=args.jitter_mode,
        padding_mode=args.padding,
        n_beacons=args.n_beacons)
    beaconer.run()
