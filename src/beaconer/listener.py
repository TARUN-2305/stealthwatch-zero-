# src/beaconer/listener.py
import socket
import threading
import time
import json
import logging
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class C2Listener:
    """Simple C2 server listener that logs connection timestamps."""
    
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        self.connections = []
        self.running = False
    
    def handle_client(self, conn, addr):
        """Handle a single client connection."""
        timestamp = time.time()
        try:
            data = conn.recv(4096)
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
        
        self.connections.append({'timestamp': timestamp, 'addr': addr[0]})
        logging.info(f"Connection from {addr[0]}:{addr[1]} at {timestamp:.3f}")
    
    def run(self):
        self.running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.host, self.port))
        except Exception as e:
            logging.error(f"Could not bind to {self.host}:{self.port}: {e}")
            return
            
        server.listen(10)
        logging.info(f"Listener started on {self.host}:{self.port}")
        
        while self.running:
            try:
                server.settimeout(1.0)
                conn, addr = server.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr))
                t.daemon = True
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logging.error(f"Error accepting connection: {e}")
                break
        
        server.close()
        logging.info("Listener stopped.")
        with open('experiments/listener_log.json', 'w') as f:
            json.dump(self.connections, f, indent=2)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple C2 Listener')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    
    listener = C2Listener(host=args.host, port=args.port)
    try:
        listener.run()
    except KeyboardInterrupt:
        listener.running = False
        logging.info("Stopping listener...")
