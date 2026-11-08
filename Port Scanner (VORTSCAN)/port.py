

import socket
import sys
import argparse
from threading import Thread, Lock
from queue import Queue
from datetime import datetime

class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=1, threads=100):
        """
        Initialize the port scanner.
        
        Args:
            target: Target host to scan
            start_port: Starting port number
            end_port: Ending port number
            timeout: Connection timeout in seconds
            threads: Number of threads to use
        """
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.lock = Lock()
        self.port_queue = Queue()
        
        # Resolve target hostname
        try:
            self.target_ip = socket.gethostbyname(target)
            print(f"[*] Target resolved: {target} -> {self.target_ip}. 🍪")
        except socket.gaierror:
            print(f"[!] Error: Could not resolve hostname '{target}'. 🍪")
            sys.exit(1)
    
    def scan_port(self, port):
        """
        Scan a single port on the target host.
        
        Args:
            port: Port number to scan
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    print(f"[+] Port {port}: OPEN. 🍪")
        except socket.error as e:
            print(f"[!] Error scanning port {port}: {e}. 🍪")
    
    def worker(self):
        """Worker thread that processes ports from the queue."""
        while True:
            port = self.port_queue.get()
            if port is None:
                break
            self.scan_port(port)
            self.port_queue.task_done()
    
    def run(self):
        """Execute the port scan."""
        print("=" * 60)
        print("                       VORTSCAN")
        print("=" * 60)
        print("[*] VORTSCAN is starting. 🍪")
        print(f"[*] Starting TCP port scan on {self.target} ({self.target_ip}). 🍪")
        print(f"[*] Scanning ports {self.start_port}-{self.end_port}. 🍪")
        print(f"[*] Timeout: {self.timeout}s | Threads: {self.threads}. 🍪")
        print(f"[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. 🍪")
        print("-" * 60)
        
        start_time = datetime.now()
        
        # Create and start worker threads
        thread_list = []
        for _ in range(self.threads):
            thread = Thread(target=self.worker, daemon=True)
            thread.start()
            thread_list.append(thread)
        
        # Queue all ports
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)
        
        # Wait for queue to empty
        self.port_queue.join()
        
        # Stop workers
        for _ in range(self.threads):
            self.port_queue.put(None)
        
        for thread in thread_list:
            thread.join()
        
        end_time = datetime.now()
        elapsed = (end_time - start_time).total_seconds()
        
        print("-" * 60)
        print(f"[*] Scan completed in {elapsed:.2f} seconds. 🍪")
        print(f"[*] Open ports found: {len(self.open_ports)}. 🍪")
        
        if self.open_ports:
            print("\n[+] Summary of open ports. 🍪")
            for port in sorted(self.open_ports):
                try:
                    service = socket.getservbyport(port)
                    print(f"    Port {port}: {service}. 🍪")
                except OSError:
                    print(f"    Port {port}: Unknown. 🍪")


def main():
    parser = argparse.ArgumentParser(
        description='VORTSCAN - Scan a target host for open ports. 🍪',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples. 🍪
    python port.py localhost 1 1000
    python port.py 192.168.1.1 20 25 --timeout 2 --threads 50
    python port.py example.com 1 65535 --threads 200
    python port.py
        '''
    )
    
    parser.add_argument('target', nargs='?', default='localhost',
                        help='Target host (hostname or IP address) (default: localhost). 🍪')
    parser.add_argument('start_port', nargs='?', type=int, default=1,
                        help='Starting port number (default: 1). 🍪')
    parser.add_argument('end_port', nargs='?', type=int, default=1024,
                        help='Ending port number (default: 1024). 🍪')
    parser.add_argument('--timeout', type=float, default=1, 
                        help='Connection timeout in seconds (default: 1). 🍪')
    parser.add_argument('--threads', type=int, default=100,
                        help='Number of worker threads (default: 100). 🍪')
    
    args = parser.parse_args()

    # If no positional args were provided, prompt the user interactively.
    if len(sys.argv) == 1:
        print("VORTSCAN. 🍪")
        print("Enter the URL you want to scan (example: scanme.nmap.org). 🍪")

        target_input = input("Enter the URL (example: scanme.nmap.org): ").strip()
        if target_input:
            args.target = target_input

        start_input = input("Enter start port (example: 1, press Enter for 1): ").strip()
        if start_input:
            try:
                args.start_port = int(start_input)
            except ValueError:
                print("[!] Error: Start port must be a number. 🍪")
                sys.exit(1)

        end_input = input("Enter end port (example: 1024, press Enter for 1024): ").strip()
        if end_input:
            try:
                args.end_port = int(end_input)
            except ValueError:
                print("[!] Error: End port must be a number. 🍪")
                sys.exit(1)
    
    # Validate port range
    if args.start_port < 1 or args.start_port > 65535:
        print("[!] Error: Start port must be between 1 and 65535. 🍪")
        sys.exit(1)
    
    if args.end_port < 1 or args.end_port > 65535:
        print("[!] Error: End port must be between 1 and 65535. 🍪")
        sys.exit(1)
    
    if args.start_port > args.end_port:
        print("[!] Error: Start port must be less than or equal to end port. 🍪")
        sys.exit(1)
    
    if args.timeout <= 0:
        print("[!] Error: Timeout must be greater than 0. 🍪")
        sys.exit(1)
    
    if args.threads < 1:
        print("[!] Error: Threads must be at least 1. 🍪")
        sys.exit(1)
    
    # Run scanner
    scanner = PortScanner(args.target, args.start_port, args.end_port, 
                         args.timeout, args.threads)
    scanner.run()


if __name__ == '__main__':
    main()