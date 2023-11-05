import socket
from scapy.all import *
from pyfiglet import Figlet
from datetime import datetime
from ftplib import FTP
import telnetlib
import dns.message
import dns.query
import dns.flags
import dns.rdatatype
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import as_completed
import matplotlib.pyplot as plt
import os

conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def load_start_ascii():
    print("-" * 50)
    f = Figlet(font='doom')
    print(f.renderText('SERVICE PORT SCANNER'))
    print("-" * 50)

def modified_port_scan(host, ports, timeout):
    pkt = IP(dst=host)/TCP(dport=ports, flags="S")                       
    ans, unans = sr(pkt, verbose=0, timeout=timeout)
    alive_ports = []
    for (s, r) in ans:
        if r[TCP].flags == "SA":
            alive_ports.append(s[TCP].dport)
    return alive_ports

def parallel_scan(host, timeout, ports, worker_num):
    start_time = datetime.now()
    print(f"Scanning {host} with timeout {timeout} seconds...")
    alive_ports = []
    with ProcessPoolExecutor(max_workers=worker_num) as executer:
        futures = [executer.submit(modified_port_scan, host, ports[i], timeout) for i in range(40)]
        for future in as_completed(futures):
            alive_ports += future.result()
    end_time = datetime.now()
    duration = end_time - start_time
    detected_ports_count = len(alive_ports)
    print(f"Scan completed for {host} with timeout {timeout} seconds. Duration: {duration}. Detected Ports: {detected_ports_count}")
    
    return (duration, detected_ports_count, alive_ports)

def modified_port_check():
    hosts = [input(f"Scanner Target IP {i+1}: ") for i in range(2)]                                     # ip갯수 설정
    p = list(input("Scanner Target Port (ex. 1 - 65535): ").split("-"))
    timeouts = [int(input(f"Enter timeout {i+1} (in seconds): ")) for i in range(2)]                    # timeout 갯수 설정
    
    worker_num = os.cpu_count()
    ports = range(int(p[0]), int(p[1]))
    n = int(len(ports) / 40)
    ports = [ports[i:i+n] for i in range(0, len(ports), n)]
    
    scan_results = {}

    with ProcessPoolExecutor(max_workers=worker_num) as executor:
        future_to_params = {(host, timeout): executor.submit(parallel_scan, host, timeout, ports, worker_num) for host in hosts for timeout in timeouts}
        for (host, timeout), future in future_to_params.items():
            scan_results.setdefault(host, {})[timeout] = future.result()

    return scan_results

def display_scan_results(scan_results):
    print("\nScan Results:")
    print("-" * 90)
    print(f"{'IP':<15} {'Timeout':<10} {'Duration':<20} {'Detected Ports Count':<20} {'Detected Ports'}")
    print("-" * 90)
    
    for host, results in scan_results.items():
        for timeout, (duration, detected_ports_count, alive_ports) in results.items():
            duration_str = str(duration)
            print(f"{host:<15} {timeout:<10} {duration_str:<20} {detected_ports_count:<20} {str(alive_ports)}")


def plot_graph(scan_results):
    for host, results in scan_results.items():
        timeouts = list(results.keys())
        detected_ports_counts = [results[timeout][1] for timeout in timeouts]
        
        plt.bar(timeouts, detected_ports_counts, color='blue', alpha=0.7)
        plt.title(f"Detected Ports Count for {host}")
        plt.xlabel("Timeout (seconds)")
        plt.ylabel("Detected Ports Count")
        plt.show()

if __name__ == "__main__":
    load_start_ascii()
    scan_results = modified_port_check()
    display_scan_results(scan_results)
    plot_graph(scan_results)
