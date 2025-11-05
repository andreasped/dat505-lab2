#!/usr/bin/env python3
"""
traffic_interceptor.py

Simple PCAP parser to extract:
 - DNS queries
 - Visited HTTP URLs (Host + URI)
 - Top talkers (IP -> packet counts)
 - Protocol counts

Usage:
 sudo python3 traffic_interceptor.py /path/to/pcap.pcap [--outdir /path/to/output]
Outputs (default outdir: ~/evidence/analysis):
 - dns_queries.csv
 - http_urls.csv
 - top_talkers.csv
 - protocol_counts.csv

This is the parser you provided, renamed and hardened. It now accepts an optional
--outdir argument to choose where CSV outputs are written.
"""

import sys
import argparse
import csv
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, ARP
import os

# --- Argument parsing ---
parser = argparse.ArgumentParser(description='Parse a pcap and extract DNS, HTTP, top-talkers, protocol counts')
parser.add_argument('pcap', help='Path to pcap file to analyze')
parser.add_argument('--outdir', help='Output directory (default: ~/evidence/analysis)')
args = parser.parse_args()

pcap_path = args.pcap
if not os.path.exists(pcap_path):
    print(f"[-] pcap path does not exist: {pcap_path}")
    sys.exit(1)

# explicit output directory in the user's home by default
homedir = os.path.expanduser('~')
default_outdir = os.path.join(homedir, 'evidence', 'analysis')
outdir = os.path.expanduser(args.outdir) if args.outdir else default_outdir

print(f"[+] Reading pcap: {pcap_path}")
try:
    pkts = rdpcap(pcap_path)
except Exception as e:
    print(f"[-] Failed to read pcap: {e}")
    sys.exit(1)

# storage
dns_queries = []
http_urls = []
protocol_counts = Counter()
ip_talkers = Counter()

for p in pkts:
    # protocol counting
    if p.haslayer(ARP):
        protocol_counts['ARP'] += 1
    if p.haslayer(DNS) and p.haslayer(DNSQR):
        protocol_counts['DNS'] += 1
        try:
            qname = p[DNSQR].qname.decode().rstrip('.')
        except Exception:
            qname = str(p[DNSQR].qname)
        src = p[IP].src if p.haslayer(IP) else ""
        dns_queries.append((p.time, src, qname))
    if p.haslayer(TCP):
        protocol_counts['TCP'] += 1
        # HTTP naive extraction
        if p.haslayer(Raw):
            try:
                payload = p[Raw].load.decode('utf-8', errors='ignore')
                if payload.startswith("GET ") or "HTTP/1." in payload:
                    # try to extract host and path
                    lines = payload.split('\r\n')
                    getline = lines[0] if lines else ""
                    host = ""
                    for L in lines:
                        if L.lower().startswith("host:"):
                            host = L.split(":", 1)[1].strip()
                            break
                    path = ""
                    if getline.startswith("GET "):
                        parts = getline.split(" ")
                        if len(parts) > 1:
                            path = parts[1]
                    if host:
                        url = f"http://{host}{path}"
                        http_urls.append((p.time, p[IP].src if p.haslayer(IP) else "", url))
            except Exception:
                pass
    if p.haslayer(UDP):
        protocol_counts['UDP'] += 1
    if p.haslayer(IP):
        ip_talkers[p[IP].src] += 1

# write outputs
os.makedirs(outdir, exist_ok=True)

with open(os.path.join(outdir, "dns_queries.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp","src_ip","query"])
    for row in dns_queries:
        w.writerow([row[0], row[1], row[2]])

with open(os.path.join(outdir, "http_urls.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp","src_ip","url"])
    for row in http_urls:
        w.writerow([row[0], row[1], row[2]])

with open(os.path.join(outdir, "top_talkers.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ip","packet_count"])
    for ip, cnt in ip_talkers.most_common():
        w.writerow([ip, cnt])

with open(os.path.join(outdir, "protocol_counts.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["protocol","count"])
    for prot, cnt in protocol_counts.items():
        w.writerow([prot, cnt])

print(f"[+] Wrote outputs to {outdir}")
print(f"[+] dns_queries: {len(dns_queries)}, http_urls: {len(http_urls)}")
