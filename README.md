# DAT505 — Lab 2: ARP Spoofing & DNS MitM with Scapy

**Course:** Ethical Hacking (DAT505)

> **Warning:** **Academic use only.** Run **only** in an isolated lab network / private VMs. Do **not** run on public or production networks.

Files:

* `arp_spoof.py` — ARP cache poisoning
* `dns_spoof.py` — selective DNS spoofing (needs a targets list)
* `traffic_interceptor.py` — packet capture/helpers
* `pcap_files/` — packet capture files
* `evidence/` — screenshots & other evidence

Example usages (sudo):

```bash
# ARP Spoofing
sudo python3 arp_spoof.py -v 192.168.128.3 -g 192.168.128.4 -i eth0 --enable-forward --verbose
```

```bash
# DNS spoofing
sudo python3 dns_spoof.py --iface eth0 --targets targets.txt --attacker-ip 192.168.128.2 --mode whitelist --forward 192.168.128.4
```

Dependencies:

```bash
pip install -r requirements.txt
```
