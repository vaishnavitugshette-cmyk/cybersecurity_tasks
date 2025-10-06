#!/usr/bin/env python3
"""
sniffer.py
Simple packet sniffer using scapy.
Usage (linux):
  sudo python3 sniffer.py -i eth0 -c 200 -f "tcp or udp" -o capture.pcap
or run indefinitely (Ctrl-C to stop):
  sudo python3 sniffer.py -i eth0 -o capture.pcap
"""
import argparse
import time
import signal
from scapy.all import sniff, wrpcap, IP, TCP, UDP, Raw

PACKETS_BUFFER = []
OUTFILE = None

def process_packet(pkt):
    global PACKETS_BUFFER
    info = {"time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}
    if pkt.haslayer(IP):
        info["src"] = pkt[IP].src
        info["dst"] = pkt[IP].dst
    else:
        info["src"] = None
        info["dst"] = None

    if pkt.haslayer(TCP):
        info["proto"] = "TCP"
        info["sport"] = pkt[TCP].sport
        info["dport"] = pkt[TCP].dport
        info["flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        info["proto"] = "UDP"
        info["sport"] = pkt[UDP].sport
        info["dport"] = pkt[UDP].dport
    else:
        info["proto"] = pkt.lastlayer().name if pkt.layers() else "OTHER"

    # payload snippet if present
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        info["payload_len"] = len(raw)
        try:
            info["payload_snippet"] = raw[:120].decode("utf-8", errors="replace")
        except Exception:
            info["payload_snippet"] = str(raw[:120])
    else:
        info["payload_len"] = 0
        info["payload_snippet"] = ""

    # print concise summary
    print(f"[{info['time']}] {info['src']}:{info.get('sport','-')} -> {info['dst']}:{info.get('dport','-')} "
          f"{info['proto']} len={info['payload_len']} flags={info.get('flags','')}")
    if info['payload_snippet']:
        print("   ", info['payload_snippet'].replace("\n"," ")[:200])

    PACKETS_BUFFER.append(pkt)
    # flush to disk every 100 packets to avoid memory issues
    if len(PACKETS_BUFFER) >= 100:
        wrpcap(OUTFILE, PACKETS_BUFFER, append=True)
        PACKETS_BUFFER = []

def graceful_exit(signum, frame):
    global PACKETS_BUFFER
    print("\nStopping capture, writing remaining packets...")
    if PACKETS_BUFFER:
        wrpcap(OUTFILE, PACKETS_BUFFER, append=True)
    print("Done.")
    exit(0)

def main():
    global OUTFILE
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", default="Wi-Fi", help="interface to listen on (e.g. eth0)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter (e.g. "tcp port 80")')
    parser.add_argument("-o", "--outfile", default="capture.pcap", help="pcap output file")
    args = parser.parse_args()

    OUTFILE = args.outfile
    print("Press Ctrl-C to stop.")
    signal.signal(signal.SIGINT, graceful_exit)

    sniff(prn=process_packet, iface=args.iface, filter=args.filter or None,
          count=args.count if args.count > 0 else 0, store=False)

if __name__ == "__main__":
    main()

