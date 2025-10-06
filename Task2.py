#!/usr/bin/env python3
"""
Task2.py — Final robust NIDS

- Signature detection: SQLi-like, XSS-like, Directory-Traversal
- SYN flood detection
- Port-scan detection
- Optional blacklist file (-b)
- Live sniff mode (requires scapy + npcap + admin on Windows)
- Dry-run simulation mode (--dry-run) which always generates alerts for testing

Usage:
  python Task2.py --dry-run
  python Task2.py -i "<iface>" -f "tcp"
"""
import argparse
import re
import time
import json
import sys
import threading
import random
from collections import defaultdict, deque

# Try to import scapy; if not available we'll run simulation.
SCAPY_AVAILABLE = True
try:
    from scapy.all import sniff, IP, TCP, Raw, conf, get_if_list
except Exception:
    SCAPY_AVAILABLE = False
    IP = "IP"
    TCP = "TCP"
    Raw = "Raw"

# Defaults
SYN_RATE_THRESHOLD = 50
PORTSCAN_PORTS_THRESHOLD = 20
WINDOW = 10
ALERT_COOLDOWN = 60

SIGNATURES = [
    {
        "name": "SQLi-like",
        "pattern": re.compile(
            rb"(union\s+select|select.+from|drop\s+table|insert\s+into|delete\s+from|'\s*or\s*'1'\s*=\s*'1)",
            re.I
        )
    },
    {
        "name": "XSS-like",
        "pattern": re.compile(
            rb"(<script[^>]*>|javascript:|onerror\s*=|onload\s*=)",
            re.I
        )
    },
    {
        "name": "Directory-Traversal",
        "pattern": re.compile(
            rb"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow)",
            re.I
        )
    },
]

BLACKLIST = set()
syn_times = defaultdict(deque)
portscan_map = defaultdict(lambda: defaultdict(lambda: deque()))
last_alert_time = {}

ALERT_LOG = "alerts.jsonl"
CLEANUP_INTERVAL = 300
last_cleanup = time.time()

stats = {"packets_processed": 0, "alerts_generated": 0, "errors": 0}


def load_blacklist(filepath):
    try:
        with open(filepath, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    BLACKLIST.add(ip)
        print(f"[INFO] Loaded {len(BLACKLIST)} IP(s) into blacklist")
    except FileNotFoundError:
        print(f"[WARNING] Blacklist file '{filepath}' not found")
    except Exception as e:
        print(f"[ERROR] Failed to load blacklist: {e}")
        stats["errors"] += 1


def safe_write_alert(alert):
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"[ERROR] Could not write to {ALERT_LOG}: {e}")
        stats["errors"] += 1


def log_alert(alert):
    alert["detected_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print("=" * 60)
    print("ALERT:", json.dumps(alert, indent=2))
    print("=" * 60)
    stats["alerts_generated"] += 1
    safe_write_alert(alert)


def should_alert(alert_type, key, cooldown=ALERT_COOLDOWN):
    now = time.time()
    akey = (alert_type, key)
    if akey in last_alert_time and (now - last_alert_time[akey]) < cooldown:
        return False
    last_alert_time[akey] = now
    return True


def cleanup_old_data(window=WINDOW):
    global last_cleanup
    now = time.time()
    if now - last_cleanup < CLEANUP_INTERVAL:
        return
    for src in list(syn_times.keys()):
        dq = syn_times[src]
        while dq and now - dq[0] > window * 2:
            dq.popleft()
        if not dq:
            del syn_times[src]
    for src in list(portscan_map.keys()):
        for dst in list(portscan_map[src].keys()):
            dq = portscan_map[src][dst]
            while dq and now - dq[0][1] > window * 2:
                dq.popleft()
            if not dq:
                del portscan_map[src][dst]
        if not portscan_map[src]:
            del portscan_map[src]
    for k in list(last_alert_time.keys()):
        if now - last_alert_time[k] > ALERT_COOLDOWN * 2:
            del last_alert_time[k]
    last_cleanup = now


# Robust helpers to support both real scapy packets and simulator FakePacket
def pkt_haslayer(pkt, layer_name):
    try:
        # If scapy is available, prefer class-based check
        if SCAPY_AVAILABLE and not isinstance(layer_name, str):
            try:
                return pkt.haslayer(layer_name)
            except Exception:
                pass
        # Try string-based haslayer
        if hasattr(pkt, "haslayer"):
            try:
                name = layer_name if isinstance(layer_name, str) else getattr(layer_name, "__name__", str(layer_name))
                return pkt.haslayer(name)
            except Exception:
                pass
        # If pkt implements _layers (simulator), check keys
        if hasattr(pkt, "_layers"):
            name = layer_name if isinstance(layer_name, str) else getattr(layer_name, "__name__", str(layer_name))
            return name in getattr(pkt, "_layers", {})
    except Exception:
        return False
    return False


def pkt_get(pkt, layer_name):
    try:
        if SCAPY_AVAILABLE and not isinstance(layer_name, str):
            try:
                if pkt.haslayer(layer_name):
                    return pkt[layer_name]
            except Exception:
                pass
        # Try mapping names to scapy classes if possible
        if SCAPY_AVAILABLE and isinstance(layer_name, str):
            try:
                if layer_name == "IP" and pkt.haslayer(IP):
                    return pkt[IP]
                if layer_name == "TCP" and pkt.haslayer(TCP):
                    return pkt[TCP]
                if layer_name == "Raw" and pkt.haslayer(Raw):
                    return pkt[Raw]
            except Exception:
                pass
        # Simulator-like dict access
        if hasattr(pkt, "__getitem__"):
            try:
                key = layer_name if isinstance(layer_name, str) else getattr(layer_name, "__name__", str(layer_name))
                return pkt[key]
            except Exception:
                pass
        # Fallback attribute access
        if hasattr(pkt, layer_name):
            return getattr(pkt, layer_name)
    except Exception:
        return None
    return None


def check_signatures(pkt):
    try:
        if not pkt_haslayer(pkt, "Raw"):
            return None
        raw = pkt_get(pkt, "Raw")
        payload = getattr(raw, "load", raw)
        if isinstance(payload, str):
            payload = payload.encode(errors="ignore")
        for sig in SIGNATURES:
            if sig["pattern"].search(payload):
                ip_layer = pkt_get(pkt, "IP")
                tcp_layer = pkt_get(pkt, "TCP")
                src = getattr(ip_layer, "src", None)
                dst = getattr(ip_layer, "dst", None)
                sport = getattr(tcp_layer, "sport", None)
                dport = getattr(tcp_layer, "dport", None)
                key = f"{src}:{sig['name']}"
                if should_alert("signature", key):
                    return {"type": "signature", "signature": sig["name"], "src": src, "dst": dst, "sport": sport, "dport": dport}
    except Exception as e:
        stats["errors"] += 1
        print(f"[ERROR] check_signatures: {e}")
    return None


def check_blacklist(pkt):
    try:
        if not pkt_haslayer(pkt, "IP"):
            return None
        ip_layer = pkt_get(pkt, "IP")
        src = getattr(ip_layer, "src", None)
        dst = getattr(ip_layer, "dst", None)
        if src in BLACKLIST:
            if should_alert("blacklist", src):
                return {"type": "blacklist", "src": src, "dst": dst}
    except Exception as e:
        stats["errors"] += 1
        print(f"[ERROR] check_blacklist: {e}")
    return None


def check_syn_flood(pkt):
    try:
        if not (pkt_haslayer(pkt, "TCP") and pkt_haslayer(pkt, "IP")):
            return None
        ip_layer = pkt_get(pkt, "IP")
        tcp_layer = pkt_get(pkt, "TCP")
        flags = getattr(tcp_layer, "flags", 0)
        if (flags & 0x02) and not (flags & 0x10):
            src = getattr(ip_layer, "src", None)
            now = time.time()
            dq = syn_times[src]
            dq.append(now)
            while dq and now - dq[0] > WINDOW:
                dq.popleft()
            if len(dq) > SYN_RATE_THRESHOLD:
                if should_alert("syn_flood", src):
                    return {"type": "syn_flood", "src": src, "count": len(dq), "window": WINDOW, "threshold": SYN_RATE_THRESHOLD}
    except Exception as e:
        stats["errors"] += 1
        print(f"[ERROR] check_syn_flood: {e}")
    return None


def check_portscan(pkt):
    try:
        if not (pkt_haslayer(pkt, "TCP") and pkt_haslayer(pkt, "IP")):
            return None
        ip_layer = pkt_get(pkt, "IP")
        tcp_layer = pkt_get(pkt, "TCP")
        src = getattr(ip_layer, "src", None)
        dst = getattr(ip_layer, "dst", None)
        dport = getattr(tcp_layer, "dport", None)
        now = time.time()
        dq = portscan_map[src][dst]
        dq.append((dport, now))
        while dq and now - dq[0][1] > WINDOW:
            dq.popleft()
        unique_ports = {p for p, ts in dq}
        if len(unique_ports) >= PORTSCAN_PORTS_THRESHOLD:
            key = f"{src}:{dst}"
            if should_alert("port_scan", key):
                return {"type": "port_scan", "src": src, "dst": dst, "unique_ports": len(unique_ports), "window": WINDOW, "threshold": PORTSCAN_PORTS_THRESHOLD, "ports": sorted(list(unique_ports))[:10]}
    except Exception as e:
        stats["errors"] += 1
        print(f"[ERROR] check_portscan: {e}")
    return None


def handle_packet(pkt):
    try:
        if not pkt_haslayer(pkt, "IP"):
            return
        stats["packets_processed"] += 1
        cleanup_old_data()
        for fn in (check_blacklist, check_signatures, check_syn_flood, check_portscan):
            alert = fn(pkt)
            if alert:
                log_alert(alert)
    except Exception as e:
        stats["errors"] += 1
        print(f"[ERROR] handle_packet: {e}")


# Simulator fake packets
class FakeLayer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakePacket:
    def __init__(self, ip_src="192.168.1.2", ip_dst="192.168.1.10", sport=12345, dport=80, flags=0x02, raw_load=b""):
        self._layers = {}
        self._layers["IP"] = FakeLayer(src=ip_src, dst=ip_dst)
        self._layers["TCP"] = FakeLayer(sport=sport, dport=dport, flags=flags)
        self._layers["Raw"] = FakeLayer(load=raw_load)

    def haslayer(self, name):
        if isinstance(name, str):
            return name in self._layers
        try:
            nm = getattr(name, "__name__", None)
            return nm in self._layers if nm else False
        except Exception:
            return False

    def __getitem__(self, name):
        key = name if isinstance(name, str) else getattr(name, "__name__", str(name))
        return self._layers.get(key, None)


def simulator_thread(target_ip=None, target_port=80, interval=1.0):
    sample_payloads = [
        b"GET /?q=1' OR '1'='1 HTTP/1.1\r\nHost: test\r\n\r\n",
        b"GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: test\r\n\r\n",
        b"GET /?q=../../../../etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n"
    ]
    ports_for_scan = list(range(1000, 1000 + PORTSCAN_PORTS_THRESHOLD + 5))
    idx = 0
    while True:
        if idx % 5 == 0:
            payload = random.choice(sample_payloads)
            pkt = FakePacket(ip_src="10.0.0.5", ip_dst=target_ip or "192.168.1.10", sport=random.randint(1024, 65535), dport=target_port, flags=0x18, raw_load=payload)
            handle_packet(pkt)
        else:
            dport = ports_for_scan[(idx // 1) % len(ports_for_scan)]
            pkt = FakePacket(ip_src="10.0.0.6", ip_dst=target_ip or "192.168.1.10", sport=random.randint(1024, 65535), dport=dport, flags=0x02, raw_load=b"")
            handle_packet(pkt)
        idx += 1
        time.sleep(interval)


def print_stats():
    print("\n" + "=" * 60)
    print("STATISTICS:")
    print(f"  Packets processed: {stats['packets_processed']}")
    print(f"  Alerts generated: {stats['alerts_generated']}")
    print(f"  Errors encountered: {stats['errors']}")
    print("=" * 60 + "\n")


def main():
    global SYN_RATE_THRESHOLD, PORTSCAN_PORTS_THRESHOLD, WINDOW, ALERT_COOLDOWN

    parser = argparse.ArgumentParser(description="Simple NIDS (final)")
    parser.add_argument("-i", "--iface", help="Network interface to listen on (scapy name or NPF device)")
    parser.add_argument("-f", "--filter", default="tcp", help="BPF filter (default: tcp)")
    parser.add_argument("-b", "--blacklist", help="Path to blacklist file (one IP per line)")
    parser.add_argument("--syn-threshold", type=int, default=SYN_RATE_THRESHOLD, help=f"SYN flood threshold (default {SYN_RATE_THRESHOLD})")
    parser.add_argument("--portscan-threshold", type=int, default=PORTSCAN_PORTS_THRESHOLD, help=f"Port scan threshold (default {PORTSCAN_PORTS_THRESHOLD})")
    parser.add_argument("--window", type=int, default=WINDOW, help=f"Detection window in seconds (default {WINDOW})")
    parser.add_argument("--alert-cooldown", type=int, default=ALERT_COOLDOWN, help=f"Alert cooldown (default {ALERT_COOLDOWN}s)")
    parser.add_argument("--dry-run", action="store_true", help="Don't sniff live traffic; simulate packets locally")
    args = parser.parse_args()

    SYN_RATE_THRESHOLD = args.syn_threshold
    PORTSCAN_PORTS_THRESHOLD = args.portscan_threshold
    WINDOW = args.window
    ALERT_COOLDOWN = args.alert_cooldown

    if args.blacklist:
        load_blacklist(args.blacklist)

    iface = args.iface
    if not iface and SCAPY_AVAILABLE:
        try:
            iface = conf.iface
        except Exception:
            iface = None

    print("=" * 60)
    print("Starting Simple NIDS")
    print("=" * 60)
    print(f"Interface: {iface if iface else '(none specified)'}")
    print(f"BPF Filter: {args.filter}")
    print(f"Alert log: {ALERT_LOG}")
    print(f"SYN flood threshold: {SYN_RATE_THRESHOLD} SYNs/{WINDOW}s")
    print(f"Port scan threshold: {PORTSCAN_PORTS_THRESHOLD} ports/{WINDOW}s")
    print(f"Alert cooldown: {ALERT_COOLDOWN}s")
    print(f"Dry-run mode: {args.dry_run or (not SCAPY_AVAILABLE)}")
    print("=" * 60 + "\n")

    use_simulator = args.dry_run or (not SCAPY_AVAILABLE)

    if use_simulator:
        if not SCAPY_AVAILABLE:
            print("[INFO] Scapy not available — running in dry-run simulation mode.")
        else:
            print("[INFO] Dry-run mode forced.")
        t = threading.Thread(target=simulator_thread, kwargs={"target_ip": None, "target_port": 8000, "interval": 1.0}, daemon=True)
        t.start()
        try:
            while True:
                time.sleep(5)
                print(f"[INFO] packets_processed={stats['packets_processed']} alerts_generated={stats['alerts_generated']}")
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down simulation...")
            print_stats()
            sys.exit(0)
    else:
        try:
            print("[INFO] Attempting live sniff. Run as Administrator on Windows.")
            sniff(iface=iface, prn=handle_packet, filter=args.filter, store=False)
        except KeyboardInterrupt:
            print("\n[INFO] Shutting down (KeyboardInterrupt).")
            print_stats()
            sys.exit(0)
        except Exception as e:
            print(f"[FATAL] Live sniff failed: {e}")
            print("[INFO] Falling back to dry-run simulation.")
            t = threading.Thread(target=simulator_thread, kwargs={"target_ip": None, "target_port": 8000, "interval": 1.0}, daemon=True)
            t.start()
            try:
                while True:
                    time.sleep(5)
                    print(f"[INFO] packets_processed={stats['packets_processed']} alerts_generated={stats['alerts_generated']}")
            except KeyboardInterrupt:
                print("\n[INFO] Shutting down simulation...")
                print_stats()
                sys.exit(0)


if __name__ == "__main__":
    main()
