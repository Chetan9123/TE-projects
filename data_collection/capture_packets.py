# data_collection/capture_packets.py
"""
Live packet capture utilities using scapy.
Requires root/admin privileges to sniff on interfaces.

Functions:
- capture_live(interface, duration=None, count=None, output_pcap=None, filter=None)
- packet_to_dict(pkt)  -> normalized metadata dict for storage
"""

import argparse
import logging
import os
import time
from typing import List, Dict, Optional

try:
    from scapy.all import sniff, wrpcap, Packet
except Exception as e:
    raise ImportError(
        "scapy is required for capture_packets.py. Install with: pip install scapy"
    ) from e

# Configure small logger for the module
logger = logging.getLogger("data_collection.capture")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def packet_to_dict(pkt: "Packet") -> Dict:
    """
    Convert a scapy packet to a simplified dict with useful metadata.
    This is intentionally conservative (no full payload unless needed).
    """
    d = {
        "timestamp": getattr(pkt, "time", time.time()),
        "summary": pkt.summary(),
        "has_payload": bytes(pkt.payload) != b"",
    }
    # IP layer
    if pkt.haslayer("IP"):
        ip = pkt.getlayer("IP")
        d.update(
            {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ttl": ip.ttl,
                "proto": ip.proto,
            }
        )
    # TCP/UDP
    if pkt.haslayer("TCP"):
        tcp = pkt.getlayer("TCP")
        d.update(
            {
                "sport": tcp.sport,
                "dport": tcp.dport,
                "flags": str(tcp.flags),
                "seq": tcp.seq,
            }
        )
    elif pkt.haslayer("UDP"):
        udp = pkt.getlayer("UDP")
        d.update({"sport": udp.sport, "dport": udp.dport})

    # Basic length info
    d["length"] = len(pkt)

    return d


def capture_live(
    interface: str = None,
    duration: int = None,
    count: int = None,
    output_pcap: str = None,
    bpf_filter: str = None,
    datastore: Optional[object] = None,
) -> List[Dict]:
    """
    Capture live packets using scapy.sniff and return a list of packet dicts.

    - interface: network interface to sniff (e.g., 'eth0', 'wlan0'). If None, default interface used.
    - duration: seconds to run the capture (mutually exclusive with count)
    - count: number of packets to capture
    - output_pcap: if provided, the pcap filename to store the raw capture
    - bpf_filter: tcpdump-style BPF filter string e.g. "tcp and port 80"
    """
    logger.info("Starting live capture. interface=%s duration=%s count=%s filter=%s",
                interface, duration, count, bpf_filter)
    sniff_args = {}
    if interface:
        sniff_args["iface"] = interface
    if count:
        sniff_args["count"] = count
    if duration:
        sniff_args["timeout"] = duration
    if bpf_filter:
        sniff_args["filter"] = bpf_filter

    pkts = sniff(**sniff_args)
    logger.info("Captured %d packets", len(pkts))

    if output_pcap:
        # Save raw pcap for later parsing/training
        os.makedirs(os.path.dirname(output_pcap) or ".", exist_ok=True)
        wrpcap(output_pcap, pkts)
        logger.info("Saved PCAP to %s", output_pcap)

    dicts = [packet_to_dict(p) for p in pkts]
    # If a DataStore-like object is provided, persist the packets
    # DataStore implements `save_bulk(list_of_dicts)` and `save_packet(dict)`
    if datastore:
        try:
            datastore.save_bulk(dicts)
            logger.info("Saved %d packets via DataStore", len(dicts))
        except Exception as e:
            logger.warning("Failed to save packets via DataStore: %s", e)

    return dicts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Capture live packets (needs root privileges)."
    )
    parser.add_argument("--iface", type=str, help="Interface to sniff on (eg. eth0)")
    parser.add_argument("--duration", type=int, help="Seconds to sniff for")
    parser.add_argument("--count", type=int, help="Number of packets to capture")
    parser.add_argument("--out", type=str, help="Output pcap filename (optional)")
    parser.add_argument("--filter", type=str, help="BPF filter (e.g. 'tcp')")
    parser.add_argument("--save", action="store_true", help="Save captured packets to data/raw/packets.jsonl via DataStore")
    args = parser.parse_args()
    datastore = None
    if args.save:
        # instantiate DataStore and pass into capture_live so packets are persisted
        from data_collection.store_raw_data import DataStore
        datastore = DataStore(out_dir="data/raw")

    results = capture_live(
        interface=args.iface,
        duration=args.duration,
        count=args.count,
        output_pcap=args.out,
        bpf_filter=args.filter,
        datastore=datastore,
    )
    print(f"Captured {len(results)} packets (summaries):")
    for r in results[:10]:
        print(r)
