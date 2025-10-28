# data_collection/parse_pcap.py
"""
Parse PCAP files to yield normalized packet dictionaries.

Prefer pyshark for rich parsing; fallback to scapy if pyshark unavailable.

Functions:
- parse_pcap_file(pcap_path, max_packets=None)
"""

import logging
from typing import Iterator, Dict

logger = logging.getLogger("data_collection.parse_pcap")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

# Attempt to import pyshark, otherwise fallback to scapy
try:
    import pyshark

    def parse_pcap_file(pcap_path: str, max_packets: int = None) -> Iterator[Dict]:
        logger.info("Parsing PCAP with pyshark: %s", pcap_path)
        cap = pyshark.FileCapture(pcap_path, keep_packets=False)
        i = 0
        for pkt in cap:
            try:
                d = {
                    "timestamp": float(pkt.sniff_timestamp),
                    "summary": str(pkt),
                    "length": int(getattr(pkt, "length", 0)),
                }
                # IP layer
                if hasattr(pkt, "ip"):
                    d.update({"src_ip": pkt.ip.src, "dst_ip": pkt.ip.dst})
                # TCP/UDP
                if hasattr(pkt, "tcp"):
                    d.update({"sport": int(pkt.tcp.srcport), "dport": int(pkt.tcp.dstport)})
                elif hasattr(pkt, "udp"):
                    d.update({"sport": int(pkt.udp.srcport), "dport": int(pkt.udp.dstport)})
                yield d
            except Exception as e:
                logger.debug("Failed to parse packet: %s", e)
            i += 1
            if max_packets and i >= max_packets:
                break
        cap.close()

except Exception:
    # fallback to scapy
    from scapy.all import rdpcap

    def parse_pcap_file(pcap_path: str, max_packets: int = None) -> Iterator[Dict]:
        logger.info("Parsing PCAP with scapy (fallback): %s", pcap_path)
        pkts = rdpcap(pcap_path)
        for i, pkt in enumerate(pkts):
            if max_packets and i >= max_packets:
                break
            try:
                d = {
                    "timestamp": getattr(pkt, "time", None),
                    "summary": pkt.summary(),
                    "length": len(pkt),
                }
                if pkt.haslayer("IP"):
                    ip = pkt.getlayer("IP")
                    d.update({"src_ip": ip.src, "dst_ip": ip.dst})
                if pkt.haslayer("TCP"):
                    tcp = pkt.getlayer("TCP")
                    d.update({"sport": tcp.sport, "dport": tcp.dport})
                elif pkt.haslayer("UDP"):
                    udp = pkt.getlayer("UDP")
                    d.update({"sport": udp.sport, "dport": udp.dport})
                yield d
            except Exception as e:
                logger.debug("Failed to parse packet: %s", e)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Parse a pcap file and print packet dicts")
    parser.add_argument("pcap", help="Path to pcap file")
    parser.add_argument("--max", type=int, default=50, help="Max packets to parse")
    args = parser.parse_args()

    for p in parse_pcap_file(args.pcap, max_packets=args.max):
        print(p)
