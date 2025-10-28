#!/usr/bin/env python3
"""Simple simulator to append synthetic packet JSON lines to data/raw/packets.jsonl
Usage: python tools/simulate_packets.py --count 100
"""
import argparse
import json
import os
import random
import time

def make_packet(i):
    now = time.time()
    pkt = {
        "timestamp": now,
        "src_ip": f"192.168.0.{random.randint(2,254)}",
        "dst_ip": random.choice(["8.8.8.8", "1.1.1.1", "10.0.0.5"]),
        "protocol": random.choice(["TCP","UDP","ICMP"]),
        "length": random.randint(40,1500),
        "id": i
    }
    return pkt


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=200, help="Number of packets to generate")
    parser.add_argument("--out", type=str, default="data/raw/packets.jsonl")
    parser.add_argument("--rate", type=float, default=0.0, help="Delay between packets in seconds (0 = write all immediately)")
    args = parser.parse_args()

    out_dir = os.path.dirname(args.out)
    ensure_dir(out_dir)

    with open(args.out, "a", encoding="utf8") as f:
        for i in range(args.count):
            pkt = make_packet(i)
            f.write(json.dumps(pkt) + "\n")
            if args.rate and i < args.count - 1:
                time.sleep(args.rate)

    print(f"Wrote {args.count} packets to {args.out}")

if __name__ == "__main__":
    main()
