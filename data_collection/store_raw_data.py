# data_collection/store_raw_data.py
"""
Data storage utilities.
- Save packet dictionaries to JSONL or CSV files
- Optional MongoDB storage (pymongo)

Class: DataStore
Methods:
- save_packet(packet_dict)
- save_bulk(list_of_dicts)
"""

import csv
import json
import logging
import os
from typing import List, Dict, Optional

logger = logging.getLogger("data_collection.store")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

# Optional MongoDB support
try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None


class DataStore:
    def __init__(
        self,
        out_dir: str = "data/raw",
        jsonl_name: str = "packets.jsonl",
        csv_name: str = "packets.csv",
        mongodb_uri: Optional[str] = None,
        mongodb_db: Optional[str] = "ai_ngfw",
        mongodb_collection: Optional[str] = "packets",
    ):
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.jsonl_path = os.path.join(out_dir, jsonl_name)
        self.csv_path = os.path.join(out_dir, csv_name)
        self.mongo = None

        if mongodb_uri and MongoClient:
            try:
                self.mongo = MongoClient(mongodb_uri)[mongodb_db][mongodb_collection]
                logger.info("Connected to MongoDB: %s/%s", mongodb_db, mongodb_collection)
            except Exception as e:
                logger.warning("Failed to connect to MongoDB: %s", e)

    def save_packet(self, pkt: Dict):
        # Append JSON line
        with open(self.jsonl_path, "a", encoding="utf8") as f:
            f.write(json.dumps(pkt, default=str) + "\n")
        # Append CSV (headless; will create header on first write)
        write_header = not os.path.exists(self.csv_path)
        with open(self.csv_path, "a", newline="", encoding="utf8") as cf:
            writer = csv.DictWriter(cf, fieldnames=list(pkt.keys()))
            if write_header:
                writer.writeheader()
            writer.writerow(pkt)
        # Optional mongodb
        if self.mongo:
            try:
                self.mongo.insert_one(pkt)
            except Exception as e:
                logger.debug("Mongo insert failed: %s", e)

    def save_bulk(self, pkts: List[Dict]):
        if not pkts:
            return
        for p in pkts:
            self.save_packet(p)

    def tail_jsonl(self, n: int = 10) -> List[Dict]:
        items = []
        try:
            with open(self.jsonl_path, "r", encoding="utf8") as f:
                lines = f.readlines()[-n:]
            for l in lines:
                items.append(json.loads(l))
        except FileNotFoundError:
            logger.warning("JSONL file not found: %s", self.jsonl_path)
        return items


if __name__ == "__main__":
    # quick demo: parse a pcap then store first N packets
    import argparse
    from parse_pcap import parse_pcap_file

    parser = argparse.ArgumentParser(description="Demo: parse pcap and store packets")
    parser.add_argument("pcap", help="PCAP file to parse")
    parser.add_argument("--n", type=int, default=50)
    parser.add_argument("--out", type=str, default="data/raw")
    parser.add_argument("--mongo", type=str, default=None, help="MongoDB URI")
    args = parser.parse_args()

    ds = DataStore(out_dir=args.out, mongodb_uri=args.mongo)
    count = 0
    for pkt in parse_pcap_file(args.pcap, max_packets=args.n):
        ds.save_packet(pkt)
        count += 1
    print(f"Saved {count} packets to {args.out}")
