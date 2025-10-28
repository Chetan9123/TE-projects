# data_collection/sensors/zeek_logs_parser.py
"""
Parse Zeek (Bro) JSON logs (e.g., conn.log in JSON format).
Converts Zeek connection records into packet/flow-like dicts.

Usage:
- zeek_conn_to_dicts("zeek_conn.json")
"""

import json
import logging
from typing import Iterator, Dict

logger = logging.getLogger("data_collection.zeek")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def zeek_conn_to_dicts(zeek_json_path: str) -> Iterator[Dict]:
    """
    Read a Zeek JSON conn log with one JSON object per line (or an array)
    and yield normalized connection dictionaries.
    """
    logger.info("Parsing Zeek logs: %s", zeek_json_path)
    with open(zeek_json_path, "r", encoding="utf8") as f:
        first = f.read(1)
        f.seek(0)
        if first == "[":
            # JSON array
            entries = json.load(f)
            for e in entries:
                yield _zeek_entry_to_dict(e)
        else:
            # line-delimited JSON
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    yield _zeek_entry_to_dict(e)
                except Exception as ex:
                    logger.debug("Skipping line due to parse error: %s", ex)


def _zeek_entry_to_dict(entry: Dict) -> Dict:
    d = {
        "ts": entry.get("ts"),
        "uid": entry.get("uid"),
        "id_orig_h": entry.get("id", {}).get("orig_h") if isinstance(entry.get("id"), dict) else entry.get("id_orig_h") or entry.get("id.orig_h"),
        "id_resp_h": entry.get("id", {}).get("resp_h") if isinstance(entry.get("id"), dict) else entry.get("id_resp_h") or entry.get("id.resp_h"),
        "id_orig_p": entry.get("id", {}).get("orig_p") if isinstance(entry.get("id"), dict) else entry.get("id_orig_p") or entry.get("id.orig_p"),
        "id_resp_p": entry.get("id", {}).get("resp_p") if isinstance(entry.get("id"), dict) else entry.get("id_resp_p") or entry.get("id.resp_p"),
        "proto": entry.get("proto"),
        "service": entry.get("service"),
        "duration": entry.get("duration"),
        "orig_bytes": entry.get("orig_bytes"),
        "resp_bytes": entry.get("resp_bytes"),
        "conn_state": entry.get("conn_state"),
    }
    return d


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Parse Zeek JSON logs to dicts")
    parser.add_argument("zeekfile", help="Zeek JSON log file (conn.log in JSONL/array)")
    args = parser.parse_args()
    for p in zeek_conn_to_dicts(args.zeekfile):
        print(p)
