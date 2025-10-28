# dashboard/visualizations.py
"""
Helpers to read logs and transform them into JSON suitable for Plotly on frontend.
"""

import json
import os
from typing import List, Dict, Any
from collections import Counter
from datetime import datetime


def _safe_load_jsonl(path: str, n: int = 100) -> List[Dict[str, Any]]:
    items = []
    if not os.path.exists(path):
        return items
    try:
        with open(path, "r", encoding="utf8") as f:
            lines = f.readlines()[-n:]
        for l in lines:
            l = l.strip()
            if not l:
                continue
            try:
                items.append(json.loads(l))
            except Exception:
                # try parsing as plain dict repr fallback
                try:
                    items.append(eval(l))
                except Exception:
                    pass
    except Exception:
        pass
    return items


def read_recent_packets(jsonl_path: str, n: int = 200) -> List[Dict[str, Any]]:
    """
    Reads the JSONL produced by store_raw_data (packets.jsonl).
    Each line is expected to be a dict with keys like timestamp, src_ip, dst_ip, length, etc.
    """
    return _safe_load_jsonl(jsonl_path, n=n)


def read_actions_log(actions_log_path: str, n: int = 200) -> List[Dict[str, Any]]:
    """
    Actions log is JSONL entries written by response_automation.log_action
    """
    return _safe_load_jsonl(actions_log_path, n=n)


def read_rules_file(rules_path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(rules_path):
        return []
    try:
        with open(rules_path, "r", encoding="utf8") as f:
            return json.load(f)
    except Exception:
        return []


def summarize_traffic_for_plotly(pkts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Create simple aggregates:
      - top_src: top source IPs
      - top_dst: top destination IPs
      - size_time_series: list of (ts, bytes)
    """
    top_src = Counter()
    top_dst = Counter()
    time_series = []

    for p in pkts:
        src = p.get("src_ip") or p.get("id_orig_h") or "unknown"
        dst = p.get("dst_ip") or p.get("id_resp_h") or "unknown"
        top_src[src] += 1
        top_dst[dst] += 1
        ts = p.get("timestamp") or p.get("ts") or p.get("time") or None
        try:
            tsf = float(ts) if ts is not None else None
        except Exception:
            # try parsing ISO
            try:
                tsf = datetime.fromisoformat(ts).timestamp()
            except Exception:
                tsf = None
        length = p.get("length") or p.get("orig_bytes") or p.get("resp_bytes") or 0
        time_series.append({"ts": tsf, "bytes": length})

    # compact top lists
    top_src_list = [{"ip": ip, "count": c} for ip, c in top_src.most_common(10)]
    top_dst_list = [{"ip": ip, "count": c} for ip, c in top_dst.most_common(10)]

    # prepare timeseries sorted by ts and aggregated per minute for plotting
    series = {}
    for e in time_series:
        ts = e["ts"]
        if ts is None:
            continue
        minute = int(ts) - (int(ts) % 60)
        series.setdefault(minute, 0)
        series[minute] += int(e.get("bytes") or 0)

    times = sorted(series.items())
    times_x = [t for t, _ in times]
    times_y = [v for _, v in times]

    return {"top_src": top_src_list, "top_dst": top_dst_list, "time_x": times_x, "time_y": times_y}
