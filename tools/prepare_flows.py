"""tools/prepare_flows.py
Create a flows CSV from data/raw/packets.jsonl for model training.
Usage: python tools/prepare_flows.py --in data/raw/packets.jsonl --out data/flows.csv
"""
import argparse
import json
import os
import sys
import pandas as pd

# Ensure project root is on sys.path so we can import local packages when script run from tools/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from preprocessing.feature_extraction import add_basic_features, aggregate_by_flow


def load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="input", default="data/raw/packets.jsonl")
    parser.add_argument("--out", dest="output", default="data/flows.csv")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    rows = load_jsonl(args.input)
    if not rows:
        print(f"No packets found in {args.input}")
        return

    df = pd.DataFrame(rows)
    # ensure fields
    for c in ["timestamp", "src_ip", "dst_ip", "proto", "length"]:
        if c not in df.columns:
            df[c] = 0

    # basic features
    df = add_basic_features(df)
    flow_df = aggregate_by_flow(df)

    # simple labeling: mark flows with mean length above median as malicious (1)
    if "length_mean" in flow_df.columns:
        med = flow_df["length_mean"].median()
        flow_df["label"] = (flow_df["length_mean"] > med).astype(int)
    else:
        flow_df["label"] = 0

    # drop non-numeric identifier cols to make features (model expects numeric features)
    out_df = flow_df.copy()
    for col in [c for c in out_df.columns if c.lower().startswith("src_ip") or c.lower().startswith("dst_ip")]:
        out_df = out_df.drop(columns=[col])
    # replace any NaN/inf with 0
    out_df = out_df.replace([pd.NA, float("inf"), float("-inf")], 0).fillna(0)

    out_df.to_csv(args.output, index=False)
    print(f"Written {len(out_df)} flows to {args.output}")


if __name__ == "__main__":
    main()
