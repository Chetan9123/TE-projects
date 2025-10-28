# preprocessing/feature_extraction.py
"""
Extract useful statistical and protocol-level features from packet data.
Input: DataFrame with raw packet fields (src_ip, dst_ip, sport, dport, length, etc.)
Output: Feature-enhanced DataFrame.
"""

import pandas as pd
import numpy as np

def add_basic_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add common statistical features derived from traffic."""
    df["byte_rate"] = df["length"] / (df["timestamp"].diff().fillna(1))
    df["is_tcp"] = df.get("proto", "").apply(lambda x: 1 if x == 6 else 0)
    df["is_udp"] = df.get("proto", "").apply(lambda x: 1 if x == 17 else 0)
    df["packet_size_diff"] = df["length"].diff().fillna(0).abs()
    print("Added byte_rate, protocol flags, and packet_size_diff features.")
    return df


def aggregate_by_flow(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate packets into flows identified by src_ip, dst_ip, and protocol.
    Generates flow-level statistics.
    """
    flow_keys = ["src_ip", "dst_ip", "proto"]
    grouped = df.groupby(flow_keys).agg({
        "length": ["mean", "std", "max", "min", "count"],
        "byte_rate": ["mean", "std"],
        "packet_size_diff": ["mean", "std"]
    }).reset_index()

    # Flatten multi-level columns
    grouped.columns = ["_".join(col).strip("_") for col in grouped.columns.values]
    print(f"Aggregated {len(grouped)} flows from {len(df)} packets.")
    return grouped


if __name__ == "__main__":
    # Test with synthetic data
    data = {
        "timestamp": np.arange(1, 11),
        "src_ip": ["10.0.0.1"] * 5 + ["10.0.0.2"] * 5,
        "dst_ip": ["8.8.8.8"] * 10,
        "proto": [6] * 10,
        "length": np.random.randint(60, 1500, size=10)
    }
    df = pd.DataFrame(data)
    df = add_basic_features(df)
    flow_df = aggregate_by_flow(df)
    print(flow_df.head())
