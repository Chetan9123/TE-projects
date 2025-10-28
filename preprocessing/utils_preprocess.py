# preprocessing/utils_preprocess.py
"""
Utility functions for data preprocessing pipelines.
Combines cleaning, feature extraction, wavelet transform, and selection.
"""

import pandas as pd
from clean_data import remove_duplicates, handle_missing, normalize_numeric
from feature_extraction import add_basic_features, aggregate_by_flow
from wavelet_transform import extract_wavelet_features
from feature_selection import correlation_filter, pca_reduce


def preprocess_pipeline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Complete preprocessing pipeline:
    1. Clean data
    2. Feature engineering
    3. Wavelet features
    4. Feature selection (correlation + PCA)
    """
    print("=== Starting preprocessing pipeline ===")
    df = remove_duplicates(df)
    df = handle_missing(df)
    df = normalize_numeric(df)

    df = add_basic_features(df)
    df = aggregate_by_flow(df)
    df = extract_wavelet_features(df, column="length_mean")

    df = correlation_filter(df)
    df = pd.concat([df, pca_reduce(df)], axis=1)

    print("=== Preprocessing completed ===")
    return df


if __name__ == "__main__":
    import numpy as np
    data = {
        "timestamp": np.arange(1, 11),
        "src_ip": ["10.0.0.1"] * 5 + ["10.0.0.2"] * 5,
        "dst_ip": ["8.8.8.8"] * 10,
        "proto": [6] * 10,
        "length": np.random.randint(60, 1500, size=10),
    }
    df = pd.DataFrame(data)
    processed = preprocess_pipeline(df)
    print(processed.head())
