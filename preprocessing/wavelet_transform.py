# preprocessing/wavelet_transform.py
"""
Wavelet Transform-based feature enhancement for anomaly detection.

Functions:
- apply_wavelet_transform(series, wavelet='db4', level=2)
- extract_wavelet_features(df, column)
"""

import numpy as np
import pandas as pd
import pywt


def apply_wavelet_transform(series: pd.Series, wavelet: str = "db4", level: int = 2):
    """Apply Discrete Wavelet Transform to a numeric series."""
    coeffs = pywt.wavedec(series, wavelet=wavelet, level=level)
    cA, *details = coeffs
    reconstructed = pywt.waverec(coeffs, wavelet)
    return cA, details, reconstructed[:len(series)]


def extract_wavelet_features(df: pd.DataFrame, column: str = "length") -> pd.DataFrame:
    """Extract statistical wavelet coefficients as new features."""
    cA, details, _ = apply_wavelet_transform(df[column].fillna(0))
    df["wavelet_mean"] = np.mean(cA)
    df["wavelet_std"] = np.std(cA)
    for i, d in enumerate(details, start=1):
        df[f"wavelet_d{i}_mean"] = np.mean(d)
        df[f"wavelet_d{i}_std"] = np.std(d)
    print(f"Extracted wavelet features from '{column}'")
    return df


if __name__ == "__main__":
    # Simple test
    import numpy as np
    df = pd.DataFrame({"length": np.random.randint(50, 1500, size=100)})
    df = extract_wavelet_features(df, "length")
    print(df.head())
