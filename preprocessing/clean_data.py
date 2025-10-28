# preprocessing/clean_data.py
"""
Module to clean raw packet or flow data.

Functions:
- remove_duplicates(df)
- handle_missing(df)
- normalize_numeric(df)
"""

import pandas as pd
from sklearn.preprocessing import MinMaxScaler

def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove exact duplicate rows."""
    before = len(df)
    df = df.drop_duplicates()
    after = len(df)
    print(f"Removed {before - after} duplicate rows.")
    return df


def handle_missing(df: pd.DataFrame) -> pd.DataFrame:
    """Fill or drop missing values depending on column type."""
    num_cols = df.select_dtypes(include="number").columns
    cat_cols = df.select_dtypes(exclude="number").columns

    df[num_cols] = df[num_cols].fillna(df[num_cols].mean())
    df[cat_cols] = df[cat_cols].fillna("Unknown")
    print("Handled missing values (filled numeric with mean, categorical with 'Unknown').")
    return df


def normalize_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize numeric columns to [0,1] range."""
    scaler = MinMaxScaler()
    num_cols = df.select_dtypes(include="number").columns
    df[num_cols] = scaler.fit_transform(df[num_cols])
    print(f"Normalized {len(num_cols)} numeric features.")
    return df


if __name__ == "__main__":
    # Demo with sample CSV
    import sys
    if len(sys.argv) < 2:
        print("Usage: python clean_data.py <data.csv>")
        exit(1)

    df = pd.read_csv(sys.argv[1])
    df = remove_duplicates(df)
    df = handle_missing(df)
    df = normalize_numeric(df)
    print(df.head())
