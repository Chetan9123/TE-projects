# preprocessing/feature_selection.py
"""
Feature selection utilities using correlation, Chi-square, and PCA.
"""

import pandas as pd
from sklearn.decomposition import PCA
from sklearn.feature_selection import chi2, SelectKBest
from sklearn.preprocessing import LabelEncoder

def correlation_filter(df: pd.DataFrame, threshold: float = 0.9) -> pd.DataFrame:
    """Remove one of each pair of highly correlated features."""
    corr_matrix = df.corr().abs()
    upper = corr_matrix.where(
        pd.np.triu(pd.np.ones(corr_matrix.shape), k=1).astype(bool)
    )
    to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
    print(f"Dropping {len(to_drop)} correlated features: {to_drop}")
    return df.drop(columns=to_drop, errors="ignore")


def chi_square_selection(X: pd.DataFrame, y: pd.Series, k: int = 10):
    """Select top k features using Chi-square test."""
    # Encode categorical columns
    X_enc = X.apply(LabelEncoder().fit_transform)
    selector = SelectKBest(chi2, k=k)
    selector.fit(X_enc, y)
    cols = X.columns[selector.get_support()]
    print(f"Selected top {k} features using Chi-square: {list(cols)}")
    return X[cols]


def pca_reduce(df: pd.DataFrame, n_components: int = 5) -> pd.DataFrame:
    """Apply PCA for dimensionality reduction."""
    pca = PCA(n_components=n_components)
    reduced = pca.fit_transform(df.select_dtypes(include="number"))
    pca_df = pd.DataFrame(
        reduced, columns=[f"pca_{i+1}" for i in range(n_components)]
    )
    print(f"Reduced to {n_components} PCA components.")
    return pca_df


if __name__ == "__main__":
    # Demo
    import numpy as np
    df = pd.DataFrame(np.random.rand(100, 8), columns=[f"f{i}" for i in range(8)])
    y = pd.Series(np.random.randint(0, 2, 100))
    df = correlation_filter(df)
    chi_df = chi_square_selection(df, y, k=5)
    pca_df = pca_reduce(df, 3)
    print(chi_df.head(), pca_df.head())
