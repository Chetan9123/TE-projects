# ai_detection/model_utils.py
"""
Utilities for dataset handling, PyTorch Dataset and simple preprocessing helpers.
Expect input features as pandas DataFrame (flows/features) and labels as Series.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, Optional

# Try to import PyTorch; if not available we still can use sklearn fallback
try:
    import torch
    from torch.utils.data import Dataset, DataLoader
    import torch.nn as nn
except Exception:
    torch = None
    Dataset = object
    DataLoader = None
    nn = None

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def train_test_split_df(
    df: pd.DataFrame, label_col: str = "label", test_size: float = 0.2, random_state: int = 42
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Split dataframe into train/test and return X_train, X_test, y_train, y_test"""
    X = df.drop(columns=[label_col])
    y = df[label_col]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )
    return X_train, X_test, y_train, y_test


def fit_scaler(X_train: pd.DataFrame, scaler_path: Optional[str] = None):
    """Fit StandardScaler and optionally save to disk"""
    scaler = StandardScaler()
    scaler.fit(X_train)
    if scaler_path:
        os.makedirs(os.path.dirname(scaler_path) or ".", exist_ok=True)
        joblib.dump(scaler, scaler_path)
    return scaler


def load_scaler(scaler_path: str):
    return joblib.load(scaler_path)


def transform_df(X: pd.DataFrame, scaler: StandardScaler) -> np.ndarray:
    """Return numpy array scaled ready for model ingestion"""
    return scaler.transform(X)


# ----------------------------
# PyTorch Dataset (for DL models)
# ----------------------------
if torch is not None:
    class FlowDataset(Dataset):
        def __init__(self, X: np.ndarray, y: np.ndarray = None):
            self.X = torch.tensor(X, dtype=torch.float32)
            self.y = None if y is None else torch.tensor(y, dtype=torch.long)

        def __len__(self):
            return len(self.X)

        def __getitem__(self, idx):
            if self.y is None:
                return self.X[idx]
            return self.X[idx], self.y[idx]


# ----------------------------
# Simple model definitions (PyTorch)
# ----------------------------
if torch is not None:
    class SimpleCNN(nn.Module):
        def __init__(self, input_dim: int, num_classes: int = 2):
            super().__init__()
            # Treat features as 1D "signal" -> conv1d expects (batch, channels, length)
            self.conv = nn.Sequential(
                nn.Conv1d(1, 16, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(16, 32, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.AdaptiveAvgPool1d(1)
            )
            self.fc = nn.Sequential(
                nn.Flatten(),
                nn.Linear(32, 64),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(64, num_classes)
            )

        def forward(self, x):
            # x: (batch, features) -> reshape to (batch, 1, features)
            x = x.unsqueeze(1)
            x = self.conv(x)
            x = self.fc(x)
            return x


    class SimpleLSTM(nn.Module):
        def __init__(self, input_dim: int, hidden_dim: int = 64, num_classes: int = 2, n_layers: int = 1):
            super().__init__()
            self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True, num_layers=n_layers, bidirectional=True)
            self.fc = nn.Sequential(
                nn.Linear(hidden_dim * 2, 64),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(64, num_classes)
            )

        def forward(self, x):
            # x: (batch, features) -> convert to (batch, seq_len=features, feature=1)
            x = x.unsqueeze(-1)
            out, _ = self.lstm(x)
            # take last time-step
            out = out[:, -1, :]
            out = self.fc(out)
            return out


    class HybridWaveletCNN(nn.Module):
        """
        Minimal hybrid: input -> 1D conv (for 'wavelet-like' multi-scale capture) -> fc
        """
        def __init__(self, input_dim: int, num_classes: int = 2):
            super().__init__()
            self.conv_block = nn.Sequential(
                nn.Conv1d(1, 32, kernel_size=5, padding=2),
                nn.ReLU(),
                nn.MaxPool1d(2),
                nn.Conv1d(32, 64, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.AdaptiveAvgPool1d(1)
            )
            self.classifier = nn.Sequential(
                nn.Flatten(),
                nn.Linear(64, 128),
                nn.ReLU(),
                nn.Dropout(0.4),
                nn.Linear(128, num_classes)
            )

        def forward(self, x):
            x = x.unsqueeze(1)
            x = self.conv_block(x)
            x = self.classifier(x)
            return x
