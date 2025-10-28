# zero_trust_control/trust_score_model.py
"""
Optional ML model for generating trust scores from features.

This example uses a lightweight sklearn LogisticRegression to compute a probability
score in [0,1] representing trust. In production you may use a richer model or
an ensemble that considers device posture, user behavior, historical incidents, etc.
"""

import os
import joblib
import numpy as np
import pandas as pd
import logging
from typing import Optional

logger = logging.getLogger("zero_trust.trustscore")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
except Exception:
    LogisticRegression = None
    StandardScaler = None


class TrustScoreModel:
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.scaler = None
        self.model_path = model_path
        if model_path and os.path.exists(model_path):
            self.load(model_path)

    def fit(self, X: pd.DataFrame, y: pd.Series, save_path: Optional[str] = None):
        """
        Fit a simple logistic regression trust model.
        X: features DataFrame (numeric)
        y: binary trust label (1 trusted, 0 not trusted)
        """
        if LogisticRegression is None:
            raise RuntimeError("scikit-learn required for TrustScoreModel")

        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X)
        self.model = LogisticRegression(max_iter=1000)
        self.model.fit(Xs, y)
        logger.info("Trained TrustScoreModel on %d samples", len(X))
        if save_path:
            os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
            joblib.dump({"model": self.model, "scaler": self.scaler}, save_path)
            logger.info("Saved TrustScoreModel to %s", save_path)
            self.model_path = save_path

    def predict_score(self, X: pd.DataFrame) -> np.ndarray:
        """Return float scores in [0,1]"""
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model not trained or loaded")
        Xs = self.scaler.transform(X)
        probs = self.model.predict_proba(Xs)[:, 1]
        return probs

    def load(self, path: str):
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        logger.info("Loaded TrustScoreModel from %s", path)
