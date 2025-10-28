# ai_detection/model_train.py
"""
Train models for AI detection.
Supports:
- PyTorch (cnn | lstm | hybrid) training loop
- sklearn RandomForest training

Usage (PyTorch example):
python model_train.py --data data/flows.csv --label_col label --model cnn --epochs 20 --save_path ai_detection/saved_models/cnn_model.pt

Usage (RF example):
python model_train.py --data data/flows.csv --label_col label --model rf --save_path ai_detection/saved_models/rf_model.pkl
"""

import argparse
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from model_utils import (
    train_test_split_df,
    fit_scaler,
    transform_df,
    FlowDataset,
    SimpleCNN,
    SimpleLSTM,
    HybridWaveletCNN,
    torch
)

# If torch is None, disable DL options
HAS_TORCH = torch is not None


def train_sklearn_rf(X_train, y_train, X_test, y_test, save_path):
    clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
    joblib.dump(clf, save_path)
    print(f"RandomForest saved to {save_path} | Test acc: {acc:.4f}")
    return acc


def train_pytorch(
    model_name: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    save_path: str,
    epochs: int = 10,
    batch_size: int = 32,
    lr: float = 1e-3,
):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    input_dim = X_train.shape[1]
    num_classes = int(max(y_train.max(), y_val.max()) + 1)

    # Choose model
    if model_name == "cnn":
        model = SimpleCNN(input_dim, num_classes=num_classes)
    elif model_name == "lstm":
        model = SimpleLSTM(input_dim, num_classes=num_classes)
    elif model_name == "hybrid":
        model = HybridWaveletCNN(input_dim, num_classes=num_classes)
    else:
        raise ValueError("Unsupported model_name")

    model = model.to(device)

    # Data loaders
    train_ds = FlowDataset(X_train, y_train)
    val_ds = FlowDataset(X_val, y_val)
    train_loader = torch.utils.data.DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = torch.utils.data.DataLoader(val_ds, batch_size=batch_size, shuffle=False)

    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    best_val = 0.0
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for xb, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)
            optimizer.zero_grad()
            out = model(xb)
            loss = criterion(out, yb)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * xb.size(0)
        avg_loss = total_loss / len(train_loader.dataset)

        # Validation
        model.eval()
        preds = []
        trues = []
        with torch.no_grad():
            for xb, yb in val_loader:
                xb = xb.to(device)
                out = model(xb)
                pred = out.argmax(dim=1).cpu().numpy()
                preds.append(pred)
                trues.append(yb.numpy())
        preds = np.concatenate(preds)
        trues = np.concatenate(trues)
        acc = (preds == trues).mean()
        print(f"Epoch {epoch}/{epochs} | Loss: {avg_loss:.4f} | Val Acc: {acc:.4f}")
        if acc > best_val:
            best_val = acc
            os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
            torch.save(model.state_dict(), save_path)
            print(f"Saved best model (acc={best_val:.4f}) to {save_path}")

    return best_val


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="CSV with features + label column")
    parser.add_argument("--label_col", default="label")
    parser.add_argument("--model", choices=["cnn", "lstm", "hybrid", "rf"], default="rf")
    parser.add_argument("--save_path", default="ai_detection/saved_models/model.pt")
    parser.add_argument("--scaler_path", default="ai_detection/saved_models/scaler.pkl")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch_size", type=int, default=32)
    parser.add_argument("--test_size", type=float, default=0.2)
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    X_train_df, X_test_df, y_train, y_test = train_test_split_df(df, label_col=args.label_col, test_size=args.test_size)

    # Fit and save scaler on numeric features
    scaler = fit_scaler(X_train_df, scaler_path=args.scaler_path)
    X_train = transform_df(X_train_df, scaler)
    X_test = transform_df(X_test_df, scaler)

    if args.model == "rf":
        acc = train_sklearn_rf(X_train, y_train.values, X_test, y_test.values, args.save_path)
        print(f"RF test acc: {acc:.4f}")
    else:
        if not HAS_TORCH:
            raise RuntimeError("PyTorch is not available. Install torch to train DL models.")
        acc = train_pytorch(
            args.model,
            X_train, y_train.values,
            X_test, y_test.values,
            save_path=args.save_path,
            epochs=args.epochs,
            batch_size=args.batch_size
        )
        print(f"Best val acc (DL): {acc:.4f}")


if __name__ == "__main__":
    main()
