# ai_detection/model_evaluate.py
"""
Evaluate a saved model on a test set and print metrics + confusion matrix.
Supports both sklearn RandomForest and PyTorch models.
"""

import argparse
import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from model_utils import transform_df, load_scaler, torch, SimpleCNN, SimpleLSTM, HybridWaveletCNN, FlowDataset

HAS_TORCH = torch is not None

def load_model_and_predict(model_path, model_type, X_scaled):
    """
    model_type: 'rf' or 'pytorch'
    If pytorch, expects file is state_dict and we need to know arch (encoded in filename)
    """
    if model_type == "rf":
        clf = joblib.load(model_path)
        preds = clf.predict(X_scaled)
        if hasattr(clf, "predict_proba"):
            probs = clf.predict_proba(X_scaled)
        else:
            probs = None
        return preds, probs
    else:
        if not HAS_TORCH:
            raise RuntimeError("PyTorch not installed.")
        # Infer model arch from filename (simple heuristic)
        arch = "cnn"
        if "lstm" in model_path.lower():
            arch = "lstm"
        elif "hybrid" in model_path.lower():
            arch = "hybrid"

        input_dim = X_scaled.shape[1]
        num_classes = 2
        if arch == "cnn":
            model = SimpleCNN(input_dim, num_classes=num_classes)
        elif arch == "lstm":
            model = SimpleLSTM(input_dim, num_classes=num_classes)
        else:
            model = HybridWaveletCNN(input_dim, num_classes=num_classes)
        model.load_state_dict(torch.load(model_path, map_location=torch.device("cpu")))
        model.eval()

        ds = FlowDataset(X_scaled)
        loader = torch.utils.data.DataLoader(ds, batch_size=128, shuffle=False)
        preds = []
        probs = []
        with torch.no_grad():
            for xb in loader:
                out = model(xb)
                p = out.argmax(dim=1).numpy()
                preds.append(p)
                probs.append(torch.softmax(out, dim=1).numpy())
        preds = np.concatenate(preds)
        probs = np.concatenate(probs)
        return preds, probs


def plot_confusion(cm, labels, out_path=None):
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(xticks=np.arange(cm.shape[1]), yticks=np.arange(cm.shape[0]), xticklabels=labels, yticklabels=labels, ylabel="True label", xlabel="Predicted label", title="Confusion matrix")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], "d"), ha="center", va="center", color="white" if cm[i, j] > thresh else "black")
    fig.tight_layout()
    if out_path:
        fig.savefig(out_path)
        print("Saved confusion matrix plot to", out_path)
    return fig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="CSV with features + label")
    parser.add_argument("--label_col", default="label")
    parser.add_argument("--scaler", required=True, help="Path to scaler.pkl")
    parser.add_argument("--model", required=True, help="Path to saved model (.pkl or .pt)")
    parser.add_argument("--model_type", choices=["rf", "pytorch"], default="rf")
    parser.add_argument("--out", default="ai_detection/saved_models/confusion.png")
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    X = df.drop(columns=[args.label_col])
    y = df[args.label_col].values

    scaler = load_scaler(args.scaler)
    X_scaled = transform_df(X, scaler)

    preds, probs = load_model_and_predict(args.model, args.model_type, X_scaled)
    print("Accuracy:", accuracy_score(y, preds))
    print("Classification report:\n", classification_report(y, preds))

    cm = confusion_matrix(y, preds)
    plot_confusion(cm, labels=[0,1], out_path=args.out)


if __name__ == "__main__":
    main()
