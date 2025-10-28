# ai_detection/model_predict.py
"""
Load a saved model and predict on new incoming flow(s).
Accepts CSV or JSON lines. Outputs predictions to stdout or file.

Usage:
python model_predict.py --input data/new_flows.csv --scaler ai_detection/saved_models/scaler.pkl --model ai_detection/saved_models/model.pt --model_type pytorch
"""

import argparse
import pandas as pd
import numpy as np
import joblib
import json
from model_utils import transform_df, load_scaler, torch, FlowDataset, SimpleCNN, SimpleLSTM, HybridWaveletCNN
from model_evaluate import load_model_and_predict

def batch_predict(input_path, scaler_path, model_path, model_type="rf", out_path=None):
    if input_path.endswith(".csv"):
        df = pd.read_csv(input_path)
    else:
        # assume JSONL
        df = pd.read_json(input_path, lines=True)

    X = df  # assume no label column present; if label present user can drop before calling
    scaler = load_scaler(scaler_path)
    X_scaled = transform_df(X, scaler)

    preds, probs = load_model_and_predict(model_path, model_type, X_scaled)

    results = []
    for i, row in enumerate(df.to_dict(orient="records")):
        r = {"input_index": i, "prediction": int(preds[i])}
        if probs is not None:
            r["probabilities"] = probs[i].tolist()
        r.update({"features": row})
        results.append(r)

    if out_path:
        with open(out_path, "w", encoding="utf8") as f:
            for r in results:
                f.write(json.dumps(r) + "\n")
        print("Wrote predictions to", out_path)
    else:
        for r in results:
            print(json.dumps(r))

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="CSV or JSONL file of new flows (no label column)")
    parser.add_argument("--scaler", required=True, help="scaler path")
    parser.add_argument("--model", required=True, help="model path")
    parser.add_argument("--model_type", choices=["rf", "pytorch"], default="rf")
    parser.add_argument("--out", help="Output JSONL path")
    args = parser.parse_args()

    batch_predict(args.input, args.scaler, args.model, args.model_type, args.out)


if __name__ == "__main__":
    main()
