from pathlib import Path
import json

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

DATA_DIR = Path("data/raw/smd/machine-1-1")
MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")

train = np.loadtxt(DATA_DIR / "train.txt", delimiter=",")
test = np.loadtxt(DATA_DIR / "test.txt", delimiter=",")
labels = np.loadtxt(DATA_DIR / "test_label.txt", delimiter=",").astype(int)

if train.ndim != 2 or test.ndim != 2:
    raise ValueError("Les données doivent être des matrices à deux dimensions.")
if train.shape[1] != test.shape[1]:
    raise ValueError("Train et test n'ont pas le même nombre de variables.")
if test.shape[0] != labels.shape[0]:
    raise ValueError("Le nombre d'étiquettes ne correspond pas au test.")
if not np.isin(labels, [0, 1]).all():
    raise ValueError("Les étiquettes doivent être 0 ou 1.")
if not np.isfinite(train).all() or not np.isfinite(test).all():
    raise ValueError("Les données contiennent des valeurs non finies.")

print("===== ENTRAINEMENT =====")
print("Observations train :", train.shape[0])
print("Variables :", train.shape[1])
print("Contamination supposée : 0.05")
print("Les étiquettes de test ne sont pas utilisées pour l'entraînement.")

model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42,
    n_jobs=2,
)
model.fit(train)

print("\n===== EVALUATION SUR LE TEST =====")
# Isolation Forest renvoie 1 pour normal et -1 pour anomalie.
predictions = (model.predict(test) == -1).astype(int)

tn, fp, fn, tp = confusion_matrix(
    labels, predictions, labels=[0, 1]
).ravel()

metrics = {
    "dataset": "SMD machine-1-1",
    "model": "IsolationForest",
    "contamination": 0.05,
    "train_rows": int(train.shape[0]),
    "test_rows": int(test.shape[0]),
    "features": int(train.shape[1]),
    "actual_anomalies": int(labels.sum()),
    "predicted_anomalies": int(predictions.sum()),
    "true_negatives": int(tn),
    "false_positives": int(fp),
    "false_negatives": int(fn),
    "true_positives": int(tp),
    "precision": float(precision_score(labels, predictions, zero_division=0)),
    "recall": float(recall_score(labels, predictions, zero_division=0)),
    "f1_score": float(f1_score(labels, predictions, zero_division=0)),
}

print(classification_report(
    labels,
    predictions,
    labels=[0, 1],
    target_names=["normal", "anomalie"],
    zero_division=0,
))
print("Matrice de confusion [[TN, FP], [FN, TP]] :")
print([[int(tn), int(fp)], [int(fn), int(tp)]])
print("Précision :", round(metrics["precision"], 4))
print("Rappel    :", round(metrics["recall"], 4))
print("F1-score  :", round(metrics["f1_score"], 4))

MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)
joblib.dump(model, MODEL_DIR / "isolation_forest_smd_machine-1-1.joblib")

with (REPORT_DIR / "isolation_forest_smd_machine-1-1.json").open(
    "w", encoding="utf-8"
) as f:
    json.dump(metrics, f, indent=2, ensure_ascii=False)

print("\nModèle sauvegardé dans models/")
print("Rapport sauvegardé dans reports/")
print("ENTRAINEMENT ET EVALUATION TERMINES")
