import pandas as pd
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
import joblib

def train_baseline(csv_path="data/generated_paths_full.csv"):
    print("Loading dataset...")
    df = pd.read_csv(csv_path)
    
    trained_features = [
        "path_length", 
        "total_weight", 
        "avg_weight", 
        "deviation_from_shortest",
        "std_weight",
        "firewall_crossings",
        "role_entropy",
        "role_score"
    ]
    
    X= df[trained_features]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y # ?
    )
    print("Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators = 120,
        random_state=42,
        class_weight="balanced"
    )
    model.fit(X_train, y_train)
    # Predicting
    y_pred = model.predict(X_test)
    # Metrics
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="binary")
    cm = confusion_matrix(y_test, y_pred)

    print("\n=== BASELINE MODEL REPORT ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"F1-score : {f1:.4f}")
    print("\nConfusion matrix:")
    print(cm)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # Feature importance
    print("\nFeature Importances:")
    for name, score in sorted(zip(trained_features, model.feature_importances_), key=lambda x: -x[1]):
        print(f"{name:25s} : {score:.4f}")

    # Lưu lại model
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/rf_baseline.pkl")
    print("\nModel saved to models/rf_baseline.pkl")


if __name__ == "__main__":
    train_baseline()