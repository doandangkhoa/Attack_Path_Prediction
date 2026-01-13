import pandas as pd
import numpy as np
import os
import json
import joblib
from collections import Counter

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, f1_score, recall_score, precision_score, 
    confusion_matrix, classification_report, precision_recall_curve
)

# =========================
# CONFIGURATION
# =========================
DATA_PATH = "data/generated_attack_paths_policy_oracle.csv"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "rf_baseline.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

def train_baseline():
    print(f"📂 Đang tải dữ liệu từ: {DATA_PATH} ...")

    if not os.path.exists(DATA_PATH):
        print("❌ Lỗi: Không tìm thấy file dữ liệu. Hãy chạy data_generator.py trước.")
        return

    df = pd.read_csv(DATA_PATH)

    # ==============================
    # 1. FEATURE SELECTION (ĐÃ SỬA KHỚP VỚI EXTRACT_FEATURES)
    # ==============================
    trained_features = [
        'rank',

        # --- STRUCTURE ---
        'path_length',

        # --- WEIGHT (DIJKSTRA) ---
        'total_weight',
        'avg_weight',
        'min_weight',
        'std_weight',
        'deviation_weight',

        # --- DETECTION / NOISE ---
        'total_detection',
        'avg_detection',
        'max_detection',

        # --- ATTACK BEHAVIOR ---
        'exploit_count',
        'security_controls',
        'firewall_crossings',
        'privilege_gain',

        # --- CONTEXT ---
        'role_entropy',
        'role_score',
        'has_admin_access',
        'is_admin_source',
        'has_bastion',
        'has_mfa',
        # --- COMPOSITE RISK ---
        'risk_factor',
    ]

    # Kiểm tra cột thiếu
    print("🧹 Đang kiểm tra dữ liệu...")
    missing_cols = [col for col in trained_features if col not in df.columns]
    if missing_cols:
        print(f"⚠️ Cảnh báo: Các cột sau bị thiếu trong CSV và sẽ được điền 0: {missing_cols}")
        for col in missing_cols:
            df[col] = 0

    # Xử lý Infinity và NaN
    df = df.replace([np.inf, -np.inf], 0)
    df = df.fillna(0)

    X = df[trained_features]
    y = df["label"]

    print(f"📊 Phân phối nhãn: {sorted(Counter(y).items())}")

    # ==============================
    # 2. SPLIT DATA (Train/Val/Test)
    # ==============================
    # Tách Test (20%)
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Tách Train (60%) và Val (20%)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp
    )

    print(f"📐 Split sizes: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    # ==============================
    # 3. RANDOM SEARCH OPTIMIZATION
    # ==============================
    print("🧠 Đang tối ưu hóa Random Forest...")

    rf = RandomForestClassifier(
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )

    param_dist = {
        "n_estimators": [100, 200, 300],
        "max_depth": [None, 10, 20],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2"]
    }

    search = RandomizedSearchCV(
        estimator=rf,
        param_distributions=param_dist,
        n_iter=20,
        scoring="f1",
        cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=42),
        verbose=1,
        n_jobs=-1,
        random_state=42
    )

    search.fit(X_train, y_train)
    best_model = search.best_estimator_

    print(f"✅ Tham số tốt nhất: {search.best_params_}")

    # ==============================
    # 4. THRESHOLD TUNING (TRÊN VAL SET)
    # ==============================
    print("\n🔍 Tìm ngưỡng tối ưu trên Validation set...")

    y_val_probs = best_model.predict_proba(X_val)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_val, y_val_probs)

    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1_scores)
    
    optimal_threshold = thresholds[best_idx]
    best_val_f1 = f1_scores[best_idx]

    print(f"   - Threshold mặc định: 0.5000")
    print(f"   - Threshold tối ưu  : {optimal_threshold:.4f}")
    print(f"   - Best Val F1       : {best_val_f1:.4f}")

    # ==============================
    # 5. FINAL EVALUATION (TRÊN TEST SET)
    # ==============================
    print("\n🧪 Đánh giá trên tập TEST...")

    y_test_probs = best_model.predict_proba(X_test)[:, 1]
    y_test_pred = (y_test_probs >= optimal_threshold).astype(int)

    acc = accuracy_score(y_test, y_test_pred)
    f1 = f1_score(y_test, y_test_pred)
    recall = recall_score(y_test, y_test_pred)
    precision = precision_score(y_test, y_test_pred)
    cm = confusion_matrix(y_test, y_test_pred)

    print("\n" + "="*50)
    print("    KẾT QUẢ ĐÁNH GIÁ (FINAL REPORT)    ")
    print("="*50)
    print(f"✅ Accuracy  : {acc:.4f}")
    print(f"✅ F1-Score  : {f1:.4f}")
    print(f"🎯 Recall    : {recall:.4f}")
    print(f"🎯 Precision : {precision:.4f}")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(classification_report(y_test, y_test_pred))

    # ==============================
    # 6. FEATURE IMPORTANCE & SAVE
    # ==============================
    print("\n⭐ Feature Importance:")
    feat_importance = {}
    importances = best_model.feature_importances_
    indices = np.argsort(importances)[::-1]

    for i in indices:
        name = trained_features[i]
        score = importances[i]
        feat_importance[name] = float(score)
        print(f"{name:20s} : {score:.4f}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(best_model, MODEL_PATH)

    metrics = {
        "accuracy": float(acc),
        "f1": float(f1),
        "recall": float(recall),
        "precision": float(precision),
        "optimal_threshold": float(optimal_threshold),
        "confusion_matrix": cm.tolist(),
        "feature_importance": feat_importance,
        "feature_names": trained_features # Lưu lại để predict dùng
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"\n💾 Saved model to: {MODEL_PATH}")

if __name__ == "__main__":
    train_baseline()