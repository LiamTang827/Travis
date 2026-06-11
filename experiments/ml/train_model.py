#!/usr/bin/env python3
"""
AML 分类模型训练与评估
========================

对 feature_matrix.csv 训练多个树集成模型，对比性能，
输出评估指标 + Feature Importance 可视化。

模型：XGBoost / LightGBM / CatBoost
评估：Macro-F1, PR-AUC, 分类别 Precision/Recall/F1
可视化：Feature Importance (Top 20), Confusion Matrix

用法：
  python experiments/ml/train_model.py
  python experiments/ml/train_model.py --test-size 0.3
  python experiments/ml/train_model.py --save-model
"""

import os
import sys
import csv
import json
import argparse
import warnings
import numpy as np
import pandas as pd
from collections import Counter

from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_recall_curve, auc,
    average_precision_score,
)
from sklearn.preprocessing import LabelEncoder, label_binarize

warnings.filterwarnings("ignore", category=UserWarning)

# ==================== 路径 ====================
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
FEATURE_CSV = os.path.join(DATA_DIR, "feature_matrix.csv")
OUTPUT_DIR = os.path.join(DATA_DIR, "model_output")


# ==================== 数据加载 ====================

def load_data(csv_path: str):
    """加载 feature_matrix.csv，返回 X, y, feature_names, label_names"""
    df = pd.read_csv(csv_path)

    # 分离元数据和特征
    meta_cols = ["address", "label"]
    feature_cols = [c for c in df.columns if c not in meta_cols]

    X = df[feature_cols].values.astype(np.float64)
    labels = df["label"].values

    # 处理 inf 和 nan
    X = np.nan_to_num(X, nan=0.0, posinf=999.0, neginf=-999.0)

    # 编码标签
    le = LabelEncoder()
    y = le.fit_transform(labels)

    print(f"[数据] 加载 {len(df)} 个样本, {len(feature_cols)} 个特征")
    print(f"  标签分布: {dict(Counter(labels))}")
    print(f"  标签编码: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    return X, y, feature_cols, le.classes_, le, df


# ==================== 模型定义 ====================

def get_models(n_classes: int, class_counts: dict):
    """返回待对比的模型字典"""
    from xgboost import XGBClassifier
    from lightgbm import LGBMClassifier
    from catboost import CatBoostClassifier
    from sklearn.ensemble import RandomForestClassifier

    # 计算类别权重（处理不平衡）
    total = sum(class_counts.values())
    n_cls = len(class_counts)
    # sklearn 风格: weight = total / (n_classes * count)
    sample_weight_map = {
        cls: total / (n_cls * cnt) for cls, cnt in class_counts.items()
    }
    scale_pos = max(class_counts.values()) / min(class_counts.values())

    models = {
        "XGBoost": XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            scale_pos_weight=scale_pos if n_classes == 2 else 1,
            eval_metric="mlogloss" if n_classes > 2 else "logloss",
            use_label_encoder=False,
            verbosity=0,
            random_state=42,
        ),
        "LightGBM": LGBMClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            class_weight="balanced",
            verbose=-1,
            random_state=42,
        ),
        "CatBoost": CatBoostClassifier(
            iterations=300,
            depth=6,
            learning_rate=0.1,
            auto_class_weights="Balanced",
            verbose=0,
            random_seed=42,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=300,
            max_depth=10,
            class_weight="balanced",
            random_state=42,
        ),
    }

    return models


# ==================== 交叉验证评估 ====================

def evaluate_models(X, y, feature_names, label_names, n_splits=5):
    """对所有模型做 Stratified K-Fold 交叉验证，返回结果"""
    n_classes = len(label_names)
    class_counts = dict(Counter(y))
    models = get_models(n_classes, class_counts)

    # 如果样本太少，减少 fold 数
    min_class_count = min(Counter(y).values())
    actual_splits = min(n_splits, min_class_count)
    if actual_splits < n_splits:
        print(f"  [WARN] 最小类别只有 {min_class_count} 个样本，"
              f"K-Fold 从 {n_splits} 降至 {actual_splits}")

    skf = StratifiedKFold(n_splits=actual_splits, shuffle=True, random_state=42)

    results = {}

    for name, model in models.items():
        print(f"\n{'='*60}")
        print(f"  训练模型: {name}")
        print(f"{'='*60}")

        # 交叉验证预测
        y_pred = cross_val_predict(model, X, y, cv=skf, method="predict")

        # 概率预测（用于 PR-AUC）
        try:
            y_proba = cross_val_predict(model, X, y, cv=skf, method="predict_proba")
        except Exception:
            y_proba = None

        # Macro-F1
        macro_f1 = f1_score(y, y_pred, average="macro")

        # PR-AUC（每个类别单独算，再取平均）
        pr_auc = 0
        if y_proba is not None:
            y_bin = label_binarize(y, classes=list(range(n_classes)))
            if n_classes == 2:
                y_bin = np.hstack([1 - y_bin, y_bin])
            pr_aucs = []
            for i in range(n_classes):
                try:
                    ap = average_precision_score(y_bin[:, i], y_proba[:, i])
                    pr_aucs.append(ap)
                except Exception:
                    pr_aucs.append(0)
            pr_auc = np.mean(pr_aucs)

        # Classification Report
        report = classification_report(
            y, y_pred, target_names=label_names, output_dict=True
        )
        report_str = classification_report(
            y, y_pred, target_names=label_names
        )

        # Confusion Matrix
        cm = confusion_matrix(y, y_pred)

        # Feature Importance（在全量数据上训练一次）
        model.fit(X, y)
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
        else:
            importances = np.zeros(len(feature_names))

        # 排序取 Top 20
        top_idx = np.argsort(importances)[::-1][:20]
        top_features = [(feature_names[i], importances[i]) for i in top_idx]

        results[name] = {
            "macro_f1": macro_f1,
            "pr_auc": pr_auc,
            "report": report,
            "report_str": report_str,
            "confusion_matrix": cm,
            "top_features": top_features,
            "model": model,
        }

        print(f"\n  Macro-F1:  {macro_f1:.4f}")
        print(f"  PR-AUC:    {pr_auc:.4f}")
        print(f"\n{report_str}")
        print(f"  Confusion Matrix:")
        print(f"  {cm}")
        print(f"\n  Top 10 Features:")
        for feat, imp in top_features[:10]:
            bar = "█" * int(imp * 50 / max(importances))
            print(f"    {feat:40s} {imp:.4f}  {bar}")

    return results


# ==================== 可视化 ====================

def plot_results(results: dict, feature_names, label_names, output_dir: str):
    """生成 Feature Importance 和 Confusion Matrix 图"""
    import matplotlib
    matplotlib.use("Agg")  # 无头模式
    import matplotlib.pyplot as plt

    os.makedirs(output_dir, exist_ok=True)

    # 1. 模型对比 bar chart
    fig, ax = plt.subplots(figsize=(10, 5))
    model_names = list(results.keys())
    f1_scores = [results[m]["macro_f1"] for m in model_names]
    pr_aucs = [results[m]["pr_auc"] for m in model_names]

    x = np.arange(len(model_names))
    width = 0.35
    ax.bar(x - width/2, f1_scores, width, label="Macro-F1", color="#2196F3")
    ax.bar(x + width/2, pr_aucs, width, label="PR-AUC", color="#FF9800")
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison: AML Classification")
    ax.set_xticks(x)
    ax.set_xticklabels(model_names)
    ax.legend()
    ax.set_ylim(0, 1.1)
    for i, (f1, pr) in enumerate(zip(f1_scores, pr_aucs)):
        ax.text(i - width/2, f1 + 0.02, f"{f1:.3f}", ha="center", fontsize=9)
        ax.text(i + width/2, pr + 0.02, f"{pr:.3f}", ha="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "model_comparison.png"), dpi=150)
    plt.close()
    print(f"\n[图] 模型对比图 → {output_dir}/model_comparison.png")

    # 2. 每个模型的 Feature Importance
    for name, res in results.items():
        top_feats = res["top_features"]
        if not top_feats or all(v == 0 for _, v in top_feats):
            continue

        fig, ax = plt.subplots(figsize=(10, 8))
        feat_names = [f[0] for f in reversed(top_feats)]
        feat_vals = [f[1] for f in reversed(top_feats)]

        colors = []
        for fn in feat_names:
            if "mixer" in fn or "flagged" in fn:
                colors.append("#f44336")  # 红: 高风险相关
            elif "bridge" in fn or "cex" in fn or "dex" in fn:
                colors.append("#FF9800")  # 橙: 实体交互
            elif "amount" in fn or "transfer" in fn or "drain" in fn or "ratio" in fn:
                colors.append("#2196F3")  # 蓝: 金额相关
            elif "interval" in fn or "burst" in fn or "frequency" in fn or "age" in fn:
                colors.append("#4CAF50")  # 绿: 时间相关
            else:
                colors.append("#9E9E9E")  # 灰: 其他

        ax.barh(feat_names, feat_vals, color=colors)
        ax.set_xlabel("Feature Importance")
        ax.set_title(f"{name} — Top {len(top_feats)} Features")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"importance_{name.lower()}.png"), dpi=150)
        plt.close()
        print(f"[图] {name} 特征重要性 → {output_dir}/importance_{name.lower()}.png")

    # 3. 最优模型的 Confusion Matrix
    best_model = max(results.items(), key=lambda x: x[1]["macro_f1"])
    best_name, best_res = best_model
    cm = best_res["confusion_matrix"]

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.set_title(f"Confusion Matrix — {best_name} (Best)")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_xticks(range(len(label_names)))
    ax.set_yticks(range(len(label_names)))
    ax.set_xticklabels(label_names, rotation=45, ha="right")
    ax.set_yticklabels(label_names)

    # 在格子里写数字
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            color = "white" if cm[i, j] > cm.max() / 2 else "black"
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color, fontsize=14)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "confusion_matrix.png"), dpi=150)
    plt.close()
    print(f"[图] 混淆矩阵 → {output_dir}/confusion_matrix.png")


# ==================== 保存模型 ====================

def save_best_model(results: dict, le: LabelEncoder,
                    feature_names: list, output_dir: str):
    """保存最优模型为 pickle"""
    import pickle

    best_name = max(results, key=lambda m: results[m]["macro_f1"])
    best = results[best_name]

    model_path = os.path.join(output_dir, "best_model.pkl")
    meta_path = os.path.join(output_dir, "model_meta.json")

    with open(model_path, "wb") as f:
        pickle.dump(best["model"], f)

    meta = {
        "model_name": best_name,
        "macro_f1": best["macro_f1"],
        "pr_auc": best["pr_auc"],
        "feature_names": feature_names,
        "label_names": list(le.classes_),
        "label_encoding": dict(zip(le.classes_.tolist(), le.transform(le.classes_).tolist())),
        "top_features": [(n, float(v)) for n, v in best["top_features"]],
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"\n[保存] 最优模型 ({best_name}, F1={best['macro_f1']:.4f})")
    print(f"  模型文件: {model_path}")
    print(f"  元数据:   {meta_path}")


# ==================== 主流程 ====================

def main():
    parser = argparse.ArgumentParser(description="训练 AML 分类模型")
    parser.add_argument("--input", type=str, default=FEATURE_CSV,
                        help="特征矩阵 CSV 路径")
    parser.add_argument("--folds", type=int, default=5,
                        help="K-Fold 折数 (默认 5)")
    parser.add_argument("--save-model", action="store_true",
                        help="保存最优模型")
    args = parser.parse_args()

    # 加载数据
    X, y, feature_names, label_names, le, df = load_data(args.input)

    # 训练和评估
    results = evaluate_models(X, y, feature_names, label_names, n_splits=args.folds)

    # 总结
    print(f"\n{'='*60}")
    print(f"  模型对比总结")
    print(f"{'='*60}")
    print(f"  {'Model':15s} {'Macro-F1':>10s} {'PR-AUC':>10s}")
    print(f"  {'-'*35}")
    best_name = None
    best_f1 = 0
    for name, res in results.items():
        marker = ""
        if res["macro_f1"] > best_f1:
            best_f1 = res["macro_f1"]
            best_name = name
        print(f"  {name:15s} {res['macro_f1']:>10.4f} {res['pr_auc']:>10.4f}")
    print(f"\n  最优模型: {best_name} (Macro-F1 = {best_f1:.4f})")

    # 可视化
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    plot_results(results, feature_names, label_names, OUTPUT_DIR)

    # 保存模型
    if args.save_model:
        save_best_model(results, le, feature_names, OUTPUT_DIR)

    # 保存评估报告 JSON
    report_path = os.path.join(OUTPUT_DIR, "evaluation_report.json")
    report = {}
    for name, res in results.items():
        report[name] = {
            "macro_f1": res["macro_f1"],
            "pr_auc": res["pr_auc"],
            "classification_report": res["report"],
            "confusion_matrix": res["confusion_matrix"].tolist(),
            "top_features": [(n, float(v)) for n, v in res["top_features"]],
        }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[报告] 完整评估报告 → {report_path}")


if __name__ == "__main__":
    main()
