import pandas as pd
import matplotlib.pyplot as plt

def data_balancing(csv_path="data/generated_paths_full.csv"):
    df = pd.read_csv(csv_path)
    counts = df["label"].value_counts(normalize=True) * 100

    plt.figure(figsize=(6,4))
    plt.bar(counts.index.astype(str), counts.values, color=["orange", "skyblue"])
    plt.title("Label Ratio (%)")
    plt.ylabel("Percentage")
    for i, v in enumerate(counts.values):
        plt.text(i, v + 1, f"{v:.2f}%", ha='center')
    plt.tight_layout()
    plt.show()

