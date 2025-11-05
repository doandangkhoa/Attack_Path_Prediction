import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("data/generated_paths.csv")
counts = df["label"].value_counts(normalize=True) * 100

plt.bar(counts.index.astype(str), counts.values, color=["orange", "skyblue"])
plt.title("Label Ratio (%)")
plt.ylabel("Percentage")
for i, v in enumerate(counts.values):
    plt.text(i, v + 1, f"{v:.2f}%", ha='center')
plt.show()
