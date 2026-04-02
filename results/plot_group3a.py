import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np


def load_data(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)

    rows = []
    for run in data:
        config = run.get("Config", {})
        targeting_cfg = config.get("TargetingConfig", {})

        target_fraction = targeting_cfg.get("TargetFraction", 0)
        eta = run.get("EtaValue", 0)

        # Check if metrics are already aggregated or need to be calculated from Trials
        if "TruePositiveRate" in run:
            tpr = run["TruePositiveRate"]
            mean_queries = run.get("MeanQueriesPerTrial", 0)
        elif "Trials" in run and len(run["Trials"]) > 0:
            trials = run["Trials"]
            tpr = sum(1 for t in trials if t.get("Verdict") == "DISHONEST") / len(
                trials
            )
            mean_queries = sum(t.get("QueriesExecuted", 0) for t in trials) / len(
                trials
            )
        else:
            tpr = 0
            mean_queries = 0

        rows.append(
            {
                "TargetFraction": round(target_fraction, 3),
                "Eta": round(eta, 4),
                "DetectionRate": tpr,
                "MeanQueries": mean_queries,
            }
        )

    df = pd.DataFrame(rows)
    return df


df = load_data("group3a_total_denial.json")

# Due to many Eta values, let's pick a few representative ones for the line plots
unique_etas = sorted(df["Eta"].unique())
if len(unique_etas) > 5:
    # Pick roughly evenly spaced Etas
    indices = np.linspace(0, len(unique_etas) - 1, 5).astype(int)
    selected_etas = [unique_etas[i] for i in indices]
else:
    selected_etas = unique_etas

subset = df[df["Eta"].isin(selected_etas)]

# Plot 1: Detection Rate vs Target Fraction
plt.figure(figsize=(10, 6))
sns.lineplot(
    data=subset,
    x="TargetFraction",
    y="DetectionRate",
    hue="Eta",
    palette="tab10",
    marker="o",
    linewidth=2,
)
plt.title("Detection Rate vs Target Fraction (Malicious Total Denial)")
plt.xlabel("Target Fraction (Proportion of packets delayed)")
plt.ylabel("Detection Rate (True Positive Rate)")
plt.grid(True, linestyle="--", alpha=0.7)
plt.legend(title="Eta")
plt.tight_layout()
plt.savefig("TotalDenial_Detection_vs_Fraction.png", dpi=300)

# Plot 2: Mean Queries vs Target Fraction
plt.figure(figsize=(10, 6))
sns.lineplot(
    data=subset,
    x="TargetFraction",
    y="MeanQueries",
    hue="Eta",
    palette="tab10",
    marker="^",
    linewidth=2,
)
plt.title("Mean Queries vs Target Fraction (Malicious Total Denial)")
plt.xlabel("Target Fraction (Proportion of packets delayed)")
plt.ylabel("Mean Queries Executed")
plt.grid(True, linestyle="--", alpha=0.7)
plt.legend(title="Eta")
plt.tight_layout()
plt.savefig("TotalDenial_Queries_vs_Fraction.png", dpi=300)

# Plot 3: Heatmap of Detection Rate (Eta vs Target Fraction)
plt.figure(figsize=(12, 8))
pivot_table = df.pivot_table(
    index="Eta", columns="TargetFraction", values="DetectionRate"
)
pivot_table = pivot_table.sort_index(ascending=False)
sns.heatmap(
    pivot_table, annot=False, cmap="viridis", cbar_kws={"label": "Detection Rate"}
)
plt.title("Detection Rate Heatmap (Eta vs Target Fraction)")
plt.xlabel("Target Fraction")
plt.ylabel("Eta Value")
plt.tight_layout()
plt.savefig("TotalDenial_Heatmap.png", dpi=300)

print("Graphs generated successfully.")
