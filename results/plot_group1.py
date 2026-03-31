import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the JSON data
file_path = "group1_honest_baseline.json"
with open(file_path, "r") as f:
    data = json.load(f)

# Extract data into a list of dictionaries for the DataFrame
records = []
for entry in data:
    eta = entry.get("EtaValue")
    batch_size = entry.get("BatchSize")
    mean_queries = entry.get("MeanQueriesPerTrial")
    mean_h0 = entry.get("MeanPosteriorH0")

    records.append(
        {
            "EtaValue": eta,
            "BatchSize": str(batch_size),  # Convert to string for categorical coloring
            "MeanQueries": mean_queries,
            "MeanPosteriorH0": mean_h0,
        }
    )

df = pd.DataFrame(records)

# ==========================================
# NEW: Filter the data to zoom in on η <= 0.1
# ==========================================
df = df[df["EtaValue"] <= 0.1]

# Set a clean visual style
sns.set_theme(style="whitegrid")

# Plot 1: Average Queries vs Eta Value
plt.figure(figsize=(10, 6))
sns.lineplot(
    data=df,
    x="EtaValue",
    y="MeanQueries",
    hue="BatchSize",
    palette="viridis",
    marker="o",
)
plt.title("Average Queries vs Error Tolerance (Honest Baseline)", fontsize=14)
plt.ylabel("Average Queries", fontsize=12)
plt.xlabel("Error Tolerance (η)", fontsize=12)
plt.legend(title="Batch Size")
plt.tight_layout()
plt.savefig("honest_queries_vs_eta_zoomed.png", dpi=300)
plt.close()

# Plot 2: Mean Posterior H0 vs Eta Value
plt.figure(figsize=(10, 6))
sns.lineplot(
    data=df,
    x="EtaValue",
    y="MeanPosteriorH0",
    hue="BatchSize",
    palette="viridis",
    marker="o",
)
plt.title("Mean Posterior P(H0) vs Error Tolerance (Honest Baseline)", fontsize=14)
plt.ylabel("Mean Posterior P(H0)", fontsize=12)
plt.xlabel("Error Tolerance (η)", fontsize=12)
plt.axhline(y=0.95, color="r", linestyle="--", label="95% Confidence Threshold")
plt.legend(title="Batch Size")
plt.tight_layout()
plt.savefig("honest_h0_vs_eta_zoomed.png", dpi=300)
plt.close()

print("Zoomed plots successfully generated!")
