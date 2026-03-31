import json
import matplotlib.pyplot as plt
import seaborn as sns

# Load the JSON data
file_path = "results/group1_honest_baseline.json"
with open(file_path, "r") as f:
    data = json.load(f)

# Extract eta values and mean queries
eta_values = [experiment["EtaValue"] for experiment in data]
mean_queries = [experiment["MeanQueriesPerTrial"] for experiment in data]

# Set the style
sns.set_theme(style="whitegrid")
plt.figure(figsize=(10, 6))

# Create the line plot with markers
plt.plot(
    eta_values,
    mean_queries,
    marker="o",
    linestyle="-",
    color="#1f77b4",
    linewidth=2,
    markersize=6,
    markerfacecolor="#ff7f0e",
    markeredgecolor="white",
)

# Formatting the graph
plt.title(
    "Honest Baseline: Mean Queries vs Error Tolerance (η)",
    fontsize=16,
    fontweight="bold",
    pad=15,
)
plt.xlabel("Error Tolerance (η)", fontsize=14)
plt.ylabel("Mean Queries to Reach 95% Confidence", fontsize=14)

# Enhance tick marks
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)

# Set limits for a better look
plt.xlim(0, max(eta_values) + 0.01)
plt.ylim(0, max(mean_queries) + 100)

plt.tight_layout()

# Save the plot
plt.savefig("group1_honest_baseline_plot.png", dpi=300)
print("Plot generated successfully.")
