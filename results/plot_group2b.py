import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_data(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)

    rows = []
    for run in data:
        config = run.get("Config", {})
        delay_cfg = config.get("DelayModelConfig", {})
        adv_cfg = config.get("AdversaryConfig", {})
        ver_cfg = config.get("VerificationConfig", {})

        rows.append(
            {
                "FlagThreshold": ver_cfg.get("FlaggingRateThreshold"),
                "Eta": run.get("EtaValue"),
                "IncompetenceRate": delay_cfg.get("IncompetenceRate"),
                "HonestyRate": adv_cfg.get("FlaggingHonestyRate"),
                "FPR": run.get("FalsePositiveRate", 0),
                "MeanQueries": run.get("MeanQueriesPerTrial", 0),
            }
        )

    df = pd.DataFrame(rows)
    df["FlagThreshold"] = df["FlagThreshold"].round(3)
    df["IncompetenceRate"] = df["IncompetenceRate"].round(3)
    df["HonestyRate"] = df["HonestyRate"].round(2)
    df["Eta"] = df["Eta"].round(3)
    return df


df = load_data("group2b_sla_sensitivity.json")

# Plot 1: FPR vs SLA Threshold (FlagThreshold) for different Incompetence Rates
plt.figure(figsize=(10, 6))
# Filter: Honesty = 1.0, Eta = 0.01
subset1 = df[(df["HonestyRate"] == 1.0) & (df["Eta"] == 0.01)]
sns.lineplot(
    data=subset1,
    x="FlagThreshold",
    y="FPR",
    hue="IncompetenceRate",
    palette="tab10",
    marker="o",
    linewidth=2,
)
plt.title("False Positive Rate vs SLA Threshold (Honesty = 1.0, Eta = 0.01)")
plt.xlabel("SLA Flagging Threshold")
plt.ylabel("False Positive Rate (FPR)")
plt.grid(True, linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("SLA_FPR_vs_Threshold_Inc.png", dpi=300)

# Plot 2: FPR vs SLA Threshold for different Honesty Rates
plt.figure(figsize=(10, 6))
# Filter: IncompetenceRate = 0.05, Eta = 0.01
subset2 = df[(df["IncompetenceRate"] == 0.05) & (df["Eta"] == 0.01)]
sns.lineplot(
    data=subset2,
    x="FlagThreshold",
    y="FPR",
    hue="HonestyRate",
    palette="Set2",
    marker="s",
    linewidth=2,
)
plt.title("False Positive Rate vs SLA Threshold (Incompetence = 0.05, Eta = 0.01)")
plt.xlabel("SLA Flagging Threshold")
plt.ylabel("False Positive Rate (FPR)")
plt.grid(True, linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("SLA_FPR_vs_Threshold_Hon.png", dpi=300)

# Plot 3: Mean Queries vs SLA Threshold
plt.figure(figsize=(10, 6))
sns.lineplot(
    data=subset1,
    x="FlagThreshold",
    y="MeanQueries",
    hue="IncompetenceRate",
    palette="tab10",
    marker="^",
    linewidth=2,
)
plt.title("Mean Queries vs SLA Threshold (Honesty = 1.0, Eta = 0.01)")
plt.xlabel("SLA Flagging Threshold")
plt.ylabel("Mean Queries Executed")
plt.grid(True, linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("SLA_Queries_vs_Threshold.png", dpi=300)

print("Plots generated successfully.")
