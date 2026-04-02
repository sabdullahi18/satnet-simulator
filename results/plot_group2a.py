import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


def load_and_prepare_data(filepath):
    """Loads the JSON result file and flattens it into a pandas DataFrame."""
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
                "QueriesPerBatch": ver_cfg.get("QueriesPerBatch"),
                "FlagThreshold": ver_cfg.get("FlaggingRateThreshold"),
                "Eta": run.get("EtaValue"),
                "IncompetenceRate": delay_cfg.get("IncompetenceRate"),
                "HonestyRate": adv_cfg.get("FlaggingHonestyRate"),
                "FPR": run.get("FalsePositiveRate", 0),
                "TNR": run.get("TrueNegativeRate", 0),
                "MeanQueries": run.get("MeanQueriesPerTrial", 0),
            }
        )

    df = pd.DataFrame(rows)

    # Clean up floating point inaccuracies from the sweep generation (e.g. 0.300000000004 -> 0.3)
    df["IncompetenceRate"] = df["IncompetenceRate"].round(3)
    df["HonestyRate"] = df["HonestyRate"].round(2)
    df["Eta"] = df["Eta"].round(3)

    return df


def plot_fpr_vs_incompetence(df):
    """Plots False Positive Rate vs Incompetence Rate for different QPB."""
    # Filter for a specific baseline setting to keep the graph readable
    # E.g., HonestyRate = 1.0 (fully honest about flags), Eta = 0.01, Threshold = 0.05
    subset = df[
        (df["HonestyRate"] == 1.0) & (df["Eta"] == 0.01) & (df["FlagThreshold"] == 0.05)
    ]

    if subset.empty:
        print("Warning: Subset for Plot 1 is empty. Check parameter filters.")
        return

    plt.figure(figsize=(10, 6))
    sns.lineplot(
        data=subset,
        x="IncompetenceRate",
        y="FPR",
        hue="QueriesPerBatch",
        palette="tab10",
        marker="o",
        linewidth=2,
    )

    plt.title("False Positive Rate vs Incompetence Rate (Honesty = 1.0, Eta = 0.01)")
    plt.xlabel("Incompetence Rate")
    plt.ylabel("False Positive Rate (FPR)")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig("FPR_vs_Incompetence.png", dpi=300)
    plt.show()


def plot_queries_vs_incompetence(df):
    """Plots Mean Queries vs Incompetence Rate for different QPB."""
    subset = df[
        (df["HonestyRate"] == 1.0) & (df["Eta"] == 0.01) & (df["FlagThreshold"] == 0.05)
    ]

    if subset.empty:
        return

    plt.figure(figsize=(10, 6))
    sns.lineplot(
        data=subset,
        x="IncompetenceRate",
        y="MeanQueries",
        hue="QueriesPerBatch",
        palette="Set2",
        marker="s",
        linewidth=2,
    )

    plt.title("Mean Queries Per Trial vs Incompetence Rate (Honesty = 1.0, Eta = 0.01)")
    plt.xlabel("Incompetence Rate")
    plt.ylabel("Mean Queries Executed")
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig("Queries_vs_Incompetence.png", dpi=300)
    plt.show()


def plot_fpr_heatmap(df):
    """Plots a heatmap of FPR across Honesty Rate and Incompetence Rate."""
    # We will fix QPB = 1 and Eta = 0.01 for the heatmap
    subset = df[
        (df["QueriesPerBatch"] == 1)
        & (df["Eta"] == 0.01)
        & (df["FlagThreshold"] == 0.05)
    ]

    if subset.empty:
        return

    # Pivot the data for the heatmap: Rows = Honesty, Cols = Incompetence
    pivot_table = subset.pivot_table(
        index="HonestyRate", columns="IncompetenceRate", values="FPR"
    )

    # Sort the index so 1.0 is at the top
    pivot_table = pivot_table.sort_index(ascending=False)

    plt.figure(figsize=(10, 8))
    sns.heatmap(
        pivot_table,
        annot=True,
        cmap="rocket_r",
        fmt=".2f",
        cbar_kws={"label": "False Positive Rate"},
    )

    plt.title("FPR Heatmap (QPB=1, Eta=0.01)")
    plt.xlabel("Incompetence Rate")
    plt.ylabel("Honesty Rate")
    plt.tight_layout()
    plt.savefig("FPR_Heatmap.png", dpi=300)
    plt.show()


if __name__ == "__main__":
    # Ensure this path maps to where your Go script saved the JSON
    json_filepath = "results/group2a_monitoring_frontier_qpb.json"

    print("Loading data...")
    try:
        results_df = load_and_prepare_data(json_filepath)

        print(f"Data loaded successfully. Found {len(results_df)} experimental runs.")
        print("Generating Plot 1: False Positive Rate vs Incompetence Rate...")
        plot_fpr_vs_incompetence(results_df)

        print("Generating Plot 2: Mean Queries vs Incompetence Rate...")
        plot_queries_vs_incompetence(results_df)

        print("Generating Plot 3: FPR Heatmap (Honesty vs Incompetence)...")
        plot_fpr_heatmap(results_df)

        print("Done! Check your working directory for the PNG files.")
    except FileNotFoundError:
        print(
            f"Error: Could not find file at '{json_filepath}'. Please check the path."
        )
