import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.colors import LinearSegmentedColormap

# Load all result files
def load(path):
    with open(path) as f:
        return json.load(f)

baseline   = load("honest_baseline.json")
delayed    = load("delayed_honest.json")
lies_tgt   = load("lies_about_targeted.json")
lies_min   = load("lies_that_minimal.json")

# ── helpers ──────────────────────────────────────────────────────────────────
ETA_VALS  = [0.001, 0.005, 0.01, 0.05, 0.1, 0.2]
FRAC_VALS = [0.05, 0.1, 0.2, 0.4, 0.6, 0.8]

def make_tpr_matrix(experiments):
    """Return a (len(ETA_VALS) x len(FRAC_VALS)) array of TPR values."""
    lookup = {(e["EtaValue"], e["TargetDelayFraction"]): e["TruePositiveRate"]
              for e in experiments}
    mat = np.full((len(ETA_VALS), len(FRAC_VALS)), np.nan)
    for i, eta in enumerate(ETA_VALS):
        for j, frac in enumerate(FRAC_VALS):
            mat[i, j] = lookup.get((eta, frac), np.nan)
    return mat

delayed_tpr  = make_tpr_matrix(delayed)
lies_tgt_tpr = make_tpr_matrix(lies_tgt)
lies_min_tpr = make_tpr_matrix(lies_min)

# ── color map ─────────────────────────────────────────────────────────────────
cmap = LinearSegmentedColormap.from_list("rg", ["#d73027", "#fee08b", "#1a9850"])

# ── figure layout ─────────────────────────────────────────────────────────────
fig = plt.figure(figsize=(18, 13), facecolor="#0f0f1a")
fig.patch.set_facecolor("#0f0f1a")

gs = gridspec.GridSpec(
    2, 4,
    figure=fig,
    left=0.06, right=0.97,
    top=0.91, bottom=0.08,
    wspace=0.42, hspace=0.48,
)

TEXT_COLOR = "#e0e0e0"
GRID_COLOR = "#2a2a3a"
AXIS_BG    = "#16162a"

eta_labels  = [str(e) for e in ETA_VALS]
frac_labels = [f"{int(f*100)}%" for f in FRAC_VALS]

def style_ax(ax, title):
    ax.set_facecolor(AXIS_BG)
    ax.set_title(title, color=TEXT_COLOR, fontsize=11, fontweight="bold", pad=8)
    ax.tick_params(colors=TEXT_COLOR, labelsize=8)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID_COLOR)

def heatmap(ax, mat, title):
    im = ax.imshow(mat, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(FRAC_VALS)))
    ax.set_xticklabels(frac_labels, color=TEXT_COLOR, fontsize=8)
    ax.set_yticks(range(len(ETA_VALS)))
    ax.set_yticklabels(eta_labels, color=TEXT_COLOR, fontsize=8)
    ax.set_xlabel("Target delay fraction", color=TEXT_COLOR, fontsize=9)
    ax.set_ylabel("η (error tolerance)", color=TEXT_COLOR, fontsize=9)
    style_ax(ax, title)
    for i in range(len(ETA_VALS)):
        for j in range(len(FRAC_VALS)):
            v = mat[i, j]
            if not np.isnan(v):
                ax.text(j, i, f"{v:.0%}", ha="center", va="center",
                        color="white" if v < 0.6 else "black",
                        fontsize=8, fontweight="bold")
    cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cb.ax.tick_params(colors=TEXT_COLOR, labelsize=7)
    cb.set_label("True Positive Rate", color=TEXT_COLOR, fontsize=8)

# ── row 0: heatmaps ────────────────────────────────────────────────────────────
ax_h0 = fig.add_subplot(gs[0, 0])
ax_h1 = fig.add_subplot(gs[0, 1])
ax_h2 = fig.add_subplot(gs[0, 2])

heatmap(ax_h0, delayed_tpr,  "Delayed Honest\n(TPR — detection rate)")
heatmap(ax_h1, lies_tgt_tpr, "Lies About Targeted\n(TPR — detection rate)")
heatmap(ax_h2, lies_min_tpr, "Lies That Minimal\n(TPR — detection rate)")

# ── row 0, col 3: per-scenario mean TPR bar chart ─────────────────────────────
ax_bar = fig.add_subplot(gs[0, 3])
style_ax(ax_bar, "Mean TPR by Scenario")

scenario_labels = ["Delayed\nHonest", "Lies About\nTargeted", "Lies That\nMinimal"]
mean_tprs = [
    np.nanmean(delayed_tpr),
    np.nanmean(lies_tgt_tpr),
    np.nanmean(lies_min_tpr),
]
bar_colors = ["#4e79a7", "#f28e2b", "#59a14f"]
bars = ax_bar.bar(scenario_labels, mean_tprs, color=bar_colors, edgecolor=GRID_COLOR, linewidth=0.8)
ax_bar.set_ylim(0, 1.1)
ax_bar.set_ylabel("Mean TPR", color=TEXT_COLOR, fontsize=9)
ax_bar.yaxis.grid(True, color=GRID_COLOR, linewidth=0.5)
ax_bar.set_axisbelow(True)
for bar, val in zip(bars, mean_tprs):
    ax_bar.text(bar.get_x() + bar.get_width() / 2, val + 0.02,
                f"{val:.2%}", ha="center", va="bottom",
                color=TEXT_COLOR, fontsize=9, fontweight="bold")

# ── row 1, col 0-1: honest baseline — confidence & queries vs eta ──────────────
ax_conf = fig.add_subplot(gs[1, 0:2])
style_ax(ax_conf, "Honest Baseline — Mean Confidence vs η")

eta_vals_bl  = [e["EtaValue"] for e in baseline]
conf_vals_bl = [e["MeanConfidence"] for e in baseline]
q_vals_bl    = [e["MeanQueriesPerTrial"] for e in baseline]

ax_conf.plot(eta_vals_bl, conf_vals_bl, color="#4e79a7", marker="o",
             linewidth=2, markersize=7, label="Mean Confidence (H₀ posterior)")
ax_conf.set_xlabel("η (error tolerance)", color=TEXT_COLOR, fontsize=9)
ax_conf.set_ylabel("Mean Confidence", color=TEXT_COLOR, fontsize=9)
ax_conf.set_ylim(0.97, 1.002)
ax_conf.yaxis.grid(True, color=GRID_COLOR, linewidth=0.5)
ax_conf.set_axisbelow(True)
ax_conf.axhline(0.95, color="#e15759", linestyle="--", linewidth=1.2,
                label="Confidence threshold (0.95)")
ax_conf.legend(fontsize=8, facecolor="#1e1e2e", labelcolor=TEXT_COLOR,
               edgecolor=GRID_COLOR)

ax_q = ax_conf.twinx()
ax_q.plot(eta_vals_bl, q_vals_bl, color="#f28e2b", marker="s",
          linewidth=2, markersize=7, linestyle="--", label="Mean Queries / Trial")
ax_q.set_ylabel("Mean Queries / Trial", color="#f28e2b", fontsize=9)
ax_q.tick_params(axis="y", colors="#f28e2b", labelsize=8)
ax_q.legend(fontsize=8, facecolor="#1e1e2e", labelcolor=TEXT_COLOR,
            edgecolor=GRID_COLOR, loc="lower right")

# ── row 1, col 2-3: TPR vs delay fraction grouped by adversary type ────────────
ax_tpr = fig.add_subplot(gs[1, 2:4])
style_ax(ax_tpr, "Detection Rate vs. Target Delay Fraction\n(averaged across all η values)")

mean_delayed  = np.nanmean(delayed_tpr, axis=0)
mean_lies_tgt = np.nanmean(lies_tgt_tpr, axis=0)
mean_lies_min = np.nanmean(lies_min_tpr, axis=0)

frac_x = [f * 100 for f in FRAC_VALS]
ax_tpr.plot(frac_x, mean_delayed,  color="#4e79a7", marker="o", linewidth=2,
            markersize=8, label="Delayed Honest")
ax_tpr.plot(frac_x, mean_lies_tgt, color="#f28e2b", marker="s", linewidth=2,
            markersize=8, label="Lies About Targeted")
ax_tpr.plot(frac_x, mean_lies_min, color="#59a14f", marker="^", linewidth=2,
            markersize=8, label="Lies That Minimal")

ax_tpr.set_xlabel("Target delay fraction (%)", color=TEXT_COLOR, fontsize=9)
ax_tpr.set_ylabel("Mean True Positive Rate", color=TEXT_COLOR, fontsize=9)
ax_tpr.set_ylim(-0.05, 1.1)
ax_tpr.yaxis.grid(True, color=GRID_COLOR, linewidth=0.5)
ax_tpr.set_axisbelow(True)
ax_tpr.legend(fontsize=9, facecolor="#1e1e2e", labelcolor=TEXT_COLOR,
              edgecolor=GRID_COLOR)

# ── super title ───────────────────────────────────────────────────────────────
fig.suptitle("SatNet Simulator — Verification Results", color=TEXT_COLOR,
             fontsize=15, fontweight="bold", y=0.97)

out = "results_plot.png"
plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
print(f"Saved → {out}")
plt.close()
