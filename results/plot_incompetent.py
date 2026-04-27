"""Plot the incompetent-network sweeps produced by cmd/satnet.

Handles multi-seed sweeps (one subdir per seed), global single-seed sweeps,
and the 2D pincomp x flag-reliability phase map. Each plot is saved as its
own PNG file under results/incompetent/plots/.
"""

import json
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.colors import LogNorm

HERE = Path(__file__).resolve().parent
INCOMP = HERE / "incompetent"
OUT = INCOMP / "plots"
OUT.mkdir(exist_ok=True)

sns.set_theme(style="whitegrid", context="paper")

# --- palette ---------------------------------------------------------------
GREY = "#6e6e6e"
BLUE = "#1f77b4"
ORANGE = "#ff7f0e"
GREEN = "#2ca02c"
RED = "#d62728"
PURPLE = "#9467bd"
BROWN = "#8c564b"

VERDICT_COLORS = {
    "TrustedRate": GREEN,
    "CaughtIncompetentRate": ORANGE,
    "CaughtMaliciousRate": RED,
    "SLABreachedRate": PURPLE,
    "InconclusiveRate": BROWN,
    "CorrectDetectionRate": BLUE,
}
VERDICT_LABELS = {
    "TrustedRate": "TRUSTED",
    "CaughtIncompetentRate": "CAUGHT_INCOMPETENT",
    "CaughtMaliciousRate": "CAUGHT_MALICIOUS",
    "SLABreachedRate": "SLA_BREACHED",
    "InconclusiveRate": "INCONCLUSIVE",
    "CorrectDetectionRate": "CORRECT_DETECTION",
}

# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------
def load(path: Path):
    with open(path, "r") as f:
        return json.load(f)


def save(fig, name: str):
    fig.tight_layout()
    fig.savefig(OUT / name, dpi=180)
    plt.close(fig)
    print(f"  wrote {(OUT / name).relative_to(HERE.parent)}")


def seed_dirs():
    """Return dict of seed_label -> Path for each seed_* subdir."""
    out = {}
    for d in sorted(INCOMP.iterdir()):
        if d.is_dir() and d.name.startswith("seed_"):
            # shorten long numeric seeds
            label = d.name
            m = re.match(r"seed_(\d+)$", label)
            if m and len(m.group(1)) > 4:
                label = f"seed_{m.group(1)[:4]}…"
            out[label] = d
    return out


def collect_seed_sweeps(fname: str):
    """Return list of (seed_label, data) for all seeds that contain `fname`."""
    results = []
    for label, path in seed_dirs().items():
        fp = path / fname
        if fp.exists():
            results.append((label, load(fp)))
    return results


def extract(data, getter):
    return np.array([getter(d) for d in data])


# ---------------------------------------------------------------------------
# Multi-seed line plot (verdict rates + queries + posteriors)
# ---------------------------------------------------------------------------
def plot_multiseed_sweep(
    fname: str,
    x_getter,
    x_label: str,
    out_prefix: str,
    title: str,
    log_x: bool = True,
    sort_x: bool = True,
):
    seeds = collect_seed_sweeps(fname)
    if not seeds:
        print(f"  [skip] no seed runs for {fname}")
        return

    # stack per seed: x and each metric
    per_seed = {}
    for label, data in seeds:
        xs = extract(data, x_getter)
        if sort_x:
            order = np.argsort(xs)
            xs = xs[order]
            data = [data[i] for i in order]
        per_seed[label] = {"x": xs, "data": data}

    # Use first seed's x as reference grid (all seeds should share the grid)
    ref_label = next(iter(per_seed))
    xs_ref = per_seed[ref_label]["x"]

    # --- PLOT A: verdict rates (one PNG per metric) -----------------------
    all_metrics = [
        "TrustedRate",
        "CaughtIncompetentRate",
        "CaughtMaliciousRate",
        "SLABreachedRate",
        "InconclusiveRate",
        "CorrectDetectionRate",
    ]
    for metric in all_metrics:
        fig, ax = plt.subplots(figsize=(7, 4.5))
        stacked = []
        for label, bundle in per_seed.items():
            ys = extract(bundle["data"], lambda d, m=metric: d[m])
            ax.plot(
                bundle["x"],
                ys,
                marker="o",
                markersize=3,
                linewidth=0.9,
                alpha=0.45,
                label=label,
            )
            if len(bundle["x"]) == len(xs_ref) and np.allclose(bundle["x"], xs_ref):
                stacked.append(ys)
        if stacked:
            stack = np.vstack(stacked)
            mean = stack.mean(axis=0)
            ax.plot(xs_ref, mean, color="black", linewidth=2.0, label="seed mean")
            if stack.shape[0] >= 2:
                lo = stack.min(axis=0)
                hi = stack.max(axis=0)
                ax.fill_between(xs_ref, lo, hi, color="black", alpha=0.08)
        ax.set_title(VERDICT_LABELS[metric], color=VERDICT_COLORS[metric])
        ax.set_ylim(-0.03, 1.03)
        ax.set_ylabel("rate")
        if log_x:
            ax.set_xscale("log")
        ax.set_xlabel(x_label)
        ax.legend(fontsize=8, ncol=2, loc="best")
        fig.suptitle(f"{title} — {VERDICT_LABELS[metric]}", y=1.02)
        save(fig, f"{out_prefix}_verdict_{metric}.png")

    # --- PLOT B: queries (mean + median + p90) ----------------------------
    fig, ax = plt.subplots(figsize=(8, 5))
    stacked_mean, stacked_med = [], []
    for label, bundle in per_seed.items():
        med = extract(bundle["data"], lambda d: d["MedianQueriesToVerdict"])
        mean = extract(bundle["data"], lambda d: d["MeanQueriesToVerdict"])
        ax.plot(bundle["x"], med, marker="o", markersize=3, linewidth=0.9, alpha=0.45, label=f"{label} median")
        ax.plot(bundle["x"], mean, marker="^", markersize=3, linewidth=0.9, alpha=0.25, linestyle=":")
        if len(bundle["x"]) == len(xs_ref) and np.allclose(bundle["x"], xs_ref):
            stacked_mean.append(mean)
            stacked_med.append(med)
    if stacked_mean:
        ax.plot(xs_ref, np.vstack(stacked_med).mean(axis=0), color="black", linewidth=2.0, label="seed mean (median)")
        ax.plot(xs_ref, np.vstack(stacked_mean).mean(axis=0), color=GREY, linewidth=1.6, linestyle="--", label="seed mean (mean)")
    if log_x:
        ax.set_xscale("log")
    ax.set_xlabel(x_label)
    ax.set_ylabel("Queries to verdict")
    ax.set_title(f"{title} — queries to verdict")
    ax.legend(fontsize=8, ncol=2, loc="best")
    save(fig, f"{out_prefix}_queries.png")

    # --- PLOT C: posterior mass (one PNG per hypothesis) ------------------
    for key, col, name in zip(
        ["MeanPosteriorH0", "MeanPosteriorH1", "MeanPosteriorH2"],
        [GREEN, ORANGE, RED],
        [r"$\bar{P}(H_0)$ honest", r"$\bar{P}(H_1)$ incompetent", r"$\bar{P}(H_2)$ malicious"],
    ):
        fig, ax = plt.subplots(figsize=(7, 4.5))
        stacked = []
        for label, bundle in per_seed.items():
            ys = extract(bundle["data"], lambda d, k=key: d[k])
            ax.plot(bundle["x"], ys, marker="o", markersize=3, linewidth=0.9, alpha=0.45, label=label)
            if len(bundle["x"]) == len(xs_ref) and np.allclose(bundle["x"], xs_ref):
                stacked.append(ys)
        if stacked:
            ax.plot(xs_ref, np.vstack(stacked).mean(axis=0), color="black", linewidth=2.0, label="seed mean")
        if log_x:
            ax.set_xscale("log")
        ax.set_xlabel(x_label)
        ax.set_ylabel(name)
        ax.set_title(name, color=col)
        ax.set_ylim(-0.03, 1.03)
        ax.legend(fontsize=8, ncol=2, loc="best")
        fig.suptitle(f"{title} — terminal posterior mass", y=1.02)
        safe_key = key.replace("MeanPosterior", "posterior_")
        save(fig, f"{out_prefix}_{safe_key}.png")


# ---------------------------------------------------------------------------
# Single-seed sweep plotter (for top-level sweep files)
# ---------------------------------------------------------------------------
def plot_single_sweep(
    fname: str,
    x_getter,
    x_label: str,
    out_prefix: str,
    title: str,
    log_x: bool = False,
    extras: dict | None = None,
):
    path = INCOMP / fname
    if not path.exists():
        print(f"  [skip] {fname} not found")
        return
    data = load(path)
    xs = extract(data, x_getter)
    order = np.argsort(xs)
    xs = xs[order]
    data = [data[i] for i in order]

    # --- Plot A: verdict rates (stacked area + lines) ---------------------
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.8))

    # stacked area
    trust = extract(data, lambda d: d["TrustedRate"])
    inc = extract(data, lambda d: d["CaughtIncompetentRate"])
    mal = extract(data, lambda d: d["CaughtMaliciousRate"])
    sla = extract(data, lambda d: d["SLABreachedRate"])
    incon = extract(data, lambda d: d["InconclusiveRate"])
    ax1.stackplot(
        xs,
        trust, inc, mal, sla, incon,
        labels=[VERDICT_LABELS[m] for m in ["TrustedRate", "CaughtIncompetentRate", "CaughtMaliciousRate", "SLABreachedRate", "InconclusiveRate"]],
        colors=[VERDICT_COLORS[m] for m in ["TrustedRate", "CaughtIncompetentRate", "CaughtMaliciousRate", "SLABreachedRate", "InconclusiveRate"]],
        alpha=0.8,
    )
    if log_x:
        ax1.set_xscale("log")
    ax1.set_xlabel(x_label)
    ax1.set_ylabel("verdict rate")
    ax1.set_ylim(0, 1)
    ax1.set_xlim(xs.min(), xs.max())
    ax1.set_title("Verdict distribution")
    ax1.legend(fontsize=8, loc="upper right", framealpha=0.9)

    # line plot with CI
    for metric, ci_key in [
        ("TrustedRate", "TrustedRateCI"),
        ("CaughtIncompetentRate", "CaughtIncompetentRateCI"),
        ("CaughtMaliciousRate", "CaughtMaliciousRateCI"),
        ("CorrectDetectionRate", "CorrectDetectionRateCI"),
    ]:
        ys = extract(data, lambda d: d[metric])
        ax2.plot(xs, ys, marker="o", markersize=4, color=VERDICT_COLORS[metric], label=VERDICT_LABELS[metric], linewidth=1.2)
        if ci_key in data[0]:
            cis = [d[ci_key] for d in data]
            if cis and isinstance(cis[0], list) and len(cis[0]) == 2:
                lo = np.array([c[0] for c in cis])
                hi = np.array([c[1] for c in cis])
                ax2.fill_between(xs, lo, hi, color=VERDICT_COLORS[metric], alpha=0.15)
    if log_x:
        ax2.set_xscale("log")
    ax2.set_xlabel(x_label)
    ax2.set_ylabel("rate")
    ax2.set_ylim(-0.03, 1.03)
    ax2.set_title("Verdict rates with 95% CI")
    ax2.legend(fontsize=8, loc="best")

    fig.suptitle(title, y=1.02)
    save(fig, f"{out_prefix}_verdicts.png")

    # --- Plot B: queries ---------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.plot(xs, extract(data, lambda d: d["MedianQueriesToVerdict"]), marker="o", color=ORANGE, label="median", linewidth=1.4)
    ax.plot(xs, extract(data, lambda d: d["MeanQueriesToVerdict"]), marker="^", color=BLUE, label="mean", linewidth=1.2, linestyle=":")
    ax.plot(xs, extract(data, lambda d: d["P90QueriesToVerdict"]), marker="s", color=RED, label="p90", linewidth=1.0, alpha=0.75)
    if log_x:
        ax.set_xscale("log")
    ax.set_xlabel(x_label)
    ax.set_ylabel("queries to verdict")
    ax.set_title(f"{title} — queries to verdict")
    ax.legend(fontsize=9)
    save(fig, f"{out_prefix}_queries.png")

    # --- Plot C: posteriors ------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.8))
    h0 = extract(data, lambda d: d["MeanPosteriorH0"])
    h1 = extract(data, lambda d: d["MeanPosteriorH1"])
    h2 = extract(data, lambda d: d["MeanPosteriorH2"])
    ax.plot(xs, h0, marker="o", color=GREEN, label=r"$\bar{P}(H_0)$ honest")
    ax.plot(xs, h1, marker="s", color=ORANGE, label=r"$\bar{P}(H_1)$ incompetent")
    ax.plot(xs, h2, marker="^", color=RED, label=r"$\bar{P}(H_2)$ malicious")
    if log_x:
        ax.set_xscale("log")
    ax.set_xlabel(x_label)
    ax.set_ylabel("terminal posterior mass")
    ax.set_ylim(-0.03, 1.03)
    ax.set_title(f"{title} — terminal posteriors")
    ax.legend(fontsize=9)
    save(fig, f"{out_prefix}_posteriors.png")


# ---------------------------------------------------------------------------
# Phase map (2D heatmaps)
# ---------------------------------------------------------------------------
def plot_phase_map():
    path = INCOMP / "pincomp_flagrel_phase_map.json"
    if not path.exists():
        print("  [skip] pincomp_flagrel_phase_map.json not found")
        return
    data = load(path)

    # Build sorted axes
    pincomps = sorted({round(d["Config"]["DelayModel"]["IncompetenceRate"], 8) for d in data})
    flagrels = sorted({round(d["Config"]["FlagReliability"], 8) for d in data})
    pi_idx = {v: i for i, v in enumerate(pincomps)}
    fr_idx = {v: i for i, v in enumerate(flagrels)}

    shape = (len(pincomps), len(flagrels))

    def grid(key):
        g = np.full(shape, np.nan)
        for d in data:
            pi = round(d["Config"]["DelayModel"]["IncompetenceRate"], 8)
            fr = round(d["Config"]["FlagReliability"], 8)
            g[pi_idx[pi], fr_idx[fr]] = d[key]
        return g

    metrics = [
        ("CorrectDetectionRate", "Correct detection rate", "viridis", 0.0, 1.0),
        ("TrustedRate", "Trusted rate", "Greens", 0.0, 1.0),
        ("CaughtIncompetentRate", "Caught-incompetent rate", "Oranges", 0.0, 1.0),
        ("CaughtMaliciousRate", "Caught-malicious rate", "Reds", 0.0, 1.0),
        ("SLABreachedRate", "SLA-breached rate", "Purples", 0.0, 1.0),
        ("InconclusiveRate", "Inconclusive rate", "Greys", 0.0, 1.0),
        ("MeanQueriesToVerdict", "Mean queries to verdict", "magma", None, None),
    ]

    # Pretty tick labels (show every other one to avoid clutter)
    def fmt_ticks(vals):
        labels = []
        for i, v in enumerate(vals):
            if i % 2 == 0 or i == len(vals) - 1:
                labels.append(f"{v:.3g}")
            else:
                labels.append("")
        return labels

    x_ticks = fmt_ticks(flagrels)
    y_ticks = fmt_ticks(pincomps)

    # Individual heatmaps
    for key, title, cmap, vmin, vmax in metrics:
        g = grid(key)
        fig, ax = plt.subplots(figsize=(7.5, 6.2))
        sns.heatmap(
            g,
            ax=ax,
            cmap=cmap,
            vmin=vmin,
            vmax=vmax,
            xticklabels=x_ticks,
            yticklabels=y_ticks,
            cbar_kws={"label": title},
            linewidths=0,
            square=False,
        )
        ax.invert_yaxis()
        ax.set_xlabel("Flag reliability  (P(flag | incompetent))")
        ax.set_ylabel("Incompetence rate  $p_{\\mathrm{incomp}}$")
        ax.set_title(f"Phase map: {title}")
        # nicer rotation
        ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
        ax.set_yticklabels(ax.get_yticklabels(), rotation=0)
        save(fig, f"phase_map_{key}.png")

    # Combined grid of all verdict heatmaps
    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    keys = [
        ("CorrectDetectionRate", "Correct detection", "viridis"),
        ("TrustedRate", "TRUSTED", "Greens"),
        ("CaughtIncompetentRate", "CAUGHT_INCOMPETENT", "Oranges"),
        ("CaughtMaliciousRate", "CAUGHT_MALICIOUS", "Reds"),
        ("SLABreachedRate", "SLA_BREACHED", "Purples"),
        ("InconclusiveRate", "INCONCLUSIVE", "Greys"),
    ]
    for ax, (key, title, cmap) in zip(axes.flat, keys):
        g = grid(key)
        sns.heatmap(
            g,
            ax=ax,
            cmap=cmap,
            vmin=0.0,
            vmax=1.0,
            xticklabels=x_ticks,
            yticklabels=y_ticks,
            cbar_kws={"label": "rate"},
        )
        ax.invert_yaxis()
        ax.set_xlabel("Flag reliability")
        ax.set_ylabel(r"$p_{\mathrm{incomp}}$")
        ax.set_title(title)
        ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
        ax.set_yticklabels(ax.get_yticklabels(), rotation=0)
    fig.suptitle(
        r"Phase map across $p_{\mathrm{incomp}} \times$ flag-reliability",
        y=1.00,
        fontsize=14,
    )
    fig.tight_layout()
    save(fig, "phase_map_combined.png")

    # Contour plot of correct-detection rate
    fig, ax = plt.subplots(figsize=(8, 6.2))
    g = grid("CorrectDetectionRate")
    X, Y = np.meshgrid(np.array(flagrels), np.array(pincomps))
    cf = ax.contourf(X, Y, g, levels=np.linspace(0, 1, 21), cmap="viridis")
    cs = ax.contour(X, Y, g, levels=[0.5, 0.8, 0.9, 0.95, 0.99], colors="white", linewidths=0.8)
    ax.clabel(cs, inline=True, fontsize=8, fmt="%.2f")
    ax.set_yscale("log")
    ax.set_xlabel("Flag reliability")
    ax.set_ylabel(r"$p_{\mathrm{incomp}}$ (log)")
    ax.set_title("Correct-detection rate — contour (log $p_{\\mathrm{incomp}}$)")
    fig.colorbar(cf, ax=ax, label="Correct-detection rate")
    save(fig, "phase_map_CorrectDetectionRate_contour.png")


# ---------------------------------------------------------------------------
# Posterior / queries distribution over trials (use seed_2 as representative)
# ---------------------------------------------------------------------------
def plot_trial_distributions():
    """Per-configuration trial-level queries distribution for incompetence_rate_sweep."""
    seeds = collect_seed_sweeps("incompetence_rate_sweep.json")
    if not seeds:
        return

    # Pick one seed, show a grid of boxplots over x
    label, data = seeds[0]
    xs = extract(data, lambda d: d["Config"]["DelayModel"]["IncompetenceRate"])
    order = np.argsort(xs)
    xs = xs[order]
    data = [data[i] for i in order]

    # Box of queries-used per configuration
    queries_per_cfg = [[t["QueriesUsed"] for t in d["Trials"]] for d in data]

    fig, ax = plt.subplots(figsize=(12, 5))
    positions = np.arange(len(xs))
    bp = ax.boxplot(queries_per_cfg, positions=positions, widths=0.6, showfliers=False, patch_artist=True)
    for patch in bp["boxes"]:
        patch.set_facecolor(BLUE)
        patch.set_alpha(0.5)
    xticks = np.arange(0, len(xs), 3)
    ax.set_xticks(xticks)
    ax.set_xticklabels([f"{xs[i]:.3g}" for i in xticks], rotation=45, ha="right")
    ax.set_xlabel(r"Incompetence rate $p_{\mathrm{incomp}}$")
    ax.set_ylabel("Queries used (per trial)")
    ax.set_title(f"Per-trial queries distribution ({label}, incompetence_rate_sweep)")
    save(fig, "trials_queries_box_incompetence.png")

    # Stacked verdict outcomes (per trial, as counts)
    verdict_classes = ["TRUSTED", "CAUGHT_INCOMPETENT", "CAUGHT_MALICIOUS", "SLA_BREACHED", "INCONCLUSIVE"]
    verdict_colors = [VERDICT_COLORS["TrustedRate"], VERDICT_COLORS["CaughtIncompetentRate"], VERDICT_COLORS["CaughtMaliciousRate"], VERDICT_COLORS["SLABreachedRate"], VERDICT_COLORS["InconclusiveRate"]]
    counts = np.zeros((len(verdict_classes), len(xs)))
    for j, d in enumerate(data):
        for t in d["Trials"]:
            vc = t.get("VerdictClass", "")
            if vc in verdict_classes:
                counts[verdict_classes.index(vc), j] += 1
    totals = counts.sum(axis=0)
    totals[totals == 0] = 1
    rates = counts / totals
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.stackplot(xs, rates, labels=verdict_classes, colors=verdict_colors, alpha=0.85)
    ax.set_xscale("log")
    ax.set_xlabel(r"Incompetence rate $p_{\mathrm{incomp}}$")
    ax.set_ylabel("verdict rate (from trial-level verdicts)")
    ax.set_ylim(0, 1)
    ax.set_xlim(xs.min(), xs.max())
    ax.set_title(f"Trial-level verdict distribution ({label}, incompetence_rate_sweep)")
    ax.legend(fontsize=8, loc="upper left")
    save(fig, "trials_verdict_stack_incompetence.png")


# ---------------------------------------------------------------------------
# Cross-sweep summary (queries to verdict across all sweeps for seed_2)
# ---------------------------------------------------------------------------
def plot_cross_sweep_summary():
    """Small multiples showing each sweep's correct-detection rate side by side (seed_2 only)."""
    seed2 = INCOMP / "seed_2"
    if not seed2.is_dir():
        return
    entries = [
        ("incompetence_rate_sweep.json", lambda d: d["Config"]["DelayModel"]["IncompetenceRate"], r"$p_{\mathrm{incomp}}$", True),
        ("alpha_sweep.json", lambda d: 1.0 - d["Config"]["Verification"]["ConfidenceThreshold"], r"$1-\alpha$", True),
        ("eta_sweep.json", lambda d: d["Config"]["Verification"]["ErrorTolerance"], r"$\eta$", True),
        ("answer_error_sweep.json", lambda d: d["Config"]["AnswerErrorRate"], "answer error rate", False),
        ("flag_reliability_sweep.json", lambda d: d["Config"]["FlagReliability"], "flag reliability", False),
        ("flag_reliability_sweep_high_pincomp.json", lambda d: d["Config"]["FlagReliability"], "flag rel. (high pincomp)", False),
    ]
    fig, axes = plt.subplots(1, len(entries), figsize=(4 * len(entries), 4.2))
    for ax, (fname, getter, xlab, logx) in zip(axes, entries):
        fp = seed2 / fname
        if not fp.exists():
            ax.set_visible(False)
            continue
        data = load(fp)
        xs = extract(data, getter)
        order = np.argsort(xs)
        xs = xs[order]
        data = [data[i] for i in order]
        for metric, color in [
            ("CorrectDetectionRate", BLUE),
            ("CaughtIncompetentRate", ORANGE),
            ("TrustedRate", GREEN),
        ]:
            ys = extract(data, lambda d: d[metric])
            ax.plot(xs, ys, marker="o", markersize=3, color=color, label=VERDICT_LABELS[metric], linewidth=1.2)
        if logx and (xs > 0).all():
            ax.set_xscale("log")
        ax.set_xlabel(xlab)
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(fname.replace(".json", ""), fontsize=9)
    axes[0].set_ylabel("rate")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.03), fontsize=9)
    fig.suptitle("Cross-sweep overview (seed_2)", y=1.02)
    fig.tight_layout(rect=[0, 0.04, 1, 0.98])
    save(fig, "cross_sweep_overview_seed2.png")


# ---------------------------------------------------------------------------
# Numpackets sweep across pincomp levels (overlay)
# ---------------------------------------------------------------------------
def plot_numpackets_pincomp_overlay():
    """Overlay numpackets sweeps for different pincomp levels on a single figure."""
    variants = [
        ("numpackets_sweep_pincomp0.050.json", 0.05, BLUE),
        ("numpackets_sweep_pincomp0.100.json", 0.10, ORANGE),
        ("numpackets_sweep_pincomp0.200.json", 0.20, RED),
    ]
    loaded = []
    for fname, pincomp, color in variants:
        p = INCOMP / fname
        if p.exists():
            data = load(p)
            xs = extract(data, lambda d: d["Config"]["NumPackets"])
            order = np.argsort(xs)
            loaded.append((pincomp, color, xs[order], [data[i] for i in order]))

    if not loaded:
        print("  [skip] no numpackets_sweep_pincomp*.json found")
        return

    for metric in ["CorrectDetectionRate", "TrustedRate", "CaughtIncompetentRate"]:
        fig, ax = plt.subplots(figsize=(7, 4.8))
        for pincomp, color, xs, data in loaded:
            label = rf"$p_{{\mathrm{{incomp}}}}={pincomp:.3g}$"
            ys = extract(data, lambda d, m=metric: d[m])
            ax.plot(xs, ys, marker="o", markersize=4, color=color, label=label, linewidth=1.3)
        ax.set_xscale("log")
        ax.set_xlabel("Number of packets")
        ax.set_ylabel("rate")
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(VERDICT_LABELS[metric], color=VERDICT_COLORS[metric])
        ax.legend(fontsize=9, loc="best")
        fig.suptitle(r"Num-packets sweep across $p_{\mathrm{incomp}}$ levels", y=1.02)
        save(fig, f"numpackets_sweep_pincomp_{metric}.png")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not INCOMP.is_dir():
        raise SystemExit(f"No results in {INCOMP}. Run the simulation first.")
    print(f"Writing figures to {OUT.relative_to(HERE.parent)}/")

    # --- Multi-seed sweeps ------------------------------------------------
    print("[multi-seed] incompetence_rate_sweep")
    plot_multiseed_sweep(
        "incompetence_rate_sweep.json",
        lambda d: d["Config"]["DelayModel"]["IncompetenceRate"],
        r"Incompetence rate $p_{\mathrm{incomp}}$",
        "incompetence_rate_sweep",
        "Incompetence-rate sweep",
        log_x=True,
    )
    print("[multi-seed] alpha_sweep")
    plot_multiseed_sweep(
        "alpha_sweep.json",
        lambda d: 1.0 - d["Config"]["Verification"]["ConfidenceThreshold"],
        r"$1-\alpha$  (stricter $\rightarrow$)",
        "alpha_sweep",
        r"Confidence-threshold sweep ($\alpha$)",
        log_x=True,
    )
    print("[multi-seed] eta_sweep")
    plot_multiseed_sweep(
        "eta_sweep.json",
        lambda d: d["Config"]["Verification"]["ErrorTolerance"],
        r"Error tolerance $\eta$",
        "eta_sweep",
        r"Error-tolerance sweep ($\eta$)",
        log_x=True,
    )
    print("[multi-seed] answer_error_sweep")
    plot_multiseed_sweep(
        "answer_error_sweep.json",
        lambda d: d["Config"]["AnswerErrorRate"],
        "Answer error rate",
        "answer_error_sweep",
        "Answer-error sweep",
        log_x=False,
    )
    print("[multi-seed] flag_reliability_sweep")
    plot_multiseed_sweep(
        "flag_reliability_sweep.json",
        lambda d: d["Config"]["FlagReliability"],
        "Flag reliability  $P(\\mathrm{flag}\\mid\\mathrm{incompetent})$",
        "flag_reliability_sweep",
        "Flag-reliability sweep",
        log_x=False,
    )
    print("[multi-seed] flag_reliability_sweep_high_pincomp")
    plot_multiseed_sweep(
        "flag_reliability_sweep_high_pincomp.json",
        lambda d: d["Config"]["FlagReliability"],
        "Flag reliability  $P(\\mathrm{flag}\\mid\\mathrm{incompetent})$",
        "flag_reliability_sweep_high_pincomp",
        r"Flag-reliability sweep (high $p_{\mathrm{incomp}}$)",
        log_x=False,
    )

    # --- Top-level single-seed sweeps -------------------------------------
    print("[single] alpha_sweep (top-level)")
    plot_single_sweep(
        "alpha_sweep.json",
        lambda d: 1.0 - d["Config"]["Verification"]["ConfidenceThreshold"],
        r"$1-\alpha$  (stricter $\rightarrow$)",
        "alpha_sweep_single",
        r"Confidence-threshold sweep ($\alpha$, single seed)",
        log_x=True,
    )
    print("[single] eta_sweep (top-level)")
    plot_single_sweep(
        "eta_sweep.json",
        lambda d: d["Config"]["Verification"]["ErrorTolerance"],
        r"Error tolerance $\eta$",
        "eta_sweep_single",
        r"Error-tolerance sweep ($\eta$, single seed)",
        log_x=True,
    )
    print("[single] answer_error_sweep (top-level)")
    plot_single_sweep(
        "answer_error_sweep.json",
        lambda d: d["Config"]["AnswerErrorRate"],
        "Answer error rate",
        "answer_error_sweep_single",
        "Answer-error sweep (single seed)",
        log_x=False,
    )
    print("[single] batch_size_sweep")
    plot_single_sweep(
        "batch_size_sweep.json",
        lambda d: d["Config"]["BatchSize"],
        "Batch size $B$",
        "batch_size_sweep",
        "Batch-size sweep",
        log_x=True,
    )
    print("[single] magnitude_sweep")
    plot_single_sweep(
        "magnitude_sweep.json",
        lambda d: d["Config"]["DelayModel"]["IncompetenceMu"],
        r"Incompetence magnitude $\mu$  (log-normal mean)",
        "magnitude_sweep",
        "Incompetence-magnitude sweep",
        log_x=False,
    )
    print("[single] numpackets_sweep")
    plot_single_sweep(
        "numpackets_sweep.json",
        lambda d: d["Config"]["NumPackets"],
        "Number of packets",
        "numpackets_sweep",
        "Num-packets sweep",
        log_x=True,
    )
    print("[single] queries_per_batch_sweep")
    plot_single_sweep(
        "queries_per_batch_sweep.json",
        lambda d: d["Config"]["Verification"]["QueriesPerBatch"],
        "Queries per batch",
        "queries_per_batch_sweep",
        "Queries-per-batch sweep",
        log_x=False,
    )
    print("[single] tau_flag_sweep")
    plot_single_sweep(
        "tau_flag_sweep.json",
        lambda d: d["Config"]["Verification"]["FlaggingRateThreshold"],
        r"Flagging-rate threshold $\tau_{\mathrm{flag}}$",
        "tau_flag_sweep",
        r"$\tau_{\mathrm{flag}}$ sweep",
        log_x=True,
    )
    print("[single] flag_reliability_sweep_low_pincomp")
    plot_single_sweep(
        "flag_reliability_sweep_low_pincomp.json",
        lambda d: d["Config"]["FlagReliability"],
        "Flag reliability  $P(\\mathrm{flag}\\mid\\mathrm{incompetent})$",
        "flag_reliability_sweep_low_pincomp",
        r"Flag-reliability sweep (low $p_{\mathrm{incomp}}$)",
        log_x=False,
    )

    # --- Numpackets pincomp overlay ----------------------------------------
    print("[overlay] numpackets sweep across pincomp levels")
    plot_numpackets_pincomp_overlay()

    # --- Phase map --------------------------------------------------------
    print("[phase] pincomp x flag_reliability")
    plot_phase_map()

    # --- Distributions and overview --------------------------------------
    print("[extras] trial distributions")
    plot_trial_distributions()
    print("[extras] cross-sweep overview")
    plot_cross_sweep_summary()

    print("done.")


if __name__ == "__main__":
    main()
