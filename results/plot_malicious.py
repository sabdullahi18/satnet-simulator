"""Plot the malicious-network experiment results.

Each plot is saved as its own PNG under results/malicious/plots/.
"""

import json
import re
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

HERE = Path(__file__).resolve().parent
MAL = HERE / "malicious"
OUT = MAL / "plots"
OUT.mkdir(exist_ok=True)

sns.set_theme(style="whitegrid", context="paper")

# --- palette ------------------------------------------------------------------
GREY   = "#6e6e6e"
BLUE   = "#1f77b4"
ORANGE = "#ff7f0e"
GREEN  = "#2ca02c"
RED    = "#d62728"
PURPLE = "#9467bd"
BROWN  = "#8c564b"
PINK   = "#e377c2"

VERDICT_COLORS = {
    "MissedRate":             GREEN,
    "CaughtMaliciousRate":    RED,
    "MisclassifiedIncompRate": ORANGE,
    "SLABreachedRate":        PURPLE,
    "InconclusiveRate":       BROWN,
    "CorrectDetectionRate":   BLUE,
}
VERDICT_LABELS = {
    "MissedRate":             "MISSED (trusted)",
    "CaughtMaliciousRate":    "CAUGHT_MALICIOUS",
    "MisclassifiedIncompRate": "MISCLASSIFIED_INCOMPETENT",
    "SLABreachedRate":        "SLA_BREACHED",
    "InconclusiveRate":       "INCONCLUSIVE",
    "CorrectDetectionRate":   "CORRECT_DETECTION",
}
STACK_METRICS = ["MissedRate", "CaughtMaliciousRate", "MisclassifiedIncompRate", "SLABreachedRate", "InconclusiveRate"]
LINE_METRICS  = ["MissedRate", "CaughtMaliciousRate", "MisclassifiedIncompRate", "CorrectDetectionRate"]


# --- helpers ------------------------------------------------------------------
def load(path: Path):
    with open(path) as f:
        return json.load(f)


def save(fig, name: str):
    fig.tight_layout()
    fig.savefig(OUT / name, dpi=180)
    plt.close(fig)
    print(f"  wrote {(OUT / name).relative_to(HERE.parent)}")


def extract(data, getter):
    return np.array([getter(d) for d in data])


def sort_by(data, getter):
    xs = extract(data, getter)
    order = np.argsort(xs)
    return xs[order], [data[i] for i in order]


def ci_bands(ax, xs, data, metric, color, log_x=False):
    ci_key = metric + "CI"
    if ci_key not in data[0]:
        return
    cis = data[0][ci_key]
    if isinstance(cis, dict):
        lo = np.array([d[ci_key]["Lower"] for d in data])
        hi = np.array([d[ci_key]["Upper"] for d in data])
    elif isinstance(cis, list) and len(cis) == 2:
        lo = np.array([d[ci_key][0] for d in data])
        hi = np.array([d[ci_key][1] for d in data])
    else:
        return
    ax.fill_between(xs, lo, hi, color=color, alpha=0.15)


# --- multi-seed helpers -------------------------------------------------------
def seed_dirs():
    """Return dict of seed_label -> Path for each seed_* subdir in MAL."""
    out = {}
    for d in sorted(MAL.iterdir()):
        if d.is_dir() and d.name.startswith("seed_"):
            label = d.name
            m = re.match(r"seed_(\d+)$", label)
            if m and len(m.group(1)) > 4:
                label = f"seed_{m.group(1)[:4]}…"
            out[label] = d
    return out


def collect_seed_sweeps(fname: str):
    """Return list of (seed_label, data) for all seeds that contain fname."""
    results = []
    for label, path in seed_dirs().items():
        fp = path / fname
        if fp.exists():
            results.append((label, load(fp)))
    return results


# --- multi-seed sweep plotter -------------------------------------------------
def plot_multiseed_sweep(
    fname: str,
    x_getter,
    x_label: str,
    out_prefix: str,
    title: str,
    log_x: bool = False,
    sort_x: bool = True,
):
    seeds = collect_seed_sweeps(fname)
    if not seeds:
        print(f"  [skip] no seed runs for {fname}")
        return

    per_seed = {}
    for label, data in seeds:
        xs = extract(data, x_getter)
        if sort_x:
            order = np.argsort(xs)
            xs = xs[order]
            data = [data[i] for i in order]
        per_seed[label] = {"x": xs, "data": data}

    ref_label = next(iter(per_seed))
    xs_ref = per_seed[ref_label]["x"]

    # --- verdict rates (one PNG per metric) -----------------------------------
    all_metrics = list(VERDICT_COLORS)
    for metric in all_metrics:
        fig, ax = plt.subplots(figsize=(7, 4.5))
        stacked = []
        for label, bundle in per_seed.items():
            ys = extract(bundle["data"], lambda d, m=metric: d[m])
            ax.plot(
                bundle["x"], ys,
                marker="o", markersize=3, linewidth=0.9, alpha=0.45,
                label=label,
            )
            if len(bundle["x"]) == len(xs_ref) and np.allclose(bundle["x"], xs_ref):
                stacked.append(ys)
        if stacked:
            stack = np.vstack(stacked)
            mean = stack.mean(axis=0)
            ax.plot(xs_ref, mean, color="black", linewidth=2.0, label="seed mean")
            if stack.shape[0] >= 2:
                ax.fill_between(xs_ref, stack.min(axis=0), stack.max(axis=0),
                                color="black", alpha=0.08)
        ax.set_title(VERDICT_LABELS[metric], color=VERDICT_COLORS[metric])
        ax.set_ylim(-0.03, 1.03)
        ax.set_ylabel("rate")
        if log_x:
            ax.set_xscale("log")
        ax.set_xlabel(x_label)
        ax.legend(fontsize=8, ncol=2, loc="best")
        fig.suptitle(f"{title} — {VERDICT_LABELS[metric]}", y=1.02)
        save(fig, f"{out_prefix}_verdict_{metric}.png")

    # --- queries (median + mean) ----------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5))
    stacked_mean, stacked_med = [], []
    for label, bundle in per_seed.items():
        med  = extract(bundle["data"], lambda d: d["MedianQueriesToVerdict"])
        mean = extract(bundle["data"], lambda d: d["MeanQueriesToVerdict"])
        ax.plot(bundle["x"], med,  marker="o", markersize=3, linewidth=0.9, alpha=0.45,
                label=f"{label} median")
        ax.plot(bundle["x"], mean, marker="^", markersize=3, linewidth=0.9, alpha=0.25,
                linestyle=":")
        if len(bundle["x"]) == len(xs_ref) and np.allclose(bundle["x"], xs_ref):
            stacked_mean.append(mean)
            stacked_med.append(med)
    if stacked_mean:
        ax.plot(xs_ref, np.vstack(stacked_med).mean(axis=0),
                color="black", linewidth=2.0, label="seed mean (median)")
        ax.plot(xs_ref, np.vstack(stacked_mean).mean(axis=0),
                color=GREY, linewidth=1.6, linestyle="--", label="seed mean (mean)")
    if log_x:
        ax.set_xscale("log")
    ax.set_xlabel(x_label)
    ax.set_ylabel("queries to verdict")
    ax.set_title(f"{title} — queries to verdict")
    ax.legend(fontsize=8, ncol=2, loc="best")
    save(fig, f"{out_prefix}_queries.png")

    # --- posteriors (one PNG per hypothesis) ----------------------------------
    for key, col, name in zip(
        ["MeanPosteriorH0", "MeanPosteriorH1", "MeanPosteriorH2"],
        [GREEN, ORANGE, RED],
        [r"$\bar{P}(H_0)$ honest", r"$\bar{P}(H_1)$ incompetent", r"$\bar{P}(H_2)$ malicious"],
    ):
        fig, ax = plt.subplots(figsize=(7, 4.5))
        stacked = []
        for label, bundle in per_seed.items():
            ys = extract(bundle["data"], lambda d, k=key: d[k])
            ax.plot(bundle["x"], ys, marker="o", markersize=3, linewidth=0.9,
                    alpha=0.45, label=label)
            if len(bundle["x"]) == len(xs_ref) and np.allclose(bundle["x"], xs_ref):
                stacked.append(ys)
        if stacked:
            ax.plot(xs_ref, np.vstack(stacked).mean(axis=0),
                    color="black", linewidth=2.0, label="seed mean")
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


# --- single-file sweep plotter -----------------------------------------------
def plot_sweep(
    data,
    xs,
    x_label: str,
    out_prefix: str,
    title: str,
    log_x: bool = False,
):
    # --- verdicts stacked area + line ------------------------------------------
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.8))

    stacked = [extract(data, lambda d, m=m: d[m]) for m in STACK_METRICS]
    ax1.stackplot(
        xs, *stacked,
        labels=[VERDICT_LABELS[m] for m in STACK_METRICS],
        colors=[VERDICT_COLORS[m] for m in STACK_METRICS],
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

    for metric in LINE_METRICS:
        ys = extract(data, lambda d, m=metric: d[m])
        ax2.plot(xs, ys, marker="o", markersize=4,
                 color=VERDICT_COLORS[metric], label=VERDICT_LABELS[metric], linewidth=1.2)
        ci_bands(ax2, xs, data, metric, VERDICT_COLORS[metric])
    if log_x:
        ax2.set_xscale("log")
    ax2.set_xlabel(x_label)
    ax2.set_ylabel("rate")
    ax2.set_ylim(-0.03, 1.03)
    ax2.set_title("Verdict rates with 95 % CI")
    ax2.legend(fontsize=8, loc="best")

    fig.suptitle(title, y=1.02)
    save(fig, f"{out_prefix}_verdicts.png")

    # --- individual verdict PNGs ---------------------------------------------
    for metric in list(VERDICT_COLORS):
        ys = extract(data, lambda d, m=metric: d[m])
        fig, ax = plt.subplots(figsize=(7, 4.5))
        ax.plot(xs, ys, marker="o", markersize=4,
                color=VERDICT_COLORS[metric], linewidth=1.3)
        ci_bands(ax, xs, data, metric, VERDICT_COLORS[metric])
        if log_x:
            ax.set_xscale("log")
        ax.set_xlabel(x_label)
        ax.set_ylabel("rate")
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(VERDICT_LABELS[metric], color=VERDICT_COLORS[metric])
        fig.suptitle(title, y=1.02)
        save(fig, f"{out_prefix}_verdict_{metric}.png")

    # --- queries --------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.plot(xs, extract(data, lambda d: d["MedianQueriesToVerdict"]),
            marker="o", color=ORANGE, label="median", linewidth=1.4)
    ax.plot(xs, extract(data, lambda d: d["MeanQueriesToVerdict"]),
            marker="^", color=BLUE, label="mean", linewidth=1.2, linestyle=":")
    ax.plot(xs, extract(data, lambda d: d["P90QueriesToVerdict"]),
            marker="s", color=RED, label="p90", linewidth=1.0, alpha=0.75)
    if log_x:
        ax.set_xscale("log")
    ax.set_xlabel(x_label)
    ax.set_ylabel("queries to verdict")
    ax.set_title(f"{title} — queries to verdict")
    ax.legend(fontsize=9)
    save(fig, f"{out_prefix}_queries.png")

    # --- posteriors -----------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.plot(xs, extract(data, lambda d: d["MeanPosteriorH0"]),
            marker="o", color=GREEN, label=r"$\bar{P}(H_0)$ honest")
    ax.plot(xs, extract(data, lambda d: d["MeanPosteriorH1"]),
            marker="s", color=ORANGE, label=r"$\bar{P}(H_1)$ incompetent")
    ax.plot(xs, extract(data, lambda d: d["MeanPosteriorH2"]),
            marker="^", color=RED, label=r"$\bar{P}(H_2)$ malicious")
    if log_x:
        ax.set_xscale("log")
    ax.set_xlabel(x_label)
    ax.set_ylabel("terminal posterior mass")
    ax.set_ylim(-0.03, 1.03)
    ax.set_title(f"{title} — terminal posteriors")
    ax.legend(fontsize=9)
    save(fig, f"{out_prefix}_posteriors.png")

    # --- contradictions -------------------------------------------------------
    if "MeanContradictions" in data[0]:
        fig, ax = plt.subplots(figsize=(8, 4.8))
        ax.plot(xs, extract(data, lambda d: d["MeanContradictions"]),
                marker="o", color=PURPLE, linewidth=1.3)
        if log_x:
            ax.set_xscale("log")
        ax.set_xlabel(x_label)
        ax.set_ylabel("mean contradictions found")
        ax.set_title(f"{title} — mean contradictions")
        save(fig, f"{out_prefix}_contradictions.png")


# --- naive liar ptarget sweep -------------------------------------------------
def plot_naive_liar():
    print("[multi-seed] naive_liar_ptarget_sweep")
    plot_multiseed_sweep(
        "naive_liar_ptarget_sweep.json",
        lambda d: d["Config"]["Targeting"]["TargetFraction"],
        r"Target fraction $p_{\mathrm{target}}$",
        "naive_liar_ptarget",
        r"Naive liar — $p_{\mathrm{target}}$ sweep  ($p_{\mathrm{lie}}=1$)",
        log_x=True,
    )


# --- silent dropper ptarget sweep ---------------------------------------------
def plot_silent_dropper():
    print("[multi-seed] silent_dropper_ptarget_sweep")
    plot_multiseed_sweep(
        "silent_dropper_ptarget_sweep.json",
        lambda d: d["Config"]["Targeting"]["TargetFraction"],
        r"Target fraction $p_{\mathrm{target}}$",
        "silent_dropper_ptarget",
        r"Silent dropper — $p_{\mathrm{target}}$ sweep",
        log_x=True,
    )


# --- smart compliant sweep ----------------------------------------------------
def plot_smart_compliant():
    print("[multi-seed] smart_compliant_sweep")
    plot_multiseed_sweep(
        "smart_compliant_sweep.json",
        lambda d: d["Config"]["Targeting"]["TargetFraction"],
        r"Target fraction $p_{\mathrm{target}}$",
        "smart_compliant",
        r"Smart compliant — $p_{\mathrm{target}}$ sweep  ($p_{\mathrm{flag}}=1$)",
        log_x=False,
    )


# --- smart overshoot sweep ----------------------------------------------------
def plot_smart_overshoot():
    print("[multi-seed] smart_overshoot_sweep")
    plot_multiseed_sweep(
        "smart_overshoot_sweep.json",
        lambda d: d["Config"]["Targeting"]["TargetFraction"],
        r"Target fraction $p_{\mathrm{target}}$",
        "smart_overshoot",
        r"Smart overshoot — $p_{\mathrm{target}}$ sweep  ($p_{\mathrm{flag}}=1$)",
        log_x=False,
    )


# --- parametric ptarget sweeps across plie values ----------------------------
def plot_parametric_ptarget_vs_plie():
    """Overlay ptarget sweeps for plie ∈ {0, 0.25, 0.50, 0.75, 1.00}."""
    files = [
        ("parametric_ptarget_plie0.00.json", 0.00, BLUE),
        ("parametric_ptarget_plie0.25.json", 0.25, GREEN),
        ("parametric_ptarget_plie0.50.json", 0.50, ORANGE),
        ("parametric_ptarget_plie0.75.json", 0.75, PURPLE),
        ("parametric_ptarget_plie1.00.json", 1.00, RED),
    ]
    loaded = []
    for fname, plie, color in files:
        p = MAL / fname
        if p.exists():
            data = load(p)
            xs, data = sort_by(data, lambda d: d["Config"]["Targeting"]["TargetFraction"])
            loaded.append((plie, color, xs, data))
    if not loaded:
        print("  [skip] no parametric_ptarget_plie*.json found")
        return

    print("[overlay] parametric_ptarget vs plie")

    for metric in list(VERDICT_COLORS):
        fig, ax = plt.subplots(figsize=(8, 5))
        for plie, color, xs, data in loaded:
            ys = extract(data, lambda d, m=metric: d[m])
            ax.plot(xs, ys, marker="o", markersize=4, color=color,
                    label=rf"$p_{{\mathrm{{lie}}}}={plie:.2f}$", linewidth=1.3)
        ax.set_xscale("log")
        ax.set_xlabel(r"Target fraction $p_{\mathrm{target}}$")
        ax.set_ylabel("rate")
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(VERDICT_LABELS[metric], color=VERDICT_COLORS[metric])
        ax.legend(fontsize=9, loc="best")
        fig.suptitle(r"Parametric attacker — $p_{\mathrm{target}}$ sweep across $p_{\mathrm{lie}}$", y=1.02)
        save(fig, f"parametric_ptarget_plie_overlay_{metric}.png")

    # queries overlay
    fig, ax = plt.subplots(figsize=(8, 5))
    for plie, color, xs, data in loaded:
        ys = extract(data, lambda d: d["MedianQueriesToVerdict"])
        ax.plot(xs, ys, marker="o", markersize=4, color=color,
                label=rf"$p_{{\mathrm{{lie}}}}={plie:.2f}$", linewidth=1.3)
    ax.set_xscale("log")
    ax.set_xlabel(r"Target fraction $p_{\mathrm{target}}$")
    ax.set_ylabel("median queries to verdict")
    ax.set_title(r"Parametric attacker — queries to verdict across $p_{\mathrm{lie}}$")
    ax.legend(fontsize=9)
    save(fig, "parametric_ptarget_plie_overlay_queries.png")

    # posteriors overlay (H2 malicious is most relevant here)
    for h_key, h_label, h_color in [
        ("MeanPosteriorH0", r"$\bar{P}(H_0)$ honest", GREEN),
        ("MeanPosteriorH2", r"$\bar{P}(H_2)$ malicious", RED),
    ]:
        fig, ax = plt.subplots(figsize=(8, 5))
        for plie, color, xs, data in loaded:
            ys = extract(data, lambda d, k=h_key: d[k])
            ax.plot(xs, ys, marker="o", markersize=4, color=color,
                    label=rf"$p_{{\mathrm{{lie}}}}={plie:.2f}$", linewidth=1.3)
        ax.set_xscale("log")
        ax.set_xlabel(r"Target fraction $p_{\mathrm{target}}$")
        ax.set_ylabel(h_label)
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(h_label, color=h_color)
        ax.legend(fontsize=9)
        fig.suptitle(r"Parametric attacker — posterior across $p_{\mathrm{lie}}$", y=1.02)
        safe = h_key.replace("MeanPosterior", "posterior_")
        save(fig, f"parametric_ptarget_plie_overlay_{safe}.png")


# --- plie sweep overlaid across tau multipliers (aggressive / parametric) ----
def _plot_plie_tau_overlay(file_triplet, out_prefix: str, title: str):
    """
    For each (fname, tau_label, color) in file_triplet, collect all seed runs
    and plot per-seed lines plus a seed-mean overlay, all on the same axes.
    One color = one tau level; alpha lines = individual seeds.
    """
    # Gather: tau_label -> color, list of (xs, data) across seeds
    tau_seeds: dict[str, tuple[str, list]] = {}
    tau_colors: dict[str, str] = {}
    for fname, tau_label, color in file_triplet:
        tau_colors[tau_label] = color
        seed_runs = collect_seed_sweeps(fname)
        if not seed_runs:
            # fall back to top-level file if no seed dirs exist
            p = MAL / fname
            if p.exists():
                data = load(p)
                xs, data = sort_by(data, lambda d: d["Config"]["PLie"])
                seed_runs = [("single", data)]
                # reconstruct xs aligned with data
                seed_runs = [("single", (xs, data))]
        tau_seeds[tau_label] = (color, seed_runs)

    if not any(runs for _, runs in tau_seeds.values()):
        print(f"  [skip] no files found for {out_prefix}")
        return

    def _sorted(seed_data):
        """Return (xs, data) sorted by PLie."""
        xs = extract(seed_data, lambda d: d["Config"]["PLie"])
        order = np.argsort(xs)
        return xs[order], [seed_data[i] for i in order]

    # Build per-tau reference xs (from first seed) for mean overlay
    tau_ref: dict[str, np.ndarray] = {}
    for tau_label, (color, seed_runs) in tau_seeds.items():
        if seed_runs:
            first = seed_runs[0]
            # seed_runs items may be (label, data) OR (label, (xs, data)) from fallback
            raw = first[1]
            if isinstance(raw, tuple):
                tau_ref[tau_label] = raw[0]
            else:
                xs, _ = _sorted(raw)
                tau_ref[tau_label] = xs

    for metric in list(VERDICT_COLORS):
        fig, ax = plt.subplots(figsize=(8, 5))
        for tau_label, (color, seed_runs) in tau_seeds.items():
            stacked = []
            xs_ref = tau_ref.get(tau_label)
            for seed_item in seed_runs:
                raw = seed_item[1]
                if isinstance(raw, tuple):
                    xs, data = raw
                else:
                    xs, data = _sorted(raw)
                ys = extract(data, lambda d, m=metric: d[m])
                ax.plot(xs, ys, marker="o", markersize=3, linewidth=0.8,
                        color=color, alpha=0.35)
                if xs_ref is not None and len(xs) == len(xs_ref) and np.allclose(xs, xs_ref):
                    stacked.append(ys)
            if stacked:
                ax.plot(xs_ref, np.vstack(stacked).mean(axis=0),
                        color=color, linewidth=1.8, label=tau_label)
            elif not stacked and seed_runs:
                # single-seed fallback: label the only line
                ax.lines[-1].set_label(tau_label)
        ax.set_xlabel(r"Lie probability $p_{\mathrm{lie}}$")
        ax.set_ylabel("rate")
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(VERDICT_LABELS[metric], color=VERDICT_COLORS[metric])
        ax.legend(fontsize=9, loc="best")
        fig.suptitle(title, y=1.02)
        save(fig, f"{out_prefix}_verdict_{metric}.png")

    fig, ax = plt.subplots(figsize=(8, 5))
    for tau_label, (color, seed_runs) in tau_seeds.items():
        stacked = []
        xs_ref = tau_ref.get(tau_label)
        for seed_item in seed_runs:
            raw = seed_item[1]
            if isinstance(raw, tuple):
                xs, data = raw
            else:
                xs, data = _sorted(raw)
            ys = extract(data, lambda d: d["MedianQueriesToVerdict"])
            ax.plot(xs, ys, marker="o", markersize=3, linewidth=0.8,
                    color=color, alpha=0.35)
            if xs_ref is not None and len(xs) == len(xs_ref) and np.allclose(xs, xs_ref):
                stacked.append(ys)
        if stacked:
            ax.plot(xs_ref, np.vstack(stacked).mean(axis=0),
                    color=color, linewidth=1.8, label=tau_label)
        elif not stacked and seed_runs:
            ax.lines[-1].set_label(tau_label)
    ax.set_xlabel(r"Lie probability $p_{\mathrm{lie}}$")
    ax.set_ylabel("median queries to verdict")
    ax.set_title(f"{title} — queries to verdict")
    ax.legend(fontsize=9)
    save(fig, f"{out_prefix}_queries.png")

    for h_key, h_label, h_color in [
        ("MeanPosteriorH0", r"$\bar{P}(H_0)$ honest", GREEN),
        ("MeanPosteriorH2", r"$\bar{P}(H_2)$ malicious", RED),
    ]:
        fig, ax = plt.subplots(figsize=(8, 5))
        for tau_label, (color, seed_runs) in tau_seeds.items():
            stacked = []
            xs_ref = tau_ref.get(tau_label)
            for seed_item in seed_runs:
                raw = seed_item[1]
                if isinstance(raw, tuple):
                    xs, data = raw
                else:
                    xs, data = _sorted(raw)
                ys = extract(data, lambda d, k=h_key: d[k])
                ax.plot(xs, ys, marker="o", markersize=3, linewidth=0.8,
                        color=color, alpha=0.35)
                if xs_ref is not None and len(xs) == len(xs_ref) and np.allclose(xs, xs_ref):
                    stacked.append(ys)
            if stacked:
                ax.plot(xs_ref, np.vstack(stacked).mean(axis=0),
                        color=color, linewidth=1.8, label=tau_label)
            elif not stacked and seed_runs:
                ax.lines[-1].set_label(tau_label)
        ax.set_xlabel(r"Lie probability $p_{\mathrm{lie}}$")
        ax.set_ylabel(h_label)
        ax.set_ylim(-0.03, 1.03)
        ax.set_title(h_label, color=h_color)
        ax.legend(fontsize=9)
        fig.suptitle(f"{title} — posterior", y=1.02)
        safe = h_key.replace("MeanPosterior", "posterior_")
        save(fig, f"{out_prefix}_{safe}.png")


def plot_aggressive_plie():
    print("[overlay] aggressive_plie across tau multipliers")
    _plot_plie_tau_overlay(
        [
            ("aggressive_plie_x2tau.json",  r"$2\times\tau_{\mathrm{flag}}$",  BLUE),
            ("aggressive_plie_x5tau.json",  r"$5\times\tau_{\mathrm{flag}}$",  ORANGE),
            ("aggressive_plie_x10tau.json", r"$10\times\tau_{\mathrm{flag}}$", RED),
        ],
        "aggressive_plie_tau_overlay",
        r"Aggressive attacker — $p_{\mathrm{lie}}$ sweep across targeting levels",
    )


def plot_parametric_plie():
    print("[overlay] parametric_plie_ptarget across tau multipliers")
    _plot_plie_tau_overlay(
        [
            ("parametric_plie_ptarget_x2tau.json",  r"$2\times\tau_{\mathrm{flag}}$",  BLUE),
            ("parametric_plie_ptarget_x5tau.json",  r"$5\times\tau_{\mathrm{flag}}$",  ORANGE),
            ("parametric_plie_ptarget_x10tau.json", r"$10\times\tau_{\mathrm{flag}}$", RED),
        ],
        "parametric_plie_tau_overlay",
        r"Parametric attacker — $p_{\mathrm{lie}}$ sweep across targeting levels",
    )


# --- parametric phase map (2D heatmaps) ---------------------------------------
def plot_parametric_phase_map():
    path = MAL / "parametric_phase_map.json"
    if not path.exists():
        print("  [skip] parametric_phase_map.json not found")
        return
    print("[phase] parametric_phase_map")
    data = load(path)

    plies    = sorted({round(d["Config"]["PLie"], 8) for d in data})
    ptargets = sorted({round(d["Config"]["Targeting"]["TargetFraction"], 10) for d in data})
    plie_idx   = {v: i for i, v in enumerate(plies)}
    ptarget_idx = {v: i for i, v in enumerate(ptargets)}
    shape = (len(plies), len(ptargets))

    def grid(key):
        g = np.full(shape, np.nan)
        for d in data:
            pi = round(d["Config"]["PLie"], 8)
            pt = round(d["Config"]["Targeting"]["TargetFraction"], 10)
            g[plie_idx[pi], ptarget_idx[pt]] = d[key]
        return g

    def fmt_ticks(vals, n=8):
        labels = []
        step = max(1, len(vals) // n)
        for i, v in enumerate(vals):
            if i % step == 0 or i == len(vals) - 1:
                labels.append(f"{v:.3g}")
            else:
                labels.append("")
        return labels

    x_ticks = fmt_ticks(ptargets)
    y_ticks = fmt_ticks(plies)

    metrics = [
        ("CaughtMaliciousRate",    "Caught-malicious rate",        "Reds",    0.0, 1.0),
        ("MissedRate",             "Missed rate",                  "Greens",  0.0, 1.0),
        ("CorrectDetectionRate",   "Correct detection rate",       "viridis", 0.0, 1.0),
        ("MisclassifiedIncompRate","Misclassified-incompetent rate","Oranges", 0.0, 1.0),
        ("SLABreachedRate",        "SLA-breached rate",            "Purples", 0.0, 1.0),
        ("MeanQueriesToVerdict",   "Mean queries to verdict",      "magma",   None, None),
        ("MeanPosteriorH2",        r"Mean $P(H_2)$ malicious",     "hot",     0.0, 1.0),
    ]

    for key, title, cmap, vmin, vmax in metrics:
        g = grid(key)
        fig, ax = plt.subplots(figsize=(8, 6.5))
        sns.heatmap(
            g, ax=ax,
            cmap=cmap, vmin=vmin, vmax=vmax,
            xticklabels=x_ticks, yticklabels=y_ticks,
            cbar_kws={"label": title},
            linewidths=0,
        )
        ax.invert_yaxis()
        ax.set_xlabel(r"Target fraction $p_{\mathrm{target}}$")
        ax.set_ylabel(r"Lie probability $p_{\mathrm{lie}}$")
        ax.set_title(f"Phase map: {title}")
        ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right")
        ax.set_yticklabels(ax.get_yticklabels(), rotation=0)
        safe = key.replace(" ", "_")
        save(fig, f"parametric_phase_map_{safe}.png")

    # contour of caught-malicious rate
    fig, ax = plt.subplots(figsize=(8, 6))
    g = grid("CaughtMaliciousRate")
    X, Y = np.meshgrid(np.array(ptargets), np.array(plies))
    cf = ax.contourf(X, Y, g, levels=np.linspace(0, 1, 21), cmap="Reds")
    cs = ax.contour(X, Y, g, levels=[0.5, 0.8, 0.9, 0.95, 0.99], colors="white", linewidths=0.8)
    ax.clabel(cs, inline=True, fontsize=8, fmt="%.2f")
    ax.set_xscale("log")
    ax.set_xlabel(r"Target fraction $p_{\mathrm{target}}$ (log)")
    ax.set_ylabel(r"Lie probability $p_{\mathrm{lie}}$")
    ax.set_title(r"Caught-malicious rate contour ($p_{\mathrm{target}}$ log scale)")
    fig.colorbar(cf, ax=ax, label="Caught-malicious rate")
    save(fig, "parametric_phase_map_contour_CaughtMaliciousRate.png")


# --- targeting modes comparison (bar chart) -----------------------------------
def plot_targeting_modes():
    path = MAL / "targeting_modes.json"
    if not path.exists():
        print("  [skip] targeting_modes.json not found")
        return
    print("[bars] targeting_modes")
    data = load(path)

    mode_names = {1: "Random", 2: "Periodic", 3: "Quota", 4: "All"}
    labels = [mode_names.get(d["Config"]["Targeting"]["Mode"], str(d["Config"]["Targeting"]["Mode"])) for d in data]

    # stacked bar of verdict rates
    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(data))
    bottom = np.zeros(len(data))
    for metric in STACK_METRICS:
        ys = extract(data, lambda d, m=metric: d[m])
        ax.bar(x, ys, bottom=bottom,
               label=VERDICT_LABELS[metric],
               color=VERDICT_COLORS[metric], alpha=0.85)
        bottom += ys
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("verdict rate")
    ax.set_ylim(0, 1)
    ax.set_title("Targeting modes — verdict distribution")
    ax.legend(fontsize=8, loc="upper right")
    save(fig, "targeting_modes_verdicts.png")

    # individual metric bars
    for metric in list(VERDICT_COLORS):
        ys = extract(data, lambda d, m=metric: d[m])
        fig, ax = plt.subplots(figsize=(6, 4.5))
        bars = ax.bar(x, ys, color=VERDICT_COLORS[metric], alpha=0.85)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylabel("rate")
        ax.set_ylim(0, max(ys.max() * 1.15, 0.05))
        ax.set_title(VERDICT_LABELS[metric], color=VERDICT_COLORS[metric])
        fig.suptitle("Targeting modes", y=1.02)
        save(fig, f"targeting_modes_{metric}.png")

    # queries bar
    fig, ax = plt.subplots(figsize=(7, 4.5))
    mean_q  = extract(data, lambda d: d["MeanQueriesToVerdict"])
    med_q   = extract(data, lambda d: d["MedianQueriesToVerdict"])
    width = 0.35
    ax.bar(x - width / 2, mean_q, width, label="mean",   color=BLUE, alpha=0.8)
    ax.bar(x + width / 2, med_q,  width, label="median", color=ORANGE, alpha=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("queries to verdict")
    ax.set_title("Targeting modes — queries to verdict")
    ax.legend(fontsize=9)
    save(fig, "targeting_modes_queries.png")

    # posteriors bar group
    for h_key, h_label, h_color in [
        ("MeanPosteriorH0", r"$\bar{P}(H_0)$ honest",      GREEN),
        ("MeanPosteriorH1", r"$\bar{P}(H_1)$ incompetent", ORANGE),
        ("MeanPosteriorH2", r"$\bar{P}(H_2)$ malicious",   RED),
    ]:
        ys = extract(data, lambda d, k=h_key: d[k])
        fig, ax = plt.subplots(figsize=(6, 4.5))
        ax.bar(x, ys, color=h_color, alpha=0.85)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.set_ylabel(h_label)
        ax.set_ylim(0, 1.05)
        ax.set_title(h_label, color=h_color)
        fig.suptitle("Targeting modes — terminal posteriors", y=1.02)
        safe = h_key.replace("MeanPosterior", "posterior_")
        save(fig, f"targeting_modes_{safe}.png")


# --- main ---------------------------------------------------------------------
def main():
    if not MAL.is_dir():
        raise SystemExit(f"No results in {MAL}. Run the simulation first.")
    print(f"Writing figures to {OUT.relative_to(HERE.parent)}/")

    plot_naive_liar()
    plot_silent_dropper()
    plot_smart_compliant()
    plot_smart_overshoot()
    plot_parametric_ptarget_vs_plie()
    plot_aggressive_plie()
    plot_parametric_plie()
    plot_parametric_phase_map()
    plot_targeting_modes()

    print("done.")


if __name__ == "__main__":
    main()
