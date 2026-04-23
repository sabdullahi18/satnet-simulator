"""Plot the honest-baseline sweeps produced by cmd/satnet.

Each plot is now saved as an individual PNG file under results/honest/.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

HERE = Path(__file__).resolve().parent
HONEST = HERE / "honest"
sns.set_theme(style="whitegrid", context="paper")

GREY = "#6e6e6e"
BLUE = "#1f77b4"
ORANGE = "#ff7f0e"
GREEN = "#2ca02c"
RED = "#d62728"


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def load(name: str):
    with open(HONEST / name, "r") as f:
        return json.load(f)


def save(fig, name: str):
    fig.tight_layout()
    fig.savefig(HONEST / name, dpi=200)
    plt.close(fig)
    print(f"  wrote {(HONEST / name).relative_to(HERE.parent)}")


def n_min_analytical(eta, alpha, eps):
    """Closed-form queries-to-verdict. Returns (continuous, ceiling)."""
    alpha = np.clip(alpha, None, 1.0 - 1e-15)
    r = eta * (1.0 - eta) / (1.0 - eps) ** 2
    continuous = np.log(2.0 * alpha / (1.0 - alpha)) / np.log(1.0 / r)
    return continuous, np.ceil(continuous)


def posterior_at(eta, eps, n):
    """Terminal P(H0 | n clean queries)."""
    r = eta * (1.0 - eta) / (1.0 - eps) ** 2
    return 1.0 / (1.0 + 2.0 * r**n)


# --------------------------------------------------------------------------- #
# η sweep                                                                     #
# --------------------------------------------------------------------------- #
def plot_eta(fname="eta_sweep.json", out_base="plot_eta_sweep", title_suffix=""):
    data = load(fname)
    etas = np.array([d["Config"]["Verification"]["ErrorTolerance"] for d in data])
    median = np.array([d["MedianQueriesToVerdict"] for d in data])
    h0 = np.array([d["MeanPosteriorH0"] for d in data])
    eps = data[0]["Config"]["Verification"]["Epsilon"]
    alpha = data[0]["Config"]["Verification"]["ConfidenceThreshold"]

    eta_dense = np.logspace(np.log10(etas.min()), np.log10(etas.max()), 600)
    n_cont, n_ceil = n_min_analytical(eta_dense, alpha, eps)
    h0_theory = posterior_at(eta_dense, eps, n_ceil)

    suffix = f" ({title_suffix})" if title_suffix else ""

    # --- Plot 1: Queries -------------------------------------------------- #
    fig1, ax1 = plt.subplots(figsize=(6, 4.5))
    ax1.plot(
        eta_dense, n_cont, color=GREY, linewidth=1.4, label="continuous prediction"
    )
    ax1.plot(
        eta_dense,
        n_ceil,
        color=BLUE,
        linestyle="--",
        linewidth=1.2,
        alpha=0.75,
        label=r"$\lceil \cdot \rceil$",
    )
    ax1.plot(
        etas,
        median,
        "o",
        color=ORANGE,
        markersize=5,
        markeredgecolor="white",
        label="empirical median",
    )
    ax1.set_xscale("log")
    ax1.set_xlabel(r"Error tolerance $\eta$")
    ax1.set_ylabel("Queries to TRUSTED verdict")
    ax1.set_title(f"Queries to verdict vs. $\\eta${suffix}")
    ax1.legend(frameon=True, fontsize=9, loc="upper left")
    save(fig1, f"{out_base}_queries.png")

    # --- Plot 2: Residual Mass -------------------------------------------- #
    fig2, ax2 = plt.subplots(figsize=(6, 4.5))
    ax2.plot(eta_dense, 1.0 - h0_theory, color=GREY, linewidth=1.4, label="analytical")
    ax2.plot(
        etas,
        1.0 - h0,
        "o",
        color=GREEN,
        markersize=5,
        markeredgecolor="white",
        label="empirical",
    )
    ax2.axhline(
        1.0 - alpha, color=RED, linestyle="--", linewidth=1.0, label=r"$1 - \alpha$"
    )
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.invert_yaxis()
    ax2.set_xlabel(r"Error tolerance $\eta$")
    ax2.set_ylabel(r"$1 - P(H_0 \mid E)$ at termination")
    ax2.set_title(f"Residual mass on non-honest hypotheses{suffix}")
    ax2.legend(frameon=True, fontsize=9, loc="lower left")
    save(fig2, f"{out_base}_residual.png")


# --------------------------------------------------------------------------- #
# α sweep                                                                     #
# --------------------------------------------------------------------------- #
def plot_alpha(fname="alpha_sweep.json", out="plot_alpha_sweep.png", title_suffix=""):
    data = load(fname)
    alphas = np.array(
        [d["Config"]["Verification"]["ConfidenceThreshold"] for d in data]
    )
    median = np.array([d["MedianQueriesToVerdict"] for d in data])
    eps = data[0]["Config"]["Verification"]["Epsilon"]
    eta = data[0]["Config"]["Verification"]["ErrorTolerance"]

    one_minus = 1.0 - alphas
    om_dense = np.logspace(np.log10(one_minus.min()), np.log10(one_minus.max()), 600)
    alpha_dense = 1.0 - om_dense
    n_cont, n_ceil = n_min_analytical(eta, alpha_dense, eps)

    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.plot(om_dense, n_cont, color=GREY, linewidth=1.4, label="continuous prediction")
    ax.plot(
        om_dense,
        n_ceil,
        color=BLUE,
        linestyle="--",
        linewidth=1.2,
        alpha=0.75,
        label=r"$\lceil \cdot \rceil$",
    )
    ax.plot(
        one_minus,
        median,
        "o",
        color=ORANGE,
        markersize=5,
        markeredgecolor="white",
        label="empirical median",
    )
    ax.set_xscale("log")
    ax.invert_xaxis()
    ax.set_xlabel(r"$1 - \alpha$  (stricter $\rightarrow$)")
    ax.set_ylabel("Queries to TRUSTED verdict")
    title = (
        rf"Honest baseline — $\alpha$ sweep ($\eta = {eta:g}, \varepsilon = {eps:g}$)"
    )
    if title_suffix:
        title += f" ({title_suffix})"
    ax.set_title(title)
    ax.legend(frameon=True, fontsize=9, loc="upper right")
    save(fig, out)


# --------------------------------------------------------------------------- #
# NumPackets sweep                                                            #
# --------------------------------------------------------------------------- #
def plot_numpackets():
    data = load("numpackets_sweep_strict.json")
    ns = np.array([d["Config"]["NumPackets"] for d in data])
    batch = data[0]["Config"]["BatchSize"]
    alpha = data[0]["Config"]["Verification"]["ConfidenceThreshold"]
    eta = data[0]["Config"]["Verification"]["ErrorTolerance"]
    eps = data[0]["Config"]["Verification"]["Epsilon"]

    batches_available = ns // batch
    trusted = np.array([d["TrustedRate"] for d in data])
    inconclusive = np.array([d["InconclusiveRate"] for d in data])
    dishonest = np.array([d["FalseDishonestRate"] for d in data])
    median_q = np.array([d["MedianQueriesToVerdict"] for d in data])
    _, n_ceil = n_min_analytical(eta, alpha, eps)
    n_needed = int(n_ceil)

    # --- Plot 1: Verdict distribution ------------------------------------- #
    fig1, ax1 = plt.subplots(figsize=(6, 4.5))
    ax1.plot(batches_available, trusted, "o-", color=GREEN, label="TRUSTED")
    ax1.plot(batches_available, inconclusive, "s-", color=ORANGE, label="INCONCLUSIVE")
    ax1.plot(batches_available, dishonest, "x-", color=RED, label="DISHONEST")
    ax1.axvline(
        n_needed,
        color=GREY,
        linestyle="--",
        alpha=0.8,
        label=rf"$n_{{\min}} = {n_needed}$",
    )
    ax1.set_xscale("log")
    ax1.set_xlabel("Batches available per trial")
    ax1.set_ylabel("Verdict rate")
    ax1.set_ylim(-0.05, 1.05)
    ax1.set_title("Verdict distribution")
    ax1.legend(frameon=True, fontsize=9)
    save(fig1, "plot_numpackets_verdicts.png")

    # --- Plot 2: Queries used --------------------------------------------- #
    fig2, ax2 = plt.subplots(figsize=(6, 4.5))
    ax2.plot(
        batches_available,
        median_q,
        "o-",
        color=ORANGE,
        markersize=5,
        label="empirical median",
    )
    ax2.axhline(
        n_needed,
        color=GREY,
        linestyle="--",
        alpha=0.8,
        label=rf"$n_{{\min}} = {n_needed}$",
    )
    ax2.set_xscale("log")
    ax2.set_xlabel("Batches available per trial")
    ax2.set_ylabel("Median queries to verdict")
    ax2.set_title("Queries to TRUSTED (when reached)")
    ax2.legend(frameon=True, fontsize=9)
    save(fig2, "plot_numpackets_queries.png")


# --------------------------------------------------------------------------- #
# Appendix: λ and ε sanity sweeps                                             #
# --------------------------------------------------------------------------- #
def plot_invariance(
    path: str, param_path: list, label: str, fname_base: str, log_x=True
):
    data = load(path)

    def getcfg(d):
        v = d["Config"]
        for k in param_path:
            v = v[k]
        return v

    xs = np.array([getcfg(d) for d in data])
    median = np.array([d["MedianQueriesToVerdict"] for d in data])
    mean = np.array([d["MeanQueriesToVerdict"] for d in data])
    h0 = np.array([d["MeanPosteriorH0"] for d in data])
    out_stem = Path(fname_base).stem

    # --- Plot 1: Queries -------------------------------------------------- #
    fig1, ax1 = plt.subplots(figsize=(6, 4.5))
    ax1.plot(xs, median, marker="o", label="median")
    ax1.plot(xs, mean, marker="^", linestyle=":", label="mean")
    if log_x and (xs > 0).all():
        ax1.set_xscale("log")
    ax1.set_xlabel(label)
    ax1.set_ylabel("Queries to TRUSTED verdict")
    ax1.set_title(f"{label} Sweep — Queries (expected flat)")
    ax1.legend(frameon=True, fontsize=9)
    save(fig1, f"{out_stem}_queries.png")

    # --- Plot 2: Posterior ------------------------------------------------ #
    fig2, ax2 = plt.subplots(figsize=(6, 4.5))
    ax2.plot(xs, h0, marker="o", color=GREEN)
    if log_x and (xs > 0).all():
        ax2.set_xscale("log")
    ax2.set_xlabel(label)
    ax2.set_ylabel(r"Mean $P(H_0\,|\,E)$ at termination")
    ax2.set_title(f"{label} Sweep — Posterior (expected flat)")
    save(fig2, f"{out_stem}_posterior.png")


# --------------------------------------------------------------------------- #
def main():
    if not HONEST.is_dir():
        raise SystemExit(f"No results in {HONEST}. Run the simulation first.")

    print(f"Writing figures to {HONEST.relative_to(HERE.parent)}/")

    # Core sweeps
    plot_eta("eta_sweep.json", "plot_eta_sweep")
    plot_alpha("alpha_sweep.json", "plot_alpha_sweep.png")
    plot_numpackets()

    # Deep sweeps
    if (HONEST / "eta_sweep_strict.json").exists():
        plot_eta(
            "eta_sweep_strict.json",
            "plot_eta_sweep_strict",
            title_suffix=r"strict $\alpha$",
        )
    if (HONEST / "alpha_sweep_large_eta.json").exists():
        plot_alpha(
            "alpha_sweep_large_eta.json",
            "plot_alpha_sweep_large_eta.png",
            title_suffix=r"large $\eta$",
        )

    # Sanity checks
    plot_invariance(
        "lambda_sweep.json",
        ["DelayModel", "TransitionRate"],
        r"$\lambda$",
        "plot_lambda_sweep.png",
        log_x=False,
    )
    plot_invariance(
        "epsilon_sweep.json",
        ["Verification", "Epsilon"],
        r"$\varepsilon$",
        "plot_epsilon_sweep.png",
    )
    plot_invariance(
        "batch_sweep.json", ["BatchSize"], "Batch size $B$", "plot_batch_sweep.png"
    )


if __name__ == "__main__":
    main()
