"""Plot the honest-baseline sweeps produced by cmd/satnet.

Consumes the JSON files written under ``results/honest/`` and writes PNG
figures next to them. Each sweep has its own figure; panels use consistent
styling so they can drop straight into the evaluation chapter.
"""

import json
import os
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

HERE = Path(__file__).resolve().parent
HONEST = HERE / "honest"
sns.set_theme(style="whitegrid", context="paper")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def load(name: str):
    path = HONEST / name
    with open(path, "r") as f:
        return json.load(f)


def queries_arr(agg):
    """Per-trial queries-used, as a numpy array."""
    return np.array([t["QueriesUsed"] for t in agg["Trials"]], dtype=float)


def save(fig, name: str):
    out = HONEST / name
    fig.tight_layout()
    fig.savefig(out, dpi=200)
    plt.close(fig)
    print(f"  wrote {out.relative_to(HERE.parent)}")


# --------------------------------------------------------------------------- #
# η sweep — headline plot                                                     #
# --------------------------------------------------------------------------- #
def plot_eta():
    data = load("eta_sweep.json")
    etas = np.array([d["Config"]["Verification"]["ErrorTolerance"] for d in data])
    median = np.array([d["MedianQueriesToVerdict"] for d in data])
    mean = np.array([d["MeanQueriesToVerdict"] for d in data])
    p90 = np.array([d["P90QueriesToVerdict"] for d in data])
    qmin = np.array([d["MinQueriesToVerdict"] for d in data])
    qmax = np.array([d["MaxQueriesToVerdict"] for d in data])
    h0 = np.array([d["MeanPosteriorH0"] for d in data])
    alpha = data[0]["Config"]["Verification"]["ConfidenceThreshold"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))

    ax1.fill_between(etas, qmin, qmax, alpha=0.15, label="min–max")
    ax1.plot(etas, p90, marker="s", linestyle="--", label="P90")
    ax1.plot(etas, median, marker="o", label="median")
    ax1.plot(etas, mean, marker="^", linestyle=":", label="mean")
    ax1.set_xscale("log")
    ax1.set_xlabel(r"Error tolerance $\eta$")
    ax1.set_ylabel("Queries to TRUSTED verdict")
    ax1.set_title("Queries to verdict vs. $\\eta$")
    ax1.legend(frameon=True, fontsize=9)

    ax2.plot(etas, h0, marker="o", color="tab:green", label=r"mean $P(H_0\,|\,E)$")
    ax2.axhline(alpha, color="tab:red", linestyle="--", label=fr"$\alpha = {alpha:g}$")
    ax2.set_xscale("log")
    ax2.set_xlabel(r"Error tolerance $\eta$")
    ax2.set_ylabel(r"Mean $P(H_0\,|\,E)$ at termination")
    ax2.set_title(r"Honest posterior at termination")
    ax2.set_ylim(min(h0.min(), alpha) - 0.02, 1.005)
    ax2.legend(frameon=True, fontsize=9)

    fig.suptitle("Honest baseline — $\\eta$ sweep", fontsize=13)
    save(fig, "plot_eta_sweep.png")


# --------------------------------------------------------------------------- #
# α sweep — trade-off                                                          #
# --------------------------------------------------------------------------- #
def plot_alpha():
    data = load("alpha_sweep.json")
    alphas = np.array([d["Config"]["Verification"]["ConfidenceThreshold"] for d in data])
    median = np.array([d["MedianQueriesToVerdict"] for d in data])
    mean = np.array([d["MeanQueriesToVerdict"] for d in data])
    p90 = np.array([d["P90QueriesToVerdict"] for d in data])

    # Theoretical expectation: queries ~ log(α / (1 - α)) / log((1-ε) / η · (1-ε) / (1-η))
    eps = data[0]["Config"]["Verification"]["Epsilon"]
    eta = data[0]["Config"]["Verification"]["ErrorTolerance"]
    per_query_lr = np.log((1 - eps) ** 2) - np.log((1 - eta) * eta + eta * (1 - eta))
    # H0 vs H1 (and H2 by symmetry). Log-odds needed to exceed α: log(α / (1-α)).
    threshold_lr = np.log(alphas / (1 - alphas))
    predicted = np.ceil(threshold_lr / per_query_lr)

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.plot(alphas, median, marker="o", label="empirical median")
    ax.plot(alphas, p90, marker="s", linestyle="--", label="empirical P90")
    ax.plot(alphas, predicted, marker="x", linestyle=":", color="tab:grey",
            label="theoretical ceil")
    ax.set_xlabel(r"Confidence threshold $\alpha$")
    ax.set_ylabel("Queries to TRUSTED verdict")
    ax.set_title(fr"Honest baseline — $\alpha$ sweep  "
                 fr"($\eta = {eta:g}$, $\varepsilon = {eps:g}$)")
    # Use log(α/(1-α)) scale for x — makes scaling visible
    ax.set_xticks(alphas)
    ax.set_xticklabels([f"{a:g}" for a in alphas], rotation=20)
    ax.legend(frameon=True, fontsize=9)
    save(fig, "plot_alpha_sweep.png")


# --------------------------------------------------------------------------- #
# Batch-size sweep — sanity check on §4.1.1                                    #
# --------------------------------------------------------------------------- #
def plot_batch():
    data = load("batch_sweep.json")
    batches = np.array([d["Config"]["BatchSize"] for d in data])

    per_trial = [queries_arr(d) for d in data]
    median = np.array([np.median(q) for q in per_trial])
    p90 = np.array([np.percentile(q, 90) for q in per_trial])
    qmin = np.array([q.min() for q in per_trial])
    qmax = np.array([q.max() for q in per_trial])

    eta = data[0]["Config"]["Verification"]["ErrorTolerance"]
    alpha = data[0]["Config"]["Verification"]["ConfidenceThreshold"]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.fill_between(batches, qmin, qmax, alpha=0.15, label="min–max across trials")
    ax.plot(batches, p90, marker="s", linestyle="--", label="P90")
    ax.plot(batches, median, marker="o", label="median")
    ax.set_xscale("log")
    ax.set_xticks(batches)
    ax.set_xticklabels([str(b) for b in batches])
    ax.set_xlabel("Batch size $B$")
    ax.set_ylabel("Queries to TRUSTED verdict")
    ax.set_title(fr"Honest baseline — batch-size sweep  "
                 fr"($\eta = {eta:g}$, $\alpha = {alpha:g}$)")
    ax.legend(frameon=True, fontsize=9)
    save(fig, "plot_batch_sweep.png")


# --------------------------------------------------------------------------- #
# Trial-length sweep at strict α — the INCONCLUSIVE crossover                 #
# --------------------------------------------------------------------------- #
def plot_numpackets():
    data = load("numpackets_sweep_strict.json")
    ns = np.array([d["Config"]["NumPackets"] for d in data])
    batch = data[0]["Config"]["BatchSize"]
    alpha = data[0]["Config"]["Verification"]["ConfidenceThreshold"]
    eta = data[0]["Config"]["Verification"]["ErrorTolerance"]

    batches_available = ns // batch
    trusted = np.array([d["TrustedRate"] for d in data])
    inconclusive = np.array([d["InconclusiveRate"] for d in data])
    dishonest = np.array([d["FalseDishonestRate"] for d in data])
    median_q = np.array([d["MedianQueriesToVerdict"] for d in data])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))

    ax1.plot(batches_available, trusted, marker="o", color="tab:green", label="TRUSTED")
    ax1.plot(batches_available, inconclusive, marker="s", color="tab:orange",
             label="INCONCLUSIVE")
    ax1.plot(batches_available, dishonest, marker="x", color="tab:red", label="DISHONEST")
    ax1.set_xscale("log")
    ax1.set_xticks(batches_available)
    ax1.set_xticklabels([str(b) for b in batches_available])
    ax1.set_xlabel("Batches available per trial")
    ax1.set_ylabel("Verdict rate")
    ax1.set_ylim(-0.05, 1.05)
    ax1.set_title("Verdict distribution")
    ax1.legend(frameon=True, fontsize=9)

    ax2.plot(batches_available, median_q, marker="o")
    ax2.set_xscale("log")
    ax2.set_xticks(batches_available)
    ax2.set_xticklabels([str(b) for b in batches_available])
    ax2.set_xlabel("Batches available per trial")
    ax2.set_ylabel("Median queries to verdict")
    ax2.set_title("Queries to TRUSTED (when reached)")

    fig.suptitle(fr"Honest baseline — strict $\alpha = {alpha:g}$  "
                 fr"($\eta = {eta:g}$, $B = {batch}$)", fontsize=12)
    save(fig, "plot_numpackets_sweep.png")


# --------------------------------------------------------------------------- #
# Sanity: λ (base-delay transition rate) and ε (noise floor)                   #
# --------------------------------------------------------------------------- #
def plot_invariance(path: str, param_path: list[str], label: str, fname: str,
                    log_x: bool = True):
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

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    ax1.plot(xs, median, marker="o", label="median")
    ax1.plot(xs, mean, marker="^", linestyle=":", label="mean")
    if log_x and (xs > 0).all():
        ax1.set_xscale("log")
    ax1.set_xlabel(label)
    ax1.set_ylabel("Queries to TRUSTED verdict")
    ax1.set_title("Queries (expected: flat)")
    ax1.legend(frameon=True, fontsize=9)

    ax2.plot(xs, h0, marker="o", color="tab:green")
    if log_x and (xs > 0).all():
        ax2.set_xscale("log")
    ax2.set_xlabel(label)
    ax2.set_ylabel(r"Mean $P(H_0\,|\,E)$ at termination")
    ax2.set_title("Posterior (expected: flat)")

    fig.suptitle(f"Honest baseline — {label} sweep (sanity check)", fontsize=12)
    save(fig, fname)


# --------------------------------------------------------------------------- #
def main():
    if not HONEST.is_dir():
        raise SystemExit(
            f"No honest-baseline results in {HONEST}. "
            f"Run `go run ./cmd/satnet` first."
        )

    print(f"Writing figures to {HONEST.relative_to(HERE.parent)}/")
    plot_eta()
    plot_alpha()
    plot_batch()
    plot_numpackets()

    # λ is a mix of zero and positive values, so we pass log_x=False so the
    # 0.0 point isn't dropped.
    plot_invariance(
        "lambda_sweep.json",
        ["DelayModel", "TransitionRate"],
        r"Base-delay transition rate $\lambda$",
        "plot_lambda_sweep.png",
        log_x=False,
    )
    plot_invariance(
        "epsilon_sweep.json",
        ["Verification", "Epsilon"],
        r"Noise floor $\varepsilon$",
        "plot_epsilon_sweep.png",
        log_x=True,
    )


if __name__ == "__main__":
    main()
