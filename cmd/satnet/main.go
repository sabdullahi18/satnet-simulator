package main

import (
	"fmt"
	"math"

	"satnet-simulator/internal/experiment"
)

// logspace returns n log-spaced values between lo and hi (inclusive).
func logspace(lo, hi float64, n int) []float64 {
	if n < 2 {
		return []float64{lo}
	}
	out := make([]float64, n)
	logLo, logHi := math.Log(lo), math.Log(hi)
	for i := 0; i < n; i++ {
		t := float64(i) / float64(n-1)
		out[i] = math.Exp(logLo + t*(logHi-logLo))
	}
	return out
}

// alphaLogspace returns n values of α such that (1 - α) is log-spaced between
// oneMinusLo and oneMinusHi. Use this so that α = 0.5 and α = 1 - 1e-10 both
// appear on the sweep without the large-α region being compressed.
func alphaLogspace(oneMinusHi, oneMinusLo float64, n int) []float64 {
	// oneMinusHi is larger (loose α), oneMinusLo is smaller (tight α).
	raw := logspace(oneMinusHi, oneMinusLo, n)
	alphas := make([]float64, len(raw))
	for i, v := range raw {
		alphas[i] = 1 - v
	}
	return alphas
}

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     SATNET SIMULATOR - Honest Baseline Evaluation")
	fmt.Println("================================================================================")

	runner := experiment.NewRunner()

	// Shared base config. Because every honest trial is deterministic in its
	// evidence stream, NumTrials could safely be dropped to ~20 without
	// changing any reported value; 200 is kept here only so that the JSON
	// files carry enough per-trial records for later cross-checks.
	base := experiment.DefaultHonestBaseline()
	base.NumTrials = 5
	base.NumPackets = 2000
	base.BatchSize = 10
	base.SimDuration = 1000.0

	// ------------------------------------------------------------------
	// η sweep (default α = 0.99). Dense log-spaced grid from 1e-3 to 0.49
	// so the step locations of n_min(η) are resolved precisely.
	// ------------------------------------------------------------------
	etas := logspace(1e-3, 0.49, 40)
	etaResults := runner.SweepHonestEta(base, etas)
	if err := runner.SaveAggregates("results/honest/eta_sweep.json", etaResults); err != nil {
		fmt.Printf("warning: could not save η sweep: %v\n", err)
	}

	// ------------------------------------------------------------------
	// η sweep at strict α = 1 - 1e-9. Same grid; n_min ranges ~4..16,
	// which is the range that gets used against careful adversaries in
	// later evaluation sections. NumPackets bumped so there are enough
	// batches (≥ 16) available even when n_min is large.
	// ------------------------------------------------------------------
	etaStrict := base
	etaStrict.Verification.ConfidenceThreshold = 1 - 1e-9
	etaStrict.NumPackets = 5000 // 500 batches available
	etaStrictResults := runner.SweepHonestEta(etaStrict, etas)
	if err := runner.SaveAggregates("results/honest/eta_sweep_strict.json", etaStrictResults); err != nil {
		fmt.Printf("warning: could not save strict η sweep: %v\n", err)
	}

	// ------------------------------------------------------------------
	// α sweep. Log-spaced in (1 - α) from 0.5 down to 1e-10, which covers
	// 10 orders of magnitude of confidence on a single axis.
	// ------------------------------------------------------------------
	alphas := alphaLogspace(0.5, 1e-10, 20)
	alphaResults := runner.SweepHonestAlpha(base, alphas)
	if err := runner.SaveAggregates("results/honest/alpha_sweep.json", alphaResults); err != nil {
		fmt.Printf("warning: could not save α sweep: %v\n", err)
	}

	// α sweep at larger η = 0.3. Each α value requires more queries, so the
	// log-linear relationship n_min ~ log(2α/(1-α)) becomes clearly visible
	// without running out of integer resolution.
	alphaLargeEta := base
	alphaLargeEta.Verification.ErrorTolerance = 0.3
	alphaLargeEta.NumPackets = 5000
	alphaLargeEtaResults := runner.SweepHonestAlpha(alphaLargeEta, alphas)
	if err := runner.SaveAggregates("results/honest/alpha_sweep_large_eta.json", alphaLargeEtaResults); err != nil {
		fmt.Printf("warning: could not save α sweep (large η): %v\n", err)
	}

	// ------------------------------------------------------------------
	// Batch availability at strict α = 0.9999. Dense values around the
	// starvation frontier so the INCONCLUSIVE → TRUSTED transition is
	// resolved at batch-count granularity.
	// ------------------------------------------------------------------
	strict := base
	strict.Verification.ConfidenceThreshold = 0.9999
	pkts := []int{20, 30, 40, 50, 60, 70, 80, 90, 100, 120, 150, 200, 300, 500, 1000, 2000}
	pktResults := runner.SweepHonestNumPackets(strict, pkts)
	if err := runner.SaveAggregates("results/honest/numpackets_sweep_strict.json", pktResults); err != nil {
		fmt.Printf("warning: could not save trial-length sweep: %v\n", err)
	}

	// ------------------------------------------------------------------
	// Appendix sweeps. These are flat by construction under H0; the runs
	// exist to demonstrate that flatness, not to characterise anything.
	// ------------------------------------------------------------------
	batches := []int{2, 5, 10, 25, 50, 100}
	batchResults := runner.SweepHonestBatch(base, batches)
	if err := runner.SaveAggregates("results/honest/batch_sweep.json", batchResults); err != nil {
		fmt.Printf("warning: could not save batch sweep: %v\n", err)
	}

	lambdas := []float64{0.0, 0.01, 0.05, 0.1, 0.5, 1.0}
	lambdaResults := runner.SweepHonestTransitionRate(base, lambdas)
	if err := runner.SaveAggregates("results/honest/lambda_sweep.json", lambdaResults); err != nil {
		fmt.Printf("warning: could not save λ sweep: %v\n", err)
	}

	epsilons := logspace(1e-6, 1e-2, 12)
	epsResults := runner.SweepHonestEpsilon(base, epsilons)
	if err := runner.SaveAggregates("results/honest/epsilon_sweep.json", epsResults); err != nil {
		fmt.Printf("warning: could not save ε sweep: %v\n", err)
	}

	runner.PrintSummary()
}
