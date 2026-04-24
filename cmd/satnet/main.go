package main

import (
	"flag"
	"fmt"
	"math"
	"time"

	"satnet-simulator/internal/experiment"
	"satnet-simulator/internal/verification"
)

// logspace returns n log-spaced values between lo and hi (inclusive).
func logspace(lo, hi float64, n int) []float64 {
	if n < 2 {
		return []float64{lo}
	}
	out := make([]float64, n)
	logLo, logHi := math.Log(lo), math.Log(hi)
	for i := range n {
		t := float64(i) / float64(n-1)
		out[i] = math.Exp(logLo + t*(logHi-logLo))
	}
	return out
}

// linspace returns n linearly-spaced values between lo and hi (inclusive).
func linspace(lo, hi float64, n int) []float64 {
	if n < 2 {
		return []float64{lo}
	}
	out := make([]float64, n)
	for i := range n {
		t := float64(i) / float64(n-1)
		out[i] = lo + t*(hi-lo)
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

func resolveBaseSeed() int64 {
	seed := flag.Int64("seed", 0, "base RNG seed; if omitted, current time is used")
	flag.Parse()
	if *seed != 0 {
		return *seed
	}
	return time.Now().UnixNano()
}

func main() {
	baseSeed := resolveBaseSeed()

	fmt.Println("================================================================================")
	fmt.Println("     SATNET SIMULATOR - Honest Baseline Evaluation")
	fmt.Println("================================================================================")
	fmt.Printf("     RNG base seed: %d\n", baseSeed)
	fmt.Println("     (trial streams are derived per config and trial index)")

	runner := experiment.NewRunner()
	runner.SetBaseSeed(baseSeed)

	// Honest baseline block — outputs already persisted to
	// results/honest/*.json in a prior invocation. Re-enable by setting
	// runHonest to true if the honest results need to be regenerated.
	const runHonest = false
	if runHonest {
		base := experiment.DefaultHonestBaseline()
		base.NumTrials = 5
		base.NumPackets = 2000
		base.BatchSize = 10
		base.SimDuration = 1000.0

		etas := logspace(1e-3, 0.49, 40)
		etaResults := runner.SweepHonestEta(base, etas)
		if err := runner.SaveAggregates("results/honest/eta_sweep.json", etaResults); err != nil {
			fmt.Printf("warning: could not save η sweep: %v\n", err)
		}

		etaStrict := base
		etaStrict.Verification.ConfidenceThreshold = 1 - 1e-9
		etaStrict.NumPackets = 5000
		etaStrictResults := runner.SweepHonestEta(etaStrict, etas)
		if err := runner.SaveAggregates("results/honest/eta_sweep_strict.json", etaStrictResults); err != nil {
			fmt.Printf("warning: could not save strict η sweep: %v\n", err)
		}

		alphas := alphaLogspace(0.5, 1e-10, 20)
		alphaResults := runner.SweepHonestAlpha(base, alphas)
		if err := runner.SaveAggregates("results/honest/alpha_sweep.json", alphaResults); err != nil {
			fmt.Printf("warning: could not save α sweep: %v\n", err)
		}

		alphaLargeEta := base
		alphaLargeEta.Verification.ErrorTolerance = 0.3
		alphaLargeEta.NumPackets = 5000
		alphaLargeEtaResults := runner.SweepHonestAlpha(alphaLargeEta, alphas)
		if err := runner.SaveAggregates("results/honest/alpha_sweep_large_eta.json", alphaLargeEtaResults); err != nil {
			fmt.Printf("warning: could not save α sweep (large η): %v\n", err)
		}

		strict := base
		strict.Verification.ConfidenceThreshold = 0.9999
		pkts := []int{20, 30, 40, 50, 60, 70, 80, 90, 100, 120, 150, 200, 300, 500, 1000, 2000}
		pktResults := runner.SweepHonestNumPackets(strict, pkts)
		if err := runner.SaveAggregates("results/honest/numpackets_sweep_strict.json", pktResults); err != nil {
			fmt.Printf("warning: could not save trial-length sweep: %v\n", err)
		}

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
	} else {
		fmt.Println("     (skipping honest baseline — already persisted)")
	}

	// ================================================================
	//     Incompetent-network evaluation
	// ================================================================
	fmt.Println("\n================================================================================")
	fmt.Println("     SATNET SIMULATOR - Incompetent Network Evaluation")
	fmt.Println("================================================================================")

	// Shared base config for incompetent sweeps. NumTrials is deliberately
	// larger than the honest case because incompetent trials are stochastic:
	// each trial samples independent congestion events and independent
	// flag/answer bernoullis, so smooth rate curves need the extra samples.
	baseI := experiment.DefaultIncompetentBaseline()
	baseI.NumTrials = 200
	baseI.NumPackets = 2000
	baseI.BatchSize = 10
	baseI.SimDuration = 1000.0

	// Sweeps 1–5 run for each seed so results can be plotted as families of
	// curves. Sweeps 6–12 are one-off diagnostics and remain seed-agnostic.
	const runSweep1_pIncomp = false
	const runSweep2_flagRel = false
	const runSweep3_ansErr = false
	const runSweep4_eta = false
	const runSweep5_alpha = false
	const runSweep6_numPackets = false
	const runSweep7_batchSize = false
	const runSweep11_queriesPerBatch = false
	const runSweep12_pincompFlagRelPhaseMap = false
	const runSweep8_magnitude = false
	const runSweep9_tauFlag = false
	const runSweep10_flagRelLowPIncomp = true

	// Each seed produces an independent set of sweep results under
	// results/incompetent/seed_<N>/. The base seed from the CLI flag is used
	// as the first entry so a single-seed run still picks up -seed overrides.
	incompetentSeeds := []int64{baseSeed, 2, 3, 4, 5}

	flagRels := linspace(0.0, 1.0, 40)

	for _, seed := range incompetentSeeds {
		seedDir := fmt.Sprintf("results/incompetent/seed_%d", seed)
		fmt.Printf("\n--- seed %d ---\n", seed)
		runner.SetBaseSeed(seed)

		if runSweep1_pIncomp {
			// Incompetence rate p_incomp. How rare can congestion events be
			// before the verifier misses them? At p_incomp near 0 the network
			// is effectively honest; somewhere along the sweep the probability
			// of querying at least one congested packet in the first
			// n_min clean queries crosses 50% and detection takes off.
			pIncompSweep := logspace(1e-4, 0.3, 40)
			r1 := runner.SweepIncompetenceRate(baseI, pIncompSweep)
			if err := runner.SaveIncompetentAggregates(seedDir+"/incompetence_rate_sweep.json", r1); err != nil {
				fmt.Printf("warning: could not save p_incomp sweep: %v\n", err)
			}
		}

		if runSweep2_flagRel {
			// Flag reliability. 1.0 is indistinguishable from honest; 0.0 is
			// the classical incompetent SNP (never flags). Fixed at
			// p_incomp = 0.10 so the signal is always present.
			flagRelBase := baseI
			flagRelBase.DelayModel.IncompetenceRate = 0.10
			r2 := runner.SweepFlagReliability(flagRelBase, flagRels)
			if err := runner.SaveIncompetentAggregates(seedDir+"/flag_reliability_sweep.json", r2); err != nil {
				fmt.Printf("warning: could not save flag-reliability sweep: %v\n", err)
			}
		}

		if runSweep3_ansErr {
			// Answer error rate (AnswerUnreliable). Bookkeeping errors produce
			// contradictions, which are the H2 signature. Isolates the H1→H2
			// misclassification boundary.
			ansBase := baseI
			ansBase.DelayModel.IncompetenceRate = 0.10
			ansBase.AnsweringStrategy = verification.AnswerUnreliable
			ansErrs := linspace(0.0, 0.5, 40)
			r3 := runner.SweepAnswerErrorRate(ansBase, ansErrs)
			if err := runner.SaveIncompetentAggregates(seedDir+"/answer_error_sweep.json", r3); err != nil {
				fmt.Printf("warning: could not save answer-error sweep: %v\n", err)
			}
		}

		if runSweep4_eta {
			// η sweep mirroring the honest η sweep.
			etaI := logspace(1e-3, 0.49, 40)
			r4 := runner.SweepIncompetentEta(baseI, etaI)
			if err := runner.SaveIncompetentAggregates(seedDir+"/eta_sweep.json", r4); err != nil {
				fmt.Printf("warning: could not save η sweep (incompetent): %v\n", err)
			}
		}

		if runSweep5_alpha {
			// α sweep mirroring the honest α sweep.
			alphaI := alphaLogspace(0.5, 1e-10, 20)
			r5 := runner.SweepIncompetentAlpha(baseI, alphaI)
			if err := runner.SaveIncompetentAggregates(seedDir+"/alpha_sweep.json", r5); err != nil {
				fmt.Printf("warning: could not save α sweep (incompetent): %v\n", err)
			}
		}
	}

	if runSweep6_numPackets {
		// ------------------------------------------------------------------
		// 6. Batch availability (NumPackets). At default α the verifier stops
		//    after ~2 clean queries, so more batches cannot help — the sweep
		//    is only informative under a stricter α that forces n_min to grow.
		//    Using α = 1−1e−6 and η = 0.3 gives n_min ≈ 10, so a customer that
		//    hands over at least n_min batches gets a verdict; below that the
		//    trial terminates INCONCLUSIVE, and the rate at which DISHONEST
		//    appears above n_min is set by p_incomp.
		// ------------------------------------------------------------------
		sparseI := baseI
		sparseI.DelayModel.IncompetenceRate = 0.02
		sparseI.NumTrials = 60
		sparseI.Verification.ConfidenceThreshold = 1 - 1e-6
		sparseI.Verification.ErrorTolerance = 0.3
		sparsePkts := []int{20, 30, 40, 50, 60, 70, 80, 90, 100, 120, 150, 200, 300, 500, 1000, 2000, 5000, 10000}
		r6 := runner.SweepIncompetentNumPackets(sparseI, sparsePkts)
		if err := runner.SaveIncompetentAggregates("results/incompetent/numpackets_sweep.json", r6); err != nil {
			fmt.Printf("warning: could not save NumPackets sweep (incompetent): %v\n", err)
		}
	}

	if runSweep7_batchSize {
		// ------------------------------------------------------------------
		// 7. Batch size B. Keeps total packet count constant so the sweep
		//    isolates the effect of per-batch composition on detection.
		// ------------------------------------------------------------------
		batchBase := baseI
		batchBase.DelayModel.IncompetenceRate = 0.05
		batchesI := []int{2, 3, 4, 5, 8, 10, 15, 20, 30, 50, 75, 100}
		r7 := runner.SweepIncompetentBatchSize(batchBase, batchesI)
		if err := runner.SaveIncompetentAggregates("results/incompetent/batch_size_sweep.json", r7); err != nil {
			fmt.Printf("warning: could not save batch-size sweep (incompetent): %v\n", err)
		}
	}

	if runSweep11_queriesPerBatch {
		// ------------------------------------------------------------------
		// 11. Queries per batch (audit aggressiveness). With larger QPB the
		// verifier probes more packets from each batch, which can reduce the
		// time to catch hidden incompetence signals.
		// ------------------------------------------------------------------
		qpbBase := baseI
		qpbBase.DelayModel.IncompetenceRate = 0.05
		qpbs := []int{1, 2, 3, 4, 5, 8, 10}
		r11 := runner.SweepIncompetentQueriesPerBatch(qpbBase, qpbs)
		if err := runner.SaveIncompetentAggregates("results/incompetent/queries_per_batch_sweep.json", r11); err != nil {
			fmt.Printf("warning: could not save queries-per-batch sweep (incompetent): %v\n", err)
		}
	}

	if runSweep12_pincompFlagRelPhaseMap {
		// ------------------------------------------------------------------
		// 12. 2D phase map over p_incomp x flag reliability. This maps
		// operating regimes where incompetence is mostly trusted, caught via
		// H1/H2 posteriors, or caught by SLA breach.
		// ------------------------------------------------------------------
		phaseBase := baseI
		phaseBase.NumTrials = 80 // Keep runtime manageable for the 2D grid.
		phasePincomp := logspace(1e-4, 0.3, 16)
		phaseFlagRel := linspace(0.0, 1.0, 16)
		r12 := runner.SweepIncompetentPhaseMap(phaseBase, phasePincomp, phaseFlagRel)
		if err := runner.SaveIncompetentAggregates("results/incompetent/pincomp_flagrel_phase_map.json", r12); err != nil {
			fmt.Printf("warning: could not save p_incomp x flag-reliability phase map: %v\n", err)
		}
	}

	if runSweep8_magnitude {
		// ------------------------------------------------------------------
		// 8. Incompetence-delay magnitude (µ). The verifier uses batch
		//    ordering, not magnitude, so this sweep is expected to be flat.
		//    Running it verifies that design property empirically.
		// ------------------------------------------------------------------
		muBase := baseI
		muBase.DelayModel.IncompetenceRate = 0.05
		mus := linspace(math.Log(1e-4), math.Log(0.1), 20)
		r8 := runner.SweepIncompetenceMagnitude(muBase, mus)
		if err := runner.SaveIncompetentAggregates("results/incompetent/magnitude_sweep.json", r8); err != nil {
			fmt.Printf("warning: could not save magnitude sweep (incompetent): %v\n", err)
		}
	}

	if runSweep9_tauFlag {
		// ------------------------------------------------------------------
		// 9. SLA flagging threshold τ_flag. A loose τ_flag allows more hidden
		//    admissions before triggering an SLA breach; a tight τ_flag catches
		//    incompetence via the contract check rather than the Bayesian
		//    posterior. This sweep shows which detector is doing the work.
		// ------------------------------------------------------------------
		tauBase := baseI
		tauBase.DelayModel.IncompetenceRate = 0.10
		taus := logspace(1e-3, 0.5, 25)
		r9 := runner.SweepIncompetentFlagThreshold(tauBase, taus)
		if err := runner.SaveIncompetentAggregates("results/incompetent/tau_flag_sweep.json", r9); err != nil {
			fmt.Printf("warning: could not save τ_flag sweep (incompetent): %v\n", err)
		}
	}

	if runSweep10_flagRelLowPIncomp {
		// ------------------------------------------------------------------
		// 10. Flag-reliability at a second, lower p_incomp for a
		//     family-of-curves overlay. Analogous to the honest-baseline
		//     "strict α" overlay: same axis, a harder operating point.
		// ------------------------------------------------------------------
		flagRelBaseLow := baseI
		flagRelBaseLow.DelayModel.IncompetenceRate = 0.02
		r10 := runner.SweepFlagReliability(flagRelBaseLow, flagRels)
		if err := runner.SaveIncompetentAggregates("results/incompetent/flag_reliability_sweep_low_pincomp.json", r10); err != nil {
			fmt.Printf("warning: could not save flag-reliability sweep (low p_incomp): %v\n", err)
		}
	}

	fmt.Println("\n================================================================================")
	fmt.Println("     Incompetent evaluation complete.")
	fmt.Println("================================================================================")
}
