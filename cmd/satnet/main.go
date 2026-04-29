package main

import (
	"flag"
	"fmt"
	"math"
	"time"

	"satnet-simulator/internal/experiment"
	"satnet-simulator/internal/verification"
)

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

func alphaLogspace(oneMinusHi, oneMinusLo float64, n int) []float64 {
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

	baseI := experiment.DefaultIncompetentBaseline()
	baseI.NumTrials = 200
	baseI.NumPackets = 10000
	baseI.BatchSize = 10
	baseI.SimDuration = 1000.0
	baseI.Verification.ConfidenceThreshold = 0.999

	// Toggle blocks individually so partial reruns are cheap.
	const (
		runSweep1_pIncomp         = false
		runSweep2_flagRel         = false
		runSweep3_flagRelHigh     = false
		runSweep4_eta             = false
		runSweep5_alpha           = false
		runSweep6_ansErr          = false
		runSweep7_budgetVsPincomp = false
		runSweep8_batchSize       = false
		runSweep9_qpb             = false
		runSweep10_magnitude      = false
		runSweep11_tauFlag        = false
		runSweep12_phaseMap       = false
	)

	flagRels := linspace(0.0, 1.0, 40)

	// ================================================================
	//   Headline sweeps — multi-seed
	// ================================================================
	// Three sweeps (p_incomp, flag-rel @ p=0.10, flag-rel @ p=0.20)
	// run for five seeds each so the chapter can show families of
	// curves with seed-mean overlays.

	incompetentSeeds := []int64{baseSeed, 2, 3, 4, 5}

	for _, seed := range incompetentSeeds {
		seedDir := fmt.Sprintf("results/incompetent/seed_%d", seed)
		fmt.Printf("\n--- seed %d (headline sweeps) ---\n", seed)
		runner.SetBaseSeed(seed)

		if runSweep1_pIncomp {
			// 1. p_incomp. Headline detection curve. Under α = 0.999 the
			//    TRUSTED → CAUGHT_INCOMPETENT transition shifts to lower
			//    p_incomp values than the previous α = 0.99 run because
			//    the verifier audits ~47 packets instead of ~2 and is
			//    therefore much more likely to catch a rare admission.
			pIncompSweep := logspace(1e-4, 0.3, 40)
			r1 := runner.SweepIncompetenceRate(baseI, pIncompSweep)
			if err := runner.SaveIncompetentAggregates(seedDir+"/incompetence_rate_sweep.json", r1); err != nil {
				fmt.Printf("warning: could not save p_incomp sweep: %v\n", err)
			}
		}

		if runSweep2_flagRel {
			// 2. Flag reliability at p_incomp = 0.10. Mid-density congestion
			//    where the per-batch admission rate is non-trivial. Detection
			//    rate decays cleanly as flag reliability rises (a network
			//    that always flags is operationally honest).
			flagRelBase := baseI
			flagRelBase.DelayModel.IncompetenceRate = 0.10
			r2 := runner.SweepFlagReliability(flagRelBase, flagRels)
			if err := runner.SaveIncompetentAggregates(seedDir+"/flag_reliability_sweep.json", r2); err != nil {
				fmt.Printf("warning: could not save flag-reliability sweep: %v\n", err)
			}
		}

		if runSweep3_flagRelHigh {
			// 3. Flag reliability overlay at p_incomp = 0.20. Replaces the
			//    previous low-p_incomp overlay, which was redundant with
			//    sweep 2 because the curve was flat at TRUSTED ≈ 1. The
			//    higher-p_incomp overlay separates from sweep 2 and lets
			//    the chapter show a family of curves at p ∈ {0.10, 0.20}.
			flagRelBaseHigh := baseI
			flagRelBaseHigh.DelayModel.IncompetenceRate = 0.20
			r3 := runner.SweepFlagReliability(flagRelBaseHigh, flagRels)
			if err := runner.SaveIncompetentAggregates(seedDir+"/flag_reliability_sweep_high_pincomp.json", r3); err != nil {
				fmt.Printf("warning: could not save flag-reliability sweep (high p_incomp): %v\n", err)
			}
		}
	}

	// ================================================================
	//   Diagnostic sweeps — single seed
	// ================================================================
	// Each sweep below runs at the unified baseline with at most one
	// or two per-sweep overrides. The most common override is to swap
	// AnsweringStrategy to AnswerUnreliable and inject an
	// answer_error_rate; this is needed wherever the parameter being
	// swept can only act when contradictions are present.

	runner.SetBaseSeed(baseSeed)
	diagDir := "results/incompetent"

	if runSweep4_eta {
		// 4. η. With AnswerUnreliable + ans_err = 0.20, contradictions
		//    accumulate during the verifier's audit. η controls how
		//    those contradictions are interpreted: small η pushes mass
		//    to H2 (CAUGHT_MALICIOUS), large η lets H1 absorb them. The
		//    sweep should show a clean H1/H2 boundary along the η axis.
		etaBase := baseI
		etaBase.DelayModel.IncompetenceRate = 0.10
		etaBase.AnsweringStrategy = verification.AnswerUnreliable
		etaBase.AnswerErrorRate = 0.20
		etas := logspace(1e-3, 0.49, 30)
		r4 := runner.SweepIncompetentEta(etaBase, etas)
		if err := runner.SaveIncompetentAggregates(diagDir+"/eta_sweep.json", r4); err != nil {
			fmt.Printf("warning: could not save η sweep (incompetent): %v\n", err)
		}
	}

	if runSweep5_alpha {
		// 5. α. Same setup as sweep 4. As α tightens, n_min grows and
		//    the verifier accumulates more contradictions before halting,
		//    pushing more trials into CAUGHT_MALICIOUS. As α loosens
		//    (toward 0.5), the verifier halts almost immediately and
		//    most trials end TRUSTED.
		alphaBase := baseI
		alphaBase.DelayModel.IncompetenceRate = 0.10
		alphaBase.AnsweringStrategy = verification.AnswerUnreliable
		alphaBase.AnswerErrorRate = 0.20
		alphas := alphaLogspace(0.5, 1e-10, 25)
		r5 := runner.SweepIncompetentAlpha(alphaBase, alphas)
		if err := runner.SaveIncompetentAggregates(diagDir+"/alpha_sweep.json", r5); err != nil {
			fmt.Printf("warning: could not save α sweep (incompetent): %v\n", err)
		}
	}

	if runSweep6_ansErr {
		// 6. Answer-error rate. AnswerUnreliable is part of the sweep
		//    definition; the rate itself is the swept parameter. With
		//    n_min ≈ 47 the verifier accumulates enough contradictions
		//    to make the H1 → H2 verdict transition empirically visible.
		aeBase := baseI
		aeBase.DelayModel.IncompetenceRate = 0.10
		aeBase.AnsweringStrategy = verification.AnswerUnreliable
		ansErrs := linspace(0.0, 0.5, 30)
		r6 := runner.SweepAnswerErrorRate(aeBase, ansErrs)
		if err := runner.SaveIncompetentAggregates(diagDir+"/answer_error_sweep.json", r6); err != nil {
			fmt.Printf("warning: could not save answer-error sweep: %v\n", err)
		}
	}

	if runSweep7_budgetVsPincomp {
		// 7. Detection vs query budget, at three p_incomp values. Three
		//    curves on one plot: each shows how detection rises with
		//    NumPackets at a fixed p_incomp. This is the cost-of-detection
		//    plot the chapter currently lacks. AnswerHonest because we
		//    want the H1 admission path, not the H2 contradiction path.
		pktBase := baseI
		pktBase.NumTrials = 100
		pktBase.AnsweringStrategy = verification.AnswerHonest
		pkts := []int{20, 30, 50, 80, 100, 150, 200, 300, 500, 1000, 2000, 5000, 10000}
		for _, pinc := range []float64{0.05, 0.10, 0.20} {
			cfg := pktBase
			cfg.DelayModel.IncompetenceRate = pinc
			cfg.Name = fmt.Sprintf("incompetent_budget_pincomp%.3f", pinc)
			r := runner.SweepIncompetentNumPackets(cfg, pkts)
			path := fmt.Sprintf("%s/numpackets_sweep_pincomp%.3f.json", diagDir, pinc)
			if err := runner.SaveIncompetentAggregates(path, r); err != nil {
				fmt.Printf("warning: could not save NumPackets sweep at p_incomp=%.3f: %v\n", pinc, err)
			}
		}
	}

	if runSweep8_batchSize {
		// 8. Batch size B. NumPackets is held at 10000, so as B grows the
		//    number of batches (= maximum query budget) shrinks from 5000
		//    down to 100. AnswerUnreliable + ans_err = 0.20 ensures any
		//    effect of per-batch composition on contradiction rate is
		//    visible rather than masked by the early-stop floor.
		batchBase := baseI
		batchBase.DelayModel.IncompetenceRate = 0.05
		batchBase.AnsweringStrategy = verification.AnswerUnreliable
		batchBase.AnswerErrorRate = 0.20
		batches := []int{2, 3, 4, 5, 8, 10, 15, 20, 30, 50, 75, 100}
		r8 := runner.SweepIncompetentBatchSize(batchBase, batches)
		if err := runner.SaveIncompetentAggregates(diagDir+"/batch_size_sweep.json", r8); err != nil {
			fmt.Printf("warning: could not save batch-size sweep (incompetent): %v\n", err)
		}
	}

	if runSweep9_qpb {
		// 9. Queries per batch. Larger QPB probes more packets per batch
		//    and so increases the per-batch contradiction probability
		//    under AnswerUnreliable. With n_min ≈ 47 the verifier has
		//    room to translate that into faster detection.
		qpbBase := baseI
		qpbBase.DelayModel.IncompetenceRate = 0.05
		qpbBase.AnsweringStrategy = verification.AnswerUnreliable
		qpbBase.AnswerErrorRate = 0.20
		qpbs := []int{1, 2, 3, 4, 5, 8, 10}
		r9 := runner.SweepIncompetentQueriesPerBatch(qpbBase, qpbs)
		if err := runner.SaveIncompetentAggregates(diagDir+"/queries_per_batch_sweep.json", r9); err != nil {
			fmt.Printf("warning: could not save queries-per-batch sweep (incompetent): %v\n", err)
		}
	}

	if runSweep10_magnitude {
		// 10. Incompetence-delay magnitude µ. Verifier uses batch ordering
		//     not magnitude, so the curve is expected to be flat. Kept
		//     short (NumTrials = 100, 15 grid points) as an empirical
		//     confirmation of that design property. AnswerHonest keeps
		//     this sweep as a pure design-property check rather than
		//     mixing in the H2 path.
		muBase := baseI
		muBase.NumTrials = 100
		muBase.DelayModel.IncompetenceRate = 0.10
		mus := linspace(math.Log(1e-4), math.Log(0.1), 15)
		r10 := runner.SweepIncompetenceMagnitude(muBase, mus)
		if err := runner.SaveIncompetentAggregates(diagDir+"/magnitude_sweep.json", r10); err != nil {
			fmt.Printf("warning: could not save magnitude sweep (incompetent): %v\n", err)
		}
	}

	if runSweep11_tauFlag {
		// 11. SLA flagging threshold τ_flag. The SLA path is dormant in the
		//     baseline because admissions are rare. p_incomp = 0.20 with
		//     FlagReliability = 0 floods the verifier with should-have-
		//     been-flagged events, so the corrected flag rate has
		//     something to compare against τ_flag. AnswerHonest isolates
		//     the SLA path from the H2 contradiction path so the sweep
		//     measures one detector at a time.
		tauBase := baseI
		tauBase.DelayModel.IncompetenceRate = 0.20
		tauBase.FlagReliability = 0.0
		tauBase.AnsweringStrategy = verification.AnswerHonest
		taus := logspace(1e-3, 0.5, 25)
		r11 := runner.SweepIncompetentFlagThreshold(tauBase, taus)
		if err := runner.SaveIncompetentAggregates(diagDir+"/tau_flag_sweep.json", r11); err != nil {
			fmt.Printf("warning: could not save τ_flag sweep (incompetent): %v\n", err)
		}
	}

	if runSweep12_phaseMap {
		// 12. p_incomp × flag-reliability phase map. The joint-axis
		//     summary of sweeps 1 and 2. Unchanged structure from the
		//     previous revision but now under α = 0.999, which sharpens
		//     the boundary between trusted and caught regions.
		phaseBase := baseI
		phaseBase.NumTrials = 80
		phasePincomp := logspace(1e-4, 0.3, 16)
		phaseFlagRel := linspace(0.0, 1.0, 16)
		r12 := runner.SweepIncompetentPhaseMap(phaseBase, phasePincomp, phaseFlagRel)
		if err := runner.SaveIncompetentAggregates(diagDir+"/pincomp_flagrel_phase_map.json", r12); err != nil {
			fmt.Printf("warning: could not save p_incomp x flag-reliability phase map: %v\n", err)
		}
	}

	fmt.Println("\n================================================================================")
	fmt.Println("     Incompetent evaluation complete.")
	fmt.Println("================================================================================")

	// ================================================================
	//     Malicious-network evaluation
	// ================================================================
	fmt.Println("\n================================================================================")
	fmt.Println("     SATNET SIMULATOR - Malicious Network Evaluation")
	fmt.Println("================================================================================")

	// Base config shared by all adversarial sweeps.
	baseM := experiment.DefaultMaliciousBaseline()
	baseM.NumTrials = 200
	baseM.NumPackets = 10000
	baseM.BatchSize = 10
	baseM.SimDuration = 1000.0
	baseM.Verification = verification.DefaultVerificationConfig()
	baseM.Verification.ConfidenceThreshold = 0.999

	tauFlag := baseM.Verification.FlaggingRateThreshold

	// Toggle individual sweeps independently.
	const (
		runMal_naive          = false
		runMal_silent         = false
		runMal_smart          = false
		runMal_paramPTarget   = false
		runMal_paramPLie      = false
		runMal_paramPhaseMap  = false
		runMal_aggressive     = false
		runMal_targetingModes = true
	)

	malDir := "results/malicious"

	// ================================================================
	//   Headline sweeps — multi-seed
	// ================================================================
	// Sweep-type experiments (naive, silent, smart, parametric, aggressive)
	// run for five seeds so the plotter can show families of curves with
	// seed-mean overlays, matching the incompetent evaluation structure.

	maliciousSeeds := []int64{baseSeed, 2, 3, 4, 5}

	for _, seed := range maliciousSeeds {
		seedDir := fmt.Sprintf("%s/seed_%d", malDir, seed)
		fmt.Printf("\n--- seed %d (malicious sweeps) ---\n", seed)
		runner.SetBaseSeed(seed)

		// ----------------------------------------------------------------
		// §5.3.1 Naive Liar — p_flag=0, p_lie=1
		// ----------------------------------------------------------------
		if runMal_naive {
			naiveBase := baseM
			naiveBase.Name = "naive_liar"
			naiveBase.DelayModel.DeliberateMin = 0.050
			naiveBase.DelayModel.DeliberateMax = 0.050
			pTargets := logspace(1e-3, 0.5, 30)
			r := runner.SweepMaliciousPTarget(experiment.NaiveLiarConfig(naiveBase, 0.1), pTargets)
			if err := runner.SaveMaliciousAggregates(seedDir+"/naive_liar_ptarget_sweep.json", r); err != nil {
				fmt.Printf("warning: %v\n", err)
			}
		}

		// ----------------------------------------------------------------
		// §5.3.2 Silent Dropper — p_flag=0, p_lie=0
		// ----------------------------------------------------------------
		if runMal_silent {
			silentBase := baseM
			silentBase.Name = "silent_dropper"
			silentBase.DelayModel.DeliberateMin = 0.050
			silentBase.DelayModel.DeliberateMax = 0.050
			pTargets := logspace(1e-3, 0.5, 30)
			r := runner.SweepMaliciousPTarget(experiment.SilentDropperConfig(silentBase, 0.1), pTargets)
			if err := runner.SaveMaliciousAggregates(seedDir+"/silent_dropper_ptarget_sweep.json", r); err != nil {
				fmt.Printf("warning: %v\n", err)
			}
		}

		// ----------------------------------------------------------------
		// §5.4 Smart Strategy — p_flag=1, p_lie=0, p_target ≤ τ_flag
		// Sweeps both the compliant range [0, τ_flag] (should stay TRUSTED)
		// and the boundary overshoot [τ_flag, 2·τ_flag] (should trigger SLA).
		// ----------------------------------------------------------------
		if runMal_smart {
			smartBase := baseM
			smartBase.Name = "smart"
			smartBase.DelayModel.DeliberateMin = 0.050
			smartBase.DelayModel.DeliberateMax = 0.050
			// Compliant range
			pCompliant := linspace(0, tauFlag, 15)
			rCompliant := runner.SweepMaliciousPTarget(experiment.SmartStrategyConfig(smartBase, tauFlag*0.5), pCompliant)
			if err := runner.SaveMaliciousAggregates(seedDir+"/smart_compliant_sweep.json", rCompliant); err != nil {
				fmt.Printf("warning: %v\n", err)
			}
			// Overshoot range
			pOvershoot := linspace(tauFlag, 2*tauFlag, 15)
			rOvershoot := runner.SweepMaliciousPTarget(experiment.SmartStrategyConfig(smartBase, tauFlag*1.5), pOvershoot)
			if err := runner.SaveMaliciousAggregates(seedDir+"/smart_overshoot_sweep.json", rOvershoot); err != nil {
				fmt.Printf("warning: %v\n", err)
			}
		}

		// ----------------------------------------------------------------
		// §5.5 Generalised Parametric — vary p_target at fixed p_lie values
		// ----------------------------------------------------------------
		if runMal_paramPTarget {
			paramBase := baseM
			paramBase.Name = "parametric"
			paramBase.DelayModel.DeliberateMin = 0.050
			paramBase.DelayModel.DeliberateMax = 0.050
			pTargets := logspace(1e-3, 0.5, 30)
			for _, pLie := range []float64{0.0, 0.25, 0.5, 0.75, 1.0} {
				cfg := experiment.ParametricConfig(paramBase, 0.1, 0.0, pLie)
				cfg.Name = fmt.Sprintf("parametric_plie%.2f", pLie)
				r := runner.SweepMaliciousPTarget(cfg, pTargets)
				path := fmt.Sprintf("%s/parametric_ptarget_plie%.2f.json", seedDir, pLie)
				if err := runner.SaveMaliciousAggregates(path, r); err != nil {
					fmt.Printf("warning: %v\n", err)
				}
			}
		}

		// ----------------------------------------------------------------
		// §5.5 Generalised Parametric — vary p_lie at fixed p_target
		// ----------------------------------------------------------------
		if runMal_paramPLie {
			paramBase := baseM
			paramBase.Name = "parametric_plie_sweep"
			paramBase.DelayModel.DeliberateMin = 0.050
			paramBase.DelayModel.DeliberateMax = 0.050
			pLies := linspace(0, 1, 25)
			for _, pTarget := range []float64{2 * tauFlag, 5 * tauFlag, 10 * tauFlag} {
				cfg := experiment.ParametricConfig(paramBase, pTarget, experiment.AggressivePFlag(pTarget, tauFlag), 0.5)
				cfg.Name = fmt.Sprintf("parametric_ptarget_x%.0f_tauflag", pTarget/tauFlag)
				r := runner.SweepMaliciousPLie(cfg, pLies)
				path := fmt.Sprintf("%s/parametric_plie_ptarget_x%.0ftau.json", seedDir, pTarget/tauFlag)
				if err := runner.SaveMaliciousAggregates(path, r); err != nil {
					fmt.Printf("warning: %v\n", err)
				}
			}
		}

		// ----------------------------------------------------------------
		// §5.5 Aggressive optimum — p_lie sweep at three p_target multiples
		// p_flag is set to AggressivePFlag so the SLA budget is exactly consumed.
		// ----------------------------------------------------------------
		if runMal_aggressive {
			aggBase := baseM
			aggBase.Name = "aggressive"
			aggBase.DelayModel.DeliberateMin = 0.050
			aggBase.DelayModel.DeliberateMax = 0.050
			pLies := linspace(0, 1, 25)
			for _, mult := range []float64{2, 5, 10} {
				pTarget := mult * tauFlag
				pFlag := experiment.AggressivePFlag(pTarget, tauFlag)
				cfg := experiment.ParametricConfig(aggBase, pTarget, pFlag, 0.5)
				cfg.Name = fmt.Sprintf("aggressive_x%.0ftau", mult)
				r := runner.SweepMaliciousPLie(cfg, pLies)
				path := fmt.Sprintf("%s/aggressive_plie_x%.0ftau.json", seedDir, mult)
				if err := runner.SaveMaliciousAggregates(path, r); err != nil {
					fmt.Printf("warning: %v\n", err)
				}
			}
		}
	}

	// ================================================================
	//   Single-seed experiments (phase map, targeting modes)
	// ================================================================
	runner.SetBaseSeed(baseSeed)

	// ----------------------------------------------------------------
	// §5.5 Phase map — 2D sweep (p_target × p_lie) with aggressive p_flag
	// ----------------------------------------------------------------
	if runMal_paramPhaseMap {
		phaseBase := baseM
		phaseBase.Name = "parametric_phase_map"
		phaseBase.NumTrials = 100
		phaseBase.DelayModel.DeliberateMin = 0.050
		phaseBase.DelayModel.DeliberateMax = 0.050
		pTargets := logspace(1e-3, 0.5, 16)
		pLies := linspace(0, 1, 16)
		r := runner.SweepMaliciousPhaseMap(phaseBase, pTargets, pLies)
		if err := runner.SaveMaliciousAggregates(malDir+"/parametric_phase_map.json", r); err != nil {
			fmt.Printf("warning: %v\n", err)
		}
	}

	// ----------------------------------------------------------------
	// §5.1 Targeting modes comparison
	// ----------------------------------------------------------------
	if runMal_targetingModes {
		modesBase := baseM
		modesBase.Name = "targeting_modes"
		modesBase.DelayModel.DeliberateMin = 0.050
		modesBase.DelayModel.DeliberateMax = 0.050
		r := runner.SweepMaliciousTargetingModes(modesBase)
		if err := runner.SaveMaliciousAggregates(malDir+"/targeting_modes.json", r); err != nil {
			fmt.Printf("warning: %v\n", err)
		}
	}

	fmt.Println("\n================================================================================")
	fmt.Println("     Malicious evaluation complete.")
	fmt.Println("================================================================================")
}
