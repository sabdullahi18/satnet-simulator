package main

import (
	"fmt"
	// "log"
	"satnet-simulator/internal/experiment"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

func generateRange(start, end, step float64) []float64 {
	var result []float64
	for v := start; v <= end+1e-9; v += step {
		result = append(result, v)
	}
	return result
}

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     SATNET SIMULATOR - Contradiction-Based Verification Design")
	fmt.Println("================================================================================")
	fmt.Println()

	runner := experiment.NewRunner()

	base := experiment.DefaultExperimentConfig()
	base.NumPackets = 1000 //10000
	base.BatchSize = 10
	base.NumTrials = 5
	base.SimDuration = 1000.0

	// // =========================================================================
	// // Group i — Honest Baseline (Perfect Network)
	// // =========================================================================
	// etas := generateRange(0.001, 0.1, 0.005)
	// batchSizes := []int{2, 10, 50, 100}
	// honestBase := base
	// honestBase.Name = "honest_baseline"
	// honestBase.TargetingConfig = network.DefaultHonestTargeting()
	// honestBase.AdversaryConfig.AnsweringStr = verification.AnswerHonest
	// honestBase.DelayModelConfig.IncompetenceRate = 0.0
	// honestResults := runner.RunEtaBatchSweep(honestBase, etas, batchSizes)
	// if err := runner.SaveResultsToFile("results/group1_honest_baseline.json", honestResults); err != nil {
	// 	log.Printf("warning: could not save honest_baseline results: %v", err)
	// }

	// // =========================================================================
	// // Group iia — Honest but Incompetent
	// // =========================================================================
	// unreliableBase := base
	// unreliableBase.TargetingConfig = network.DefaultHonestTargeting()
	// unreliableBase.AdversaryConfig.AnsweringStr = verification.AnswerInconsistent
	//
	// incompRates := generateRange(0.005, 0.1, 0.01)
	// honestyRates := generateRange(0.0, 1.0, 0.1)
	// queriesPerBatchSweep := []int{1, 2, 5, 10}
	//
	// var allResults []experiment.ExperimentResult
	// for _, qpb := range queriesPerBatchSweep {
	// 	cfg := unreliableBase
	// 	cfg.Name = fmt.Sprintf("incompetent_baseline_qpb%d", qpb)
	// 	cfg.VerificationConfig.QueriesPerBatch = qpb
	// 	results2a := runner.Run5DUnreliableSweep(
	// 		cfg,
	// 		[]float64{0.05, 0.1, 0.15},
	// 		[]float64{0.01, 0.05},
	// 		incompRates,
	// 		honestyRates,
	// 		[]float64{0.0},
	// 	)
	// 	allResults = append(allResults, results2a...)
	// }
	// if err := runner.SaveResultsToFile("results/group2a_monitoring_frontier_qpb.json", allResults); err != nil {
	// 	log.Printf("warning: could not save results: %v", err)
	// }

	// =========================================================================
	// Group iib — Honest but Incompetent - SLA sensitivity
	// =========================================================================
	g2b := base
	g2b.Name = "sla_sensitivity"
	g2b.TargetingConfig = network.DefaultHonestTargeting()
	g2b.AdversaryConfig.AnsweringStr = verification.AnswerInconsistent
	thresholds := generateRange(0.01, 0.15, 0.005)
	results2b := runner.Run5DUnreliableSweep(
		g2b,
		thresholds,
		[]float64{0.01, 0.05},
		[]float64{0.03, 0.05, 0.08},
		[]float64{0.5, 0.8, 1.0},
		[]float64{0.0},
	)
	runner.SaveResultsToFile("results/group2b_sla_sensitivity.json", results2b)

	// // =========================================================================
	// // Group iiia — malicious but competent (AnswerLiesThatMinimal)
	// // =========================================================================
	// g3a := base
	// g3a.Name = "malicious_total_denial"
	// g3a.DelayModelConfig.IncompetenceRate = 0.0
	// g3a.AdversaryConfig.AnsweringStr = verification.AnswerLiesThatMinimal
	// g3a.TargetingConfig.Mode = network.TargetRandom
	// fractions := generateRange(0.01, 0.5, 0.05)
	// results3a := runner.RunEtaFractionSweep(g3a, etas, fractions)
	// runner.SaveResultsToFile("results/group3a_total_denial.json", results3a)

	// // =========================================================================
	// // Group iiib — malicious but competent (AnswerLiesAboutTargeted)
	// // =========================================================================
	// g3b := base
	// g3b.Name = "malicious_selective_denial"
	// g3b.DelayModelConfig.IncompetenceRate = 0.0
	// g3b.AdversaryConfig.AnsweringStr = verification.AnswerLiesAboutTargeted
	// targetingModes := []network.TargetingMode{network.TargetRandom, network.TargetPeriodic}
	//
	// var results3b []experiment.ExperimentResult
	//
	// // Sweep across Targeting Modes and Fractions manually
	// for _, mode := range targetingModes {
	// 	for _, frac := range fractions {
	// 		cfg := g3b
	//
	// 		modeName := "random"
	// 		if mode == network.TargetPeriodic {
	// 			modeName = "periodic"
	// 		}
	//
	// 		cfg.TargetingConfig.Mode = mode
	// 		cfg.TargetingConfig.TargetFraction = frac
	// 		cfg.Name = fmt.Sprintf("malicious_selective_denial_%s_frac%.2f", modeName, frac)
	// 		sweepResults := runner.RunEtaBatchSweep(cfg, etas, batchSizes)
	// 		results3b = append(results3b, sweepResults...)
	// 	}
	// }
	// runner.SaveResultsToFile("results/group3b_selective_denial.json", results3b)

	runner.PrintSummary()
}
