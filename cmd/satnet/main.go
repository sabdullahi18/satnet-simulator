package main

import (
	"fmt"
	"log"
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
	base.NumPackets = 10000
	base.BatchSize = 10
	base.NumTrials = 100
	base.SimDuration = 1000.0

	// =========================================================================
	// Group i — Honest Baseline (Perfect Network)
	// =========================================================================
	etas := generateRange(0.001, 0.2, 0.005)
	honestBase := base
	honestBase.Name = "honest_baseline"
	honestBase.TargetingConfig = network.DefaultHonestTargeting()
	honestBase.AdversaryConfig.AnsweringStr = verification.AnswerHonest
	honestBase.DelayModelConfig.IncompetenceRate = 0.0
	honestResults := runner.RunEtaSweep(honestBase, etas)
	if err := runner.SaveResultsToFile("results/group1_honest_baseline.json", honestResults); err != nil {
		log.Printf("warning: could not save honest_baseline results: %v", err)
	}

	// // =========================================================================
	// // Group iia — Honest but Incompetent
	// // =========================================================================
	// unreliableBase := base
	// unreliableBase.Name = "incompetent_baseline"
	// unreliableBase.TargetingConfig = network.DefaultHonestTargeting()
	// unreliableBase.AdversaryConfig.AnsweringStr = verification.AnswerInconsistent
	// unreliableBase.VerificationConfig.FlaggingRateThreshold = 0.05
	// incompRates := generateRange(0.00, 0.1, 0.01)
	// honestyRates := generateRange(0.0, 1.0, 0.1)
	// results2a := runner.Run5DUnreliableSweep(
	// 	unreliableBase,
	// 	[]float64{0.05},       // Lock: SLA threshold = 5%
	// 	[]float64{0.01, 0.05}, // Two η values
	// 	incompRates,           // Sweep: network quality
	// 	honestyRates,          // Sweep: monitoring quality
	// 	[]float64{0.0},        // Lock: no answer errors
	// )
	// runner.SaveResultsToFile("results/group2a_monitoring_frontier.json", results2a)

	// // =========================================================================
	// // Group iib — Honest but Incompetent - SLA sensitivity
	// // =========================================================================
	// g2b := base
	// g2b.Name = "sla_sensitivity"
	// g2b.TargetingConfig = network.DefaultHonestTargeting()
	// g2b.AdversaryConfig.AnsweringStr = verification.AnswerInconsistent
	// thresholds := generateRange(0.01, 0.15, 0.005) // Fine-grained SLA sweep
	// results2b := runner.Run5DUnreliableSweep(
	// 	g2b,
	// 	thresholds,                  // Sweep: SLA threshold
	// 	[]float64{0.01, 0.05},       // Two η values
	// 	[]float64{0.03, 0.05, 0.08}, // Three network qualities
	// 	[]float64{0.5, 0.8, 1.0},    // Three monitoring qualities
	// 	[]float64{0.0},              // No answer errors
	// )
	// runner.SaveResultsToFile("results/group2b_sla_sensitivity.json", results2b)
	//
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
	//
	// // =========================================================================
	// // Group iiia — malicious but competent (AnswerLiesAboutTargeted)
	// // =========================================================================
	// g3b := base
	// g3b.Name = "malicious_selective_denial"
	// g3b.DelayModelConfig.IncompetenceRate = 0.0
	// g3b.AdversaryConfig.AnsweringStr = verification.AnswerLiesAboutTargeted
	// g3b.TargetingConfig.Mode = network.TargetRandom
	// results3b := runner.RunEtaFractionSweep(g3b, etas, fractions)
	// runner.SaveResultsToFile("results/group3b_selective_denial.json", results3b)
	//
	runner.PrintSummary()
}
