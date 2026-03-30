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
	base.BatchSize = 2
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

	// =========================================================================
	// Group iia — Honest but Incompetent with Unreliable Answers
	// unreliable answers versus eta
	// =========================================================================
	unreliableBase := base
	unreliableBase.Name = "incompetent_baseline"
	unreliableBase.TargetingConfig = network.DefaultHonestTargeting()
	unreliableBase.AdversaryConfig.AnsweringStr = verification.AnswerUnreliable
	errorRates := generateRange(0.0, 0.20, 0.005)
	standardEtas := []float64{0.005, 0.01, 0.05, 0.1}
	split2A := unreliableBase
	split2A.Name = "unreliable_eta_vs_error"
	results2A := runner.Run5DUnreliableSweep(
		split2A,
		[]float64{0.05},
		standardEtas,
		[]float64{0.03},
		[]float64{1.0},
		errorRates,
	)
	runner.SaveResultsToFile("results/group2A_eta_error.json", results2A)

	// // =========================================================================
	// // GROUP iib: Unreliable Answers vs. True Incompetence (The Double Penalty)
	// // =========================================================================
	// smoothIncompRates := generateRange(0.0, 0.1, 0.002)    // 0% to 30% incompetence
	// specificErrorRates := []float64{0.0, 0.02, 0.05, 0.10} // 4 fixed error curves
	//
	// split2B := unreliableBase
	// split2B.Name = "unreliable_incomp_vs_error"
	// results2B := runner.Run5DUnreliableSweep(
	// 	split2B,
	// 	[]float64{0.08},    // Lock: Standard SLA
	// 	[]float64{0.05},    // Lock: Standard η
	// 	smoothIncompRates,  // Sweep: High-res Incompetence
	// 	[]float64{1.0},     // Lock: 100% honest flagging
	// 	specificErrorRates, // Sweep: Error rates
	// )
	// runner.SaveResultsToFile("results/group2B_incomp_error.json", results2B)

	// // =========================================================================
	// // GROUP iic: Unreliable Answers vs. SLA Strictness (Flag Threshold)
	// // =========================================================================
	// smoothFlagThresholds := generateRange(0.01, 0.10, 0.002) // 10% to 40% SLAs
	// specificErrorRates2 := []float64{0.0, 0.02, 0.05, 0.10}  // 3 fixed error curves
	//
	// split2C := unreliableBase
	// split2C.Name = "unreliable_thresh_vs_error"
	// results2C := runner.Run5DUnreliableSweep(
	// 	split2C,
	// 	smoothFlagThresholds, // Sweep: High-res SLA Strictness
	// 	[]float64{0.05},      // Lock: Standard η
	// 	[]float64{0.04},
	// 	[]float64{1.0},      // Lock: 100% honest flagging
	// 	specificErrorRates2, // Sweep: Error rates
	// )
	// runner.SaveResultsToFile("results/group2C_thresh_error.json", results2C)

	// =========================================================================
	// GROUP 3: The SLA Cheater (Inconsistent Flagging)
	// =========================================================================
	smoothHonestyRates := generateRange(0.0, 1.0, 0.05) // 0% to 100% honesty in 5% steps
	badIncompRates := []float64{0.1, 0.20, 0.30, 0.40}  // Mediocre, Bad, Terrible networks

	cheatBase := base
	cheatBase.Name = "sla_cheater_honesty_vs_incomp"
	cheatBase.TargetingConfig = network.DefaultHonestTargeting()
	cheatBase.AdversaryConfig.AnsweringStr = verification.AnswerInconsistent // The cheating strategy

	// We use the standard 5D runner but set error rate to 0.0 since we are isolating Flag Honesty
	cheatResults := runner.Run5DUnreliableSweep(
		cheatBase,
		[]float64{0.05},       // Lock: Standard SLA threshold
		[]float64{0.01, 0.05}, // Lock: Standard η
		badIncompRates,        // Sweep: 3 network qualities
		smoothHonestyRates,    // Sweep: High-res Honesty (How much they hide)
		[]float64{0.0},        // Lock: 0% Answer Errors (Perfect API)
	)
	runner.SaveResultsToFile("results/group3_sla_cheater.json", cheatResults)

	// // Experiment 2: Lies-that-minimal — blanket denial; claims every packet was minimal.
	// liesMBase := base
	// liesMBase.Name = "lies_that_minimal"
	// liesMBase.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	// liesMBase.AdversaryConfig.AnsweringStr = verification.AnswerLiesThatMinimal
	// liesMResults := runner.RunEtaFractionSweep(liesMBase, etaValues, fractionValues)
	// if err := runner.SaveResultsToFile("results/lies_that_minimal.json", liesMResults); err != nil {
	// 	log.Printf("warning: could not save lies_that_minimal results: %v", err)
	// }
	//
	// // Experiment 3: Lies-about-targeted — lies only for deliberately delayed packets.
	// liesABase := base
	// liesABase.Name = "lies_about_targeted"
	// liesABase.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	// liesABase.AdversaryConfig.AnsweringStr = verification.AnswerLiesAboutTargeted
	// liesAResults := runner.RunEtaFractionSweep(liesABase, etaValues, fractionValues)
	// if err := runner.SaveResultsToFile("results/lies_about_targeted.json", liesAResults); err != nil {
	// 	log.Printf("warning: could not save lies_about_targeted results: %v", err)
	// }
	//
	// // Experiment 4: Delayed-honest — uses flagging to cover deliberate delays.
	// delayedHBase := base
	// delayedHBase.Name = "delayed_honest"
	// delayedHBase.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	// delayedHBase.AdversaryConfig.AnsweringStr = verification.AnswerDelayedHonest
	// delayedHResults := runner.RunEtaFractionSweep(delayedHBase, etaValues, fractionValues)
	// if err := runner.SaveResultsToFile("results/delayed_honest.json", delayedHResults); err != nil {
	// 	log.Printf("warning: could not save delayed_honest results: %v", err)
	// }

	runner.PrintSummary()
}
