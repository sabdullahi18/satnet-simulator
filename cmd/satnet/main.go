package main

import (
	"fmt"
	"log"
	"satnet-simulator/internal/experiment"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     SATNET SIMULATOR - Contradiction-Based Verification Design")
	fmt.Println("================================================================================")
	fmt.Println()

	runner := experiment.NewRunner()

	// η × targeting-fraction grid: every combination is run.
	etaValues := []float64{0.001, 0.005, 0.01, 0.05, 0.10, 0.20}
	fractionValues := []float64{0.05, 0.10, 0.20, 0.40, 0.60, 0.80}
	incompRates := []float64{0.0, 0.05, 0.10, 0.15, 0.20, 0.30, 0.40}
	honestyRates := []float64{1.0, 0.8, 0.5, 0.2, 0.0}

	base := experiment.DefaultExperimentConfig()
	base.NumPackets = 10000
	base.BatchSize = 2
	base.NumTrials = 5 //do 100 later
	base.SimDuration = 1000.0

	// // =========================================================================
	// // Group i — Honest Baseline (Perfect Network)
	// // =========================================================================
	// honestBase := base
	// honestBase.Name = "honest_baseline"
	// honestBase.TargetingConfig = network.DefaultHonestTargeting()
	// honestBase.AdversaryConfig.AnsweringStr = verification.AnswerHonest
	// honestBase.DelayModelConfig.IncompetenceRate = 0.0
	// honestResults := runner.RunEtaSweep(honestBase, etaValues)
	// if err := runner.SaveResultsToFile("results/honest_baseline.json", honestResults); err != nil {
	// 	log.Printf("warning: could not save honest_baseline results: %v", err)
	// }

	// =========================================================================
	// Group ii — Honest but Incompetent Network
	// =========================================================================
	incompBase := base
	incompBase.Name = "incompetent_baseline"
	incompBase.TargetingConfig = network.DefaultHonestTargeting()
	incompBase.AdversaryConfig.AnsweringStr = verification.AnswerInconsistent
	incompResults := runner.Run4DCheatSweep(incompBase, fractionValues, etaValues, incompRates, honestyRates)
	if err := runner.SaveResultsToFile("results/group2_incompetent.json", incompResults); err != nil {
		log.Printf("warning: could not save incompetent results: %v", err)
	}

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
