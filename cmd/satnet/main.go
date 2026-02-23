package main

import (
	"fmt"
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

	fmt.Println("\n>>> Experiment 1: Honest Network (baseline)")
	honestConfig := experiment.DefaultExperimentConfig()
	honestConfig.Name = "honest_baseline"
	honestConfig.NumPackets = 100
	honestConfig.BatchSize = 2
	honestConfig.NumTrials = 5
	honestConfig.TargetingConfig = network.DefaultHonestTargeting()
	honestConfig.AdversaryConfig.AnsweringStr = verification.AnswerHonest
	runner.RunExperiment(honestConfig)

	fmt.Println("\n>>> Experiment 2: Adversarial Network (10% targeted, Delayed-Honest strategy)")
	adversarialConfig := experiment.DefaultExperimentConfig()
	adversarialConfig.Name = "adversarial_10pct_delayed_honest"
	adversarialConfig.NumPackets = 100
	adversarialConfig.BatchSize = 2
	adversarialConfig.NumTrials = 5
	adversarialConfig.TargetingConfig = network.DefaultAdversarialTargeting(0.10)
	adversarialConfig.AdversaryConfig.AnsweringStr = verification.AnswerDelayedHonest
	adversarialConfig.AdversaryConfig.MaliciousRate = 0.10
	runner.RunExperiment(adversarialConfig)

	fmt.Println("\n>>> Experiment 3: Adversarial Network (20% targeted, Lies-That-Minimal gaslighting)")
	adversarialConfig2 := experiment.DefaultExperimentConfig()
	adversarialConfig2.Name = "adversarial_20pct_lies_that_minimal"
	adversarialConfig2.NumPackets = 100
	adversarialConfig2.BatchSize = 2
	adversarialConfig2.NumTrials = 5
	adversarialConfig2.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	adversarialConfig2.AdversaryConfig.AnsweringStr = verification.AnswerLiesThatMinimal
	adversarialConfig2.AdversaryConfig.MaliciousRate = 0.20
	runner.RunExperiment(adversarialConfig2)

	runner.PrintSummary()

	// fmt.Println("\n>>> CSV Export:")
	// fmt.Println(runner.GenerateCSV())
}
