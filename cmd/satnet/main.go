package main

import (
	"fmt"
	"satnet-simulator/internal/experiment"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     SATNET SIMULATOR - Verification Design Demo")
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("Delay Model: d_obs(P) = d_base(t) + d_legit(P) + d_malicious(P)")
	fmt.Println("  - d_base(t):      Piecewise constant with Poisson transitions")
	fmt.Println("  - d_legit(P):     LogNormal(μ, σ²) for realistic jitter")
	fmt.Println("  - d_malicious(P): Uniform[M_min, M_max] if P ∈ T (target set)")
	fmt.Println()

	runner := experiment.NewRunner()

	fmt.Println("\n>>> Experiment 1: Honest Network (baseline)")
	honestConfig := experiment.DefaultExperimentConfig()
	honestConfig.Name = "honest_baseline"
	honestConfig.NumPackets = 100
	honestConfig.NumTrials = 5
	honestConfig.TargetingConfig = network.DefaultHonestTargeting()
	honestConfig.LyingStrategy = verification.StrategyHonest
	runner.RunExperiment(honestConfig)

	fmt.Println("\n>>> Experiment 2: Adversarial Network (10% targeted, sophisticated lying)")
	adversarialConfig := experiment.DefaultExperimentConfig()
	adversarialConfig.Name = "adversarial_10pct"
	adversarialConfig.NumPackets = 100
	adversarialConfig.NumTrials = 5
	adversarialConfig.TargetingConfig = network.DefaultAdversarialTargeting(0.10)
	adversarialConfig.LyingStrategy = verification.StrategySophisticated
	adversarialConfig.LieProbability = 0.8
	runner.RunExperiment(adversarialConfig)

	fmt.Println("\n>>> Experiment 3: Adversarial Network (20% targeted, sophisticated lying)")
	adversarialConfig2 := experiment.DefaultExperimentConfig()
	adversarialConfig2.Name = "adversarial_20pct"
	adversarialConfig2.NumPackets = 100
	adversarialConfig2.NumTrials = 5
	adversarialConfig2.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	adversarialConfig2.LyingStrategy = verification.StrategySophisticated
	adversarialConfig2.LieProbability = 0.8
	runner.RunExperiment(adversarialConfig2)

	runner.PrintSummary()

	// fmt.Println("\n>>> CSV Export:")
	// fmt.Println(runner.GenerateCSV())
}
