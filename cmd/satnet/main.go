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

	// Primary experimental axis: sweep η ∈ {0.001, 0.005, 0.01, 0.05, 0.10, 0.20}.
	// For each (prover strategy, η), multiple independent trials are executed.
	etaValues := []float64{0.001, 0.005, 0.01, 0.05, 0.10, 0.20}

	base := experiment.DefaultExperimentConfig()
	base.NumPackets = 200
	base.BatchSize = 5
	base.NumTrials = 10
	base.SimDuration = 100.0

	// Experiment 1: Honest baseline — measures false positive rate across η.
	// H0 should be identified as TRUSTED; any DISHONEST verdict is a false positive.
	honestBase := base
	honestBase.Name = "honest_baseline"
	honestBase.TargetingConfig = network.DefaultHonestTargeting()
	honestBase.AdversaryConfig.AnsweringStr = verification.AnswerHonest
	runner.RunEtaSweep(honestBase, etaValues)

	// Experiment 2: Lies-that-minimal — blanket denial; claims every packet was minimal.
	// Most reckless strategy, highly vulnerable to contradiction checks.
	liesMBase := base
	liesMBase.Name = "lies_that_minimal"
	liesMBase.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	liesMBase.AdversaryConfig.AnsweringStr = verification.AnswerLiesThatMinimal
	runner.RunEtaSweep(liesMBase, etaValues)

	// Experiment 3: Lies-about-targeted — lies only for deliberately delayed packets.
	// More careful strategy; exploits the fact that queried packets may not be targeted.
	liesABase := base
	liesABase.Name = "lies_about_targeted"
	liesABase.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	liesABase.AdversaryConfig.AnsweringStr = verification.AnswerLiesAboutTargeted
	runner.RunEtaSweep(liesABase, etaValues)

	// Experiment 4: Delayed-honest — uses flagging to cover deliberate delays.
	// Never claims a targeted packet was minimal; instead flags them as congested.
	// Raises the flag rate, but avoids direct contradictions.
	delayedHBase := base
	delayedHBase.Name = "delayed_honest"
	delayedHBase.TargetingConfig = network.DefaultAdversarialTargeting(0.20)
	delayedHBase.AdversaryConfig.AnsweringStr = verification.AnswerDelayedHonest
	runner.RunEtaSweep(delayedHBase, etaValues)

	runner.PrintSummary()
}
