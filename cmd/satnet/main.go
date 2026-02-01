package main

import (
	"fmt"
	"satnet-simulator/internal/experiment"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     SATELLITE NETWORK SIMULATOR")
	fmt.Println("================================================================================")

	runner := experiment.NewRunner()

	baseConfig := experiment.ExperimentConfig{
		NumPackets:  300,
		NumTrials:   1,
		SimDuration: 30.0,
		Paths: []network.SatellitePath{
			{Name: "PATH_A", Delay: 0.10, SpikeProb: 0.05, SpikeDelay: 0.2},
			{Name: "PATH_B", Delay: 0.12, SpikeProb: 0.05, SpikeDelay: 0.2},
		},
		PathStrategy:    network.StrategyRandom,
		FlagProbability: 0.5,

		AdversarialConfig: network.AdversarialConfig{
			Mode:              network.ModeRandomDelay,
			DelayFraction:     0.10,
			MinMaliciousDelay: 0.2,
			MaxMaliciousDelay: 1.0,
		},

		VerificationConfig: verification.DefaultVerificationConfig(),
	}

	// 1. Random Flag / Random Answer
	c1 := baseConfig
	c1.Name = "1_RandFlag_RandAns"
	c1.FlaggingStrategy = verification.FlagRandom
	c1.AnsweringStrategy = verification.AnswerRandom
	r1 := runner.RunExperiment(c1)
	fmt.Print(r1)

	// // 2. Random Flag / Best Answer (Smart)
	// c2 := baseConfig
	// c2.Name = "2_RandFlag_BestAns"
	// c2.FlaggingStrategy = verification.FlagRandom
	// c2.AnsweringStrategy = verification.AnswerSmart
	// r2 := runner.RunExperiment(c2)
	// fmt.Print(r2)

	// // 3. Best Flag (Smart) / Random Answer
	// c3 := baseConfig
	// c3.Name = "3_BestFlag_RandAns"
	// c3.FlaggingStrategy = verification.FlagSmart
	// c3.AnsweringStrategy = verification.AnswerRandom
	// r3 := runner.RunExperiment(c3)
	// fmt.Print(r3)

	// // 4. Best Flag (Smart) / Best Answer (Sophisticated)
	// c4 := baseConfig
	// c4.Name = "4_BestFlag_BestAns"
	// c4.FlaggingStrategy = verification.FlagSmart
	// c4.AnsweringStrategy = verification.AnswerSmart
	// r4 := runner.RunExperiment(c4)
	// fmt.Print(r4)

	runner.PrintSummary()
}
