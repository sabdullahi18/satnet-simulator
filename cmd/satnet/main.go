package main

import (
	"fmt"
	// "os"
	//
	// "satnet-simulator/internal/engine"
	"satnet-simulator/internal/experiment"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     SATELLITE NETWORK TRUST VERIFICATION SIMULATOR")
	fmt.Println("     ZKP-Style Questioning with Statistical Analysis")
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("This simulator tests a verification protocol for detecting malicious")
	fmt.Println("delay injection by satellite network providers, using a combination of:")
	fmt.Println("  - Comparison queries to detect transitivity violations")
	fmt.Println("  - Temporal consistency checks")
	fmt.Println("  - Physical constraint verification")
	fmt.Println("  - Bayesian and SPRT statistical analysis")
	fmt.Println()

	runner := experiment.NewRunner()
	baseConfig := experiment.ExperimentConfig{
		NumPackets:  200,
		NumTrials:   20,
		SimDuration: 30.0,
		Paths: []network.SatellitePath{
			{Name: "LEO_FAST", Delay: 0.05, SpikeProb: 0.1, SpikeDelay: 0.5},
			{Name: "LEO_MED", Delay: 0.08, SpikeProb: 0.15, SpikeDelay: 0.8},
			{Name: "GEO_SLOW", Delay: 0.25, SpikeProb: 0.02, SpikeDelay: 0.3},
		},
		PathStrategy: network.StrategyRandom,
		VerificationConfig: verification.VerificationConfig{
			SamplingRate:      0.10,
			MaxQueries:        500,
			TargetConfidence:  0.99,
			QueryStrategy:     verification.StrategyAdaptive,
			MinPhysicalDelay:  0.01,
			MaxJitter:         2.5,
			TemporalTolerance: 0.5,
			PriorHonest:       0.5,
		},
	}

	// ===========================================================================
	// EXPERIMENT 1: Baseline - Honest Network
	// ===========================================================================
	fmt.Println("\n>>> EXPERIMENT 1: Baseline (Honest Network)")
	fmt.Println("    Testing that we don't falsely accuse honest networks")

	honestConfig := baseConfig
	honestConfig.Name = "baseline_honest"
	honestConfig.AdversarialConfig = network.DefaultHonestConfig()
	honestConfig.LyingStrategy = verification.StrategyHonest
	honestConfig.LieProbability = 0.0

	honestResult := runner.RunExperiment(honestConfig)
	fmt.Print(honestResult)

	// // ===========================================================================
	// // EXPERIMENT 2: Varying Delay Fractions
	// // ===========================================================================
	// fmt.Println("\n>>> EXPERIMENT 2: Varying Delay Fractions")
	// fmt.Println("    Testing detection rate at different attack intensities")
	//
	// delayFractions := []float64{0.01, 0.02, 0.05, 0.10, 0.20}
	//
	// for _, fraction := range delayFractions {
	// 	config := baseConfig
	// 	config.Name = fmt.Sprintf("delay_%.0f%%", fraction*100)
	// 	config.AdversarialConfig = network.AdversarialConfig{
	// 		Mode:              network.ModeRandomDelay,
	// 		DelayFraction:     fraction,
	// 		MinMaliciousDelay: 0.5,
	// 		MaxMaliciousDelay: 2.0,
	// 	}
	// 	config.LyingStrategy = verification.StrategySophisticated
	// 	config.LieProbability = 0.8
	//
	// 	result := runner.RunExperiment(config)
	// 	fmt.Printf("  Delay %.0f%%: TPR=%.1f%%, Queries=%.0f\n",
	// 		fraction*100, result.TruePositiveRate*100, result.MeanQueriesPerDetection)
	// }

	// // ===========================================================================
	// // EXPERIMENT 3: Lying Strategy Comparison
	// // ===========================================================================
	// fmt.Println("\n>>> EXPERIMENT 3: Lying Strategy Comparison")
	// fmt.Println("    Testing how different lying strategies affect detection")
	//
	// adversarialConfig := baseConfig
	// adversarialConfig.AdversarialConfig = network.AdversarialConfig{
	// 	Mode:              network.ModeRandomDelay,
	// 	DelayFraction:     0.10,
	// 	MinMaliciousDelay: 0.5,
	// 	MaxMaliciousDelay: 2.0,
	// }
	//
	// strategies := []verification.LyingStrategy{
	// 	verification.StrategyHonest,              // Delays but tells truth (catches itself)
	// 	verification.StrategyAlwaysClaimShortest, // Naive lying
	// 	verification.StrategyRandomLies,          // Random lying
	// 	verification.StrategySophisticated,       // Tries to be consistent
	// 	verification.StrategyTargeted,            // Lies about specific packets
	// }
	//
	// for _, strategy := range strategies {
	// 	config := adversarialConfig
	// 	config.Name = fmt.Sprintf("strategy_%s", strategy)
	// 	config.LyingStrategy = strategy
	// 	config.LieProbability = 0.7
	//
	// 	result := runner.RunExperiment(config)
	// 	fmt.Printf("  %s: TPR=%.1f%%, Queries=%.0f\n",
	// 		strategy, result.TruePositiveRate*100, result.MeanQueriesPerDetection)
	// }

	//		// ===========================================================================
	//		// EXPERIMENT 4: Sampling Rate Impact
	//		// ===========================================================================
	//		fmt.Println("\n>>> EXPERIMENT 4: Sampling Rate Impact")
	//		fmt.Println("    Testing how sampling rate affects detection")
	//
	//		samplingRates := []float64{0.01, 0.05, 0.10, 0.20}
	//
	//		for _, rate := range samplingRates {
	//			config := adversarialConfig
	//			config.Name = fmt.Sprintf("sampling_%.0f%%", rate*100)
	//			config.VerificationConfig.SamplingRate = rate
	//			config.LyingStrategy = verification.StrategySophisticated
	//			config.LieProbability = 0.7
	//
	//			result := runner.RunExperiment(config)
	//			fmt.Printf("  Sampling %.0f%%: TPR=%.1f%%, Sampled=%d, Queries=%.0f\n",
	//				rate*100, result.TruePositiveRate*100,
	//				int(float64(config.NumPackets)*rate),
	//				result.MeanQueriesPerDetection)
	//		}
	//
	//		// ===========================================================================
	//		// EXPERIMENT 5: Query Strategy Comparison
	//		// ===========================================================================
	//		fmt.Println("\n>>> EXPERIMENT 5: Query Strategy Comparison")
	//		fmt.Println("    Testing different query generation strategies")
	//
	//		queryStrategies := []verification.QueryStrategy{
	//			verification.StrategyRandom,
	//			verification.StrategyTargetedQuery,
	//			verification.StrategyAdaptive,
	//		}
	//
	//		for _, qstrat := range queryStrategies {
	//			config := adversarialConfig
	//			config.Name = fmt.Sprintf("query_%s", qstrat)
	//			config.VerificationConfig.QueryStrategy = qstrat
	//			config.LyingStrategy = verification.StrategySophisticated
	//			config.LieProbability = 0.7
	//
	//			result := runner.RunExperiment(config)
	//			fmt.Printf("  %s: TPR=%.1f%%, Queries=%.0f\n",
	//				qstrat, result.TruePositiveRate*100, result.MeanQueriesPerDetection)
	//		}
	//
	//		// ===========================================================================
	//		// SUMMARY
	//		// ===========================================================================
	//		runner.PrintSummary()
	//
	//		// ===========================================================================
	//		// EXPORT RESULTS
	//		// ===========================================================================
	//		csv := runner.GenerateCSV()
	//		err := os.WriteFile("results.csv", []byte(csv), 0644)
	//		if err != nil {
	//			fmt.Printf("Warning: Could not write results.csv: %v\n", err)
	//		} else {
	//			fmt.Println("\nResults exported to results.csv")
	//		}
	//
	//		// ===========================================================================
	//		// DETAILED DEMO
	//		// ===========================================================================
	//		fmt.Println("\n================================================================================")
	//		fmt.Println("                        DETAILED DEMO")
	//		fmt.Println("================================================================================")
	//		runDetailedDemo()
	//	}
	//
	//	func runDetailedDemo() {
	//		fmt.Println("\nRunning detailed demo with verbose output...")
	//		fmt.Println()
	//
	//		config := experiment.ExperimentConfig{
	//			Name:        "detailed_demo",
	//			NumPackets:  50,
	//			NumTrials:   1,
	//			SimDuration: 15.0,
	//			Paths: []network.SatellitePath{
	//				{Name: "LEO", Delay: 0.05, SpikeProb: 0.1, SpikeDelay: 0.5},
	//				{Name: "GEO", Delay: 0.25, SpikeProb: 0.02, SpikeDelay: 0.3},
	//			},
	//			PathStrategy: network.StrategyRandom,
	//			AdversarialConfig: network.AdversarialConfig{
	//				Mode:              network.ModeRandomDelay,
	//				DelayFraction:     0.15,
	//				MinMaliciousDelay: 1.0,
	//				MaxMaliciousDelay: 3.0,
	//			},
	//			LyingStrategy:  verification.StrategySophisticated,
	//			LieProbability: 0.8,
	//			VerificationConfig: verification.VerificationConfig{
	//				SamplingRate:      0.20,
	//				MaxQueries:        100,
	//				TargetConfidence:  0.95,
	//				QueryStrategy:     verification.StrategyAdaptive,
	//				MinPhysicalDelay:  0.01,
	//				MaxJitter:         2.5,
	//				TemporalTolerance: 0.5,
	//				PriorHonest:       0.5,
	//			},
	//		}
	//
	//		sim := engine.NewSimulation()
	//		router := network.NewVerifiableRouter(config.Paths, config.AdversarialConfig)
	//		shortestPath, shortestDelay := router.GetShortestPath()
	//
	//		oracle := verification.NewNetworkOracle(
	//			config.LyingStrategy,
	//			config.LieProbability,
	//			shortestPath,
	//			shortestDelay,
	//		)
	//
	//		dest := experiment.NewMockGroundStation("Dest")
	//
	//		transmissions := make([]verification.TransmissionRecord, 0)
	//
	//		router.OnTransmission = func(info network.TransmissionInfo) {
	//			record := verification.TransmissionRecord{
	//				PacketID:       info.PacketID,
	//				SentTime:       info.SentTime,
	//				ReceivedTime:   info.ReceivedTime,
	//				PathUsed:       info.PathUsed,
	//				PathDelay:      info.PathBaseDelay,
	//				MinDelay:       info.MinDelay,
	//				ActualDelay:    info.ActualDelay,
	//				MaliciousDelay: info.MaliciousDelay,
	//				IsShortestPath: info.IsShortestPath,
	//				WasDelayed:     info.WasDelayed,
	//			}
	//			oracle.RecordTransmission(record)
	//			transmissions = append(transmissions, record)
	//
	//			if info.WasDelayed {
	//				fmt.Printf("  [DELAYED] Packet %d: malicious_delay=%.2fs, total=%.2fs\n",
	//					info.PacketID, info.MaliciousDelay, info.ActualDelay)
	//			}
	//		}
	//
	//		fmt.Println("=== TRANSMISSION PHASE ===")
	//		for i := 0; i < config.NumPackets; i++ {
	//			pktID := i
	//			sendTime := float64(i) * 0.3
	//
	//			sim.Schedule(sendTime, func() {
	//				pkt := network.NewPacket(pktID, "Source", sim.Now)
	//				router.Forward(sim, pkt, dest, config.PathStrategy)
	//			})
	//		}
	//
	//		sim.Run(config.SimDuration + 10.0)
	//
	//		fmt.Printf("\nTransmission complete: %d packets, %d delayed\n",
	//			router.PacketsRouted, router.PacketsDelayed)
	//
	//		fmt.Println("\n=== VERIFICATION PHASE ===")
	//
	//		verifier := verification.NewVerifier(oracle, config.VerificationConfig)
	//		for _, p := range config.Paths {
	//			isShortest := p.Name == shortestPath
	//			verifier.AddPathInfo(p.Name, p.Delay, isShortest)
	//		}
	//
	//		verifier.IngestRecords(transmissions)
	//
	//		fmt.Printf("Sampled %d packets for verification\n", len(verifier.SampledIDs))
	//
	//		result := verifier.RunVerification(sim.Now)
	//
	//		fmt.Print(result)
	//
	//		fmt.Println("\n=== PROBABILITY MODEL ===")
	//		model := verification.NewProbabilityModel(router.PacketsDelayed, router.PacketsRouted, 0.3)
	//		fmt.Println(model.Summary())
	//		fmt.Printf("Queries needed for 95%% confidence: %d\n", model.QueriesNeededForConfidence(0.95))
	//		fmt.Printf("Queries needed for 99%% confidence: %d\n", model.QueriesNeededForConfidence(0.99))
}
