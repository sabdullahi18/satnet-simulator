package main

import (
	"fmt"
	"math/rand"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/nodes"
	"satnet-simulator/internal/verification"
)

func main() {
	// Seed random for reproducibility during testing
	// Remove or change for production runs
	rand.Seed(time.Now().UnixNano())

	fmt.Println("==============================================")
	fmt.Println("   SATELLITE NETWORK TRUST VERIFICATION")
	fmt.Println("==============================================")
	fmt.Println()

	// Run multiple scenarios
	runScenario("HONEST_NETWORK", verification.StrategyHonest, 0.0)
	runScenario("ALWAYS_LIES_ABOUT_SHORTEST_PATH", verification.StrategyAlwaysClaimShortest, 0.0)
	runScenario("RANDOM_LIES_30%", verification.StrategyRandomLies, 0.3)
	runScenario("MINIMIZE_DELAY_LIES", verification.StrategyMinimizeDelay, 0.0)
	runScenario("SMART_LIAR", verification.StrategySmart, 0.5)
}

func runScenario(name string, strategy verification.LyingStrategy, lieProb float64) {
	fmt.Printf("\n########################################\n")
	fmt.Printf("# SCENARIO: %s\n", name)
	fmt.Printf("########################################\n\n")

	// Create simulation
	sim := engine.NewSimulation()

	// Define satellite paths
	pathLEO := network.SatellitePath{
		Name:       "path_leo_fast",
		Delay:      0.1,  // 100ms base delay (LEO)
		SpikeProb:  0.3,  // 30% chance of delay spike
		SpikeDelay: 2.0,  // 2 second spike
	}

	pathGEO := network.SatellitePath{
		Name:       "path_geo_slow",
		Delay:      0.8,  // 800ms base delay (GEO)
		SpikeProb:  0.0,  // No spikes (more reliable)
		SpikeDelay: 0.0,
	}

	paths := []network.SatellitePath{pathLEO, pathGEO}

	// Create verifiable router with RANDOM path selection
	// This is key: we randomly choose paths to test if network reports correctly
	router := network.NewVerifiableRouter(paths, network.StrategyRandom)

	// Create oracle (network's interface that may lie)
	shortestPath, shortestDelay := router.GetShortestPath()
	oracle := verification.NewNetworkOracle(strategy, lieProb, shortestPath, shortestDelay)

	// Set up path info for verifier
	pathInfos := []verification.PathInfo{
		{Name: pathLEO.Name, BaseDelay: pathLEO.Delay, IsShortest: true},
		{Name: pathGEO.Name, BaseDelay: pathGEO.Delay, IsShortest: false},
	}

	// Create verifier BEFORE transmission so it can record ground truth
	verifier := verification.NewVerifier(oracle, pathInfos, 0.05, 2.5) // min delay, max jitter

	// Connect router to record ground truth to BOTH oracle and verifier
	// The verifier controls path selection, so it knows the truth
	// The oracle gets a copy but may lie when queried
	router.OnTransmission = func(info network.TransmissionInfo) {
		record := verification.TransmissionRecord{
			PacketID:       info.PacketID,
			SentTime:       info.SentTime,
			ReceivedTime:   info.ReceivedTime,
			PathUsed:       info.PathUsed,
			PathDelay:      info.PathBaseDelay,
			ActualDelay:    info.ActualDelay,
			IsShortestPath: info.IsShortestPath,
		}
		// Oracle gets the truth (but may lie when answering)
		oracle.RecordTransmission(record)
		// Verifier also knows the truth (for verification)
		verifier.RecordGroundTruth(record)
	}

	// Create ground stations
	stationA := &nodes.GroundStation{Name: "StationA", Router: (*network.SatNetRouter)(nil)}
	stationB := &nodes.GroundStation{Name: "StationB", Router: (*network.SatNetRouter)(nil)}

	// We'll create our own send function that uses the verifiable router
	numPackets := 100 // Send 100 packets for statistical significance

	fmt.Printf("Sending %d packets between stations using RANDOM path selection...\n", numPackets)
	fmt.Println("(This simulates the verifier not knowing which path will be used)")
	fmt.Println()

	// Schedule packet sends from A to B
	for i := 0; i < numPackets; i++ {
		pktID := i
		sendTime := float64(i) * 0.2 // Send every 200ms

		sim.Schedule(sendTime, func() {
			pkt := network.NewPacket(pktID, stationA.Name, sim.Now)
			fmt.Printf("[%.2fs] %s SENT pkt %d\n", sim.Now, stationA.Name, pkt.ID)
			router.Forward(sim, pkt, stationB)
		})
	}

	// Run simulation
	sim.Run(30.0)

	fmt.Println()
	fmt.Println("=== TRANSMISSION PHASE COMPLETE ===")
	fmt.Printf("Recorded %d transmissions\n", len(oracle.GroundTruth))
	fmt.Println()

	// Now run verification
	fmt.Println("=== VERIFICATION PHASE ===")
	fmt.Println("Interrogating the network about its behavior...")
	fmt.Println()

	// Create time intervals to query
	intervals := []verification.TimeInterval{
		{Start: 0.0, End: 5.0},
		{Start: 5.0, End: 10.0},
		{Start: 10.0, End: 15.0},
		{Start: 15.0, End: 20.0},
	}

	// Run verification: interrogate packets in each interval
	result := verifier.RunVerification(intervals, numPackets, sim.Now)

	// Print results
	fmt.Println(result)

	// Summary
	if result.Trustworthy {
		fmt.Println(">>> CONCLUSION: Network appears trustworthy (no contradictions detected)")
	} else {
		fmt.Println(">>> CONCLUSION: Network is LYING! Contradictions detected!")
		fmt.Printf(">>> Found %d contradictions in %d queries\n", result.ContradictionsFound, result.TotalQueries)
	}
}
