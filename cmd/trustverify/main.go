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
	fmt.Println("The verifier does NOT have access to ground truth.")
	fmt.Println("It can only detect lies through INTERNAL CONTRADICTIONS")
	fmt.Println("in the network's own responses.")
	fmt.Println()

	// Run multiple scenarios
	runScenario("HONEST_NETWORK", verification.StrategyHonest, 0.0, false)
	runScenario("ALWAYS_LIES_ABOUT_SHORTEST_PATH", verification.StrategyAlwaysClaimShortest, 0.0, true)
	runScenario("RANDOM_LIES_30%", verification.StrategyRandomLies, 0.3, true)
	runScenario("MINIMIZE_DELAY_LIES", verification.StrategyMinimizeDelay, 0.0, true)
	runScenario("SMART_LIAR", verification.StrategySmart, 0.5, true)
}

func runScenario(name string, strategy verification.LyingStrategy, lieProb float64, showDebug bool) {
	fmt.Printf("\n########################################\n")
	fmt.Printf("# SCENARIO: %s\n", name)
	fmt.Printf("########################################\n\n")

	// Create simulation
	sim := engine.NewSimulation()

	// Define satellite paths (publicly known information)
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
	router := network.NewVerifiableRouter(paths, network.StrategyRandom)

	// Create oracle (network's interface that may lie)
	shortestPath, shortestDelay := router.GetShortestPath()
	oracle := verification.NewNetworkOracle(strategy, lieProb, shortestPath, shortestDelay)

	// Set up path info for verifier (publicly known)
	pathInfos := []verification.PathInfo{
		{Name: pathLEO.Name, BaseDelay: pathLEO.Delay, IsShortest: true},
		{Name: pathGEO.Name, BaseDelay: pathGEO.Delay, IsShortest: false},
	}

	// Create verifier
	verifier := verification.NewVerifier(oracle, pathInfos, 0.05, 2.5) // min delay, max jitter

	// Connect router to record:
	// 1. Hash commitment (what the verifier receives - can't see actual path)
	// 2. Ground truth to oracle (so oracle knows what actually happened)
	// 3. Debug ground truth (for analysis only, NOT used in verification)
	router.OnTransmission = func(info network.TransmissionInfo) {
		// Oracle needs the truth to know what lies to tell
		record := verification.TransmissionRecord{
			PacketID:       info.PacketID,
			SentTime:       info.SentTime,
			ReceivedTime:   info.ReceivedTime,
			PathUsed:       info.PathUsed,
			PathDelay:      info.PathBaseDelay,
			ActualDelay:    info.ActualDelay,
			IsShortestPath: info.IsShortestPath,
		}
		oracle.RecordTransmission(record)

		// Verifier receives a HASH commitment from the network
		// This is like getting a sealed envelope - can't see the path, but can verify later
		pathHash := verification.HashPath(info.PathUsed)
		verifier.RecordPathCommitment(info.PacketID, pathHash, info.SentTime)

		// DEBUG ONLY: Record ground truth for analysis (NOT used in verification!)
		verifier.RecordDebugGroundTruth(record)
	}

	// Create ground stations
	stationA := &nodes.GroundStation{Name: "StationA", Router: (*network.SatNetRouter)(nil)}
	stationB := &nodes.GroundStation{Name: "StationB", Router: (*network.SatNetRouter)(nil)}

	// We'll create our own send function that uses the verifiable router
	numPackets := 100 // Send 100 packets for statistical significance

	fmt.Printf("Sending %d packets between stations...\n", numPackets)
	fmt.Println("Network provides hash commitments for each packet (path hidden)")
	fmt.Println()

	// Schedule packet sends from A to B
	for i := 0; i < numPackets; i++ {
		pktID := i
		sendTime := float64(i) * 0.2 // Send every 200ms

		sim.Schedule(sendTime, func() {
			pkt := network.NewPacket(pktID, stationA.Name, sim.Now)
			router.Forward(sim, pkt, stationB)
		})
	}

	// Run simulation (quieter output)
	sim.Run(30.0)

	fmt.Println()
	fmt.Printf("Transmitted %d packets, received %d hash commitments\n",
		len(oracle.GroundTruth), len(verifier.PathCommitments))
	fmt.Println()

	// Now run verification
	fmt.Println("=== VERIFICATION PHASE ===")
	fmt.Println("Interrogating the network about its behavior...")
	fmt.Println("(Checking for internal contradictions only)")
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
		fmt.Println(">>> CONCLUSION: Network contradicted itself!")
		fmt.Printf(">>> Found %d contradictions in %d queries\n", result.ContradictionsFound, result.TotalQueries)
	}

	// Show debug report for lying scenarios
	if showDebug {
		fmt.Println(verifier.GetDebugReport())
	}
}
