package main

import (
	"fmt"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/nodes"
	"satnet-simulator/internal/verification"
)

func main() {
	fmt.Println("==============================================")
	fmt.Println("   SATELLITE NETWORK TRUST VERIFICATION")
	fmt.Println("==============================================")
	fmt.Println()
	fmt.Println("The verifier doesn't have access to the ground truth")
	fmt.Println("It can only detect lies through internal contradictions in the network's own responses")

	// runScenario("HONEST_NETWORK", verification.StrategyHonest, 0.0, true)
	runScenario("ALWAYS_LIES_ABOUT_SHORTEST_PATH", verification.StrategyAlwaysClaimShortest, 0.0, true)
	// runScenario("RANDOM_LIES_30%", verification.StrategyRandomLies, 0.3, true)
	// runScenario("MINIMIZE_DELAY_LIES", verification.StrategyMinimiseDelay, 0.0, true)
	// runScenario("SMART_LIAR", verification.StrategySmart, 0.5, true)

}

func runScenario(name string, strategy verification.LyingStrategy, lieProb float64, showGroundTruth bool) {
	fmt.Printf("\n########################################\n")
	fmt.Printf("# SCENARIO: %s\n", name)
	fmt.Printf("########################################\n\n")

	sim := engine.NewSimulation()

	pathLEO := network.SatellitePath{
		Name:       "path_leo_fast",
		Delay:      0.1,
		SpikeProb:  0.3,
		SpikeDelay: 2.0,
	}

	pathGEO := network.SatellitePath{
		Name:       "path_geo_slow",
		Delay:      0.8,
		SpikeProb:  0.0,
		SpikeDelay: 0.0,
	}

	paths := []network.SatellitePath{pathLEO, pathGEO}
	router := network.NewVerifiableRouter(paths, network.StrategyRandom)
	shortestPath, shortestDelay := router.GetShortestPath()
	oracle := verification.NewNetworkOracle(strategy, lieProb, shortestPath, shortestDelay)

	pathInfos := []verification.PathInfo{
		{Name: pathLEO.Name, BaseDelay: pathLEO.Delay, IsShortest: true},
		{Name: pathGEO.Name, BaseDelay: pathGEO.Delay, IsShortest: false},
	}

	verifier := verification.NewVerifier(oracle, pathInfos, 0.05, 2.5) // min delay, max jitter

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
		oracle.RecordTransmission(record)
		pathHash := verification.HashPath(info.PathUsed)
		verifier.RecordPathCommitment(info.PacketID, pathHash, info.SentTime)
		verifier.RecordGroundTruth(record)
	}

	stationA := &nodes.GroundStation{Name: "StationA", Router: (*network.VerifiableRouter)(nil)}
	stationB := &nodes.GroundStation{Name: "StationB", Router: (*network.VerifiableRouter)(nil)}
	numPackets := 100

	fmt.Printf("Sending %d packets between stations using RANDOM path selection...\n", numPackets)
	fmt.Println("(This simulates the verifier not knowing which path will be used)")
	fmt.Println()

	for i := range numPackets {
		pktID := i
		sendTime := float64(i) * 0.2

		sim.Schedule(sendTime, func() {
			pkt := network.NewPacket(pktID, stationA.Name, sim.Now)
			fmt.Printf("[%.2fs] %s SENT pkt %d\n", sim.Now, stationA.Name, pkt.ID)
			router.Forward(sim, pkt, stationB)
		})
	}

	sim.Run(30.0)

	fmt.Println()
	fmt.Println("=== TRANSMISSION PHASE COMPLETE ===")
	fmt.Printf("Recorded %d transmissions\n", len(oracle.GroundTruth))
	fmt.Println()

	fmt.Println("=== VERIFICATION PHASE ===")
	fmt.Println("Interrogating the network about its behaviour...")
	fmt.Println()

	intervals := []verification.TimeInterval{
		{Start: 0.0, End: 5.0},
		{Start: 5.0, End: 10.0},
		{Start: 10.0, End: 15.0},
		{Start: 15.0, End: 20.0},
	}

	result := verifier.RunVerification(intervals, numPackets, sim.Now)
	fmt.Println(result)

	if result.Trustworthy {
		fmt.Println(">>> CONCLUSION: Network appears trustworthy (no contradictions detected)")
	} else {
		fmt.Println(">>> CONCLUSION: Network is LYING! Contradictions detected!")
		fmt.Printf(">>> Found %d contradictions in %d queries\n", result.ContradictionsFound, result.TotalQueries)
	}
	if showGroundTruth {
		fmt.Println(verifier.GetDebugReport())
	}
}
