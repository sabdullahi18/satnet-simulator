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

	// Run the enhanced scenario with subpath verification and probe packets
	runEnhancedScenario("SMART_LIAR_WITH_PROBES", verification.StrategySmart, 0.5)
}

// runEnhancedScenario demonstrates the full verification system with subpaths and probes
func runEnhancedScenario(name string, strategy verification.LyingStrategy, lieProb float64) {
	fmt.Printf("\n########################################\n")
	fmt.Printf("# SCENARIO: %s\n", name)
	fmt.Printf("########################################\n\n")

	sim := engine.NewSimulation()

	// Create detailed path topology with subpaths
	topology := network.NewPathTopology()
	leoPath := topology.CreateDetailedLEOPath("path_leo_fast")
	geoPath := topology.CreateDetailedGEOPath("path_geo_slow")

	fmt.Println("=== PATH TOPOLOGY ===")
	fmt.Printf("LEO Path: %s\n", leoPath.Name)
	fmt.Printf("  Hops: %d, Total Delay: %.4fs\n", len(leoPath.SubPaths), leoPath.TotalDelay)
	fmt.Printf("  Merkle Root: %s\n", leoPath.ComputeMerkleRoot())
	for i, sp := range leoPath.SubPaths {
		fmt.Printf("    [%d] %s -> %s (%.4fs) hash=%s\n", i, sp.FromNode, sp.ToNode, sp.LinkDelay, sp.ComputeHash())
	}

	fmt.Printf("\nGEO Path: %s\n", geoPath.Name)
	fmt.Printf("  Hops: %d, Total Delay: %.4fs\n", len(geoPath.SubPaths), geoPath.TotalDelay)
	fmt.Printf("  Merkle Root: %s\n", geoPath.ComputeMerkleRoot())
	for i, sp := range geoPath.SubPaths {
		fmt.Printf("    [%d] %s -> %s (%.4fs) hash=%s\n", i, sp.FromNode, sp.ToNode, sp.LinkDelay, sp.ComputeHash())
	}
	fmt.Println()

	// Standard paths for router (backwards compatibility)
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

	verifier := verification.NewVerifier(oracle, pathInfos, 0.05, 2.5)

	// Create probe manager for injecting verification probes
	probeManager := verification.NewProbeManager(topology)

	// Track transmissions
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

		// If this is a probe packet, record the result
		if probe := probeManager.GetProbe(info.PacketID); probe != nil {
			result := &verification.ProbeResult{
				Probe:        probe,
				ReceivedTime: info.ReceivedTime,
				ActualDelay:  info.ActualDelay,
				ReportedPath: info.PathUsed,
			}

			// Check if path matches forced path
			if probe.ForcedPath != "" {
				result.PathMatchesForced = (info.PathUsed == probe.ForcedPath)
				if !result.PathMatchesForced {
					result.AddIssue(fmt.Sprintf("Forced path violation: expected %s, got %s", probe.ForcedPath, info.PathUsed))
				}
			}

			// Check timing bounds
			if probe.ExpectedMinDelay > 0 && info.ActualDelay < probe.ExpectedMinDelay {
				result.AddIssue(fmt.Sprintf("Timing violation: %.4fs < min %.4fs", info.ActualDelay, probe.ExpectedMinDelay))
			}

			probeManager.RecordResult(info.PacketID, result)
		}
	}

	stationA := &nodes.GroundStation{Name: "StationA", Router: (*network.VerifiableRouter)(nil)}
	stationB := &nodes.GroundStation{Name: "StationB", Router: (*network.VerifiableRouter)(nil)}
	numPackets := 100

	fmt.Println("=== TRANSMISSION PHASE ===")
	fmt.Printf("Sending %d regular packets + probe packets...\n\n", numPackets)

	// Schedule regular packets
	for i := range numPackets {
		pktID := i
		sendTime := float64(i) * 0.2

		sim.Schedule(sendTime, func() {
			pkt := network.NewPacket(pktID, stationA.Name, sim.Now)
			fmt.Printf("[%.2fs] %s SENT pkt %d\n", sim.Now, stationA.Name, pkt.ID)
			router.Forward(sim, pkt, stationB)
		})
	}

	// Schedule probe packets - these force specific paths for verification
	probeSchedule := probeManager.CreateProbeSchedule(1.0, 15.0, 3.0, []string{"path_leo_fast", "path_geo_slow"})
	fmt.Printf("\n=== PROBE INJECTION ===\n")
	fmt.Printf("Scheduling %d probe packets to verify path behavior...\n\n", len(probeSchedule.Probes))

	for _, probe := range probeSchedule.Probes {
		p := probe // capture for closure
		sim.Schedule(p.SentTime, func() {
			pkt := network.NewPacket(p.ID, stationA.Name, sim.Now)
			fmt.Printf("[%.2fs] PROBE %d SENT (forced path: %s, expected delay: %.4f-%.4fs)\n",
				sim.Now, p.ID, p.ForcedPath, p.ExpectedMinDelay, p.ExpectedMaxDelay)
			router.Forward(sim, pkt, stationB)
		})
	}

	sim.Run(30.0)

	fmt.Println()
	fmt.Println("=== TRANSMISSION PHASE COMPLETE ===")
	fmt.Printf("Recorded %d transmissions\n", len(oracle.GroundTruth))
	fmt.Println()

	// Analyze probe results
	fmt.Println("=== PROBE ANALYSIS ===")
	probeContradictions := probeManager.AnalyseResults()
	fmt.Println(probeManager.Summary())
	if len(probeContradictions) > 0 {
		fmt.Printf("Probe contradictions found: %d\n", len(probeContradictions))
		for _, pc := range probeContradictions {
			fmt.Printf("  - %s\n", pc)
		}
	} else {
		fmt.Println("No probe contradictions detected")
	}
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

	// Demonstrate Merkle proof verification
	fmt.Println("=== MERKLE PROOF DEMONSTRATION ===")
	proof := leoPath.GenerateMerkleProof(1) // Prove subpath 1 (leo_1 -> leo_2)
	if proof != nil {
		fmt.Printf("Generated proof for subpath %d (hash: %s)\n", proof.SubPathIndex, proof.SubPathHash)
		fmt.Printf("  Siblings: %v\n", proof.Siblings)
		fmt.Printf("  Positions: %v\n", proof.Positions)
		verified := network.VerifyMerkleProof(proof, leoPath.ComputeMerkleRoot())
		fmt.Printf("  Verification against Merkle root: %v\n", verified)
	}
	fmt.Println()

	// Final conclusion
	totalContradictions := result.ContradictionsFound + len(probeContradictions)
	if totalContradictions == 0 {
		fmt.Println(">>> CONCLUSION: Network appears trustworthy (no contradictions detected)")
	} else {
		fmt.Println(">>> CONCLUSION: Network is LYING! Contradictions detected!")
		fmt.Printf(">>> Found %d query contradictions + %d probe contradictions = %d total\n",
			result.ContradictionsFound, len(probeContradictions), totalContradictions)
	}
}

// runScenario is the original scenario without probes (kept for reference)
func runScenario(name string, strategy verification.LyingStrategy, lieProb float64) {
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

	verifier := verification.NewVerifier(oracle, pathInfos, 0.05, 2.5)

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
}
