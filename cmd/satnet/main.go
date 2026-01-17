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

	// runEnhancedScenario("HONEST", verification.StrategyHonest, 0.0)
	// runEnhancedScenario("SMART_LIAR", verification.StrategySmart, 0.5)
}

func runEnhancedScenario(name string, strategy verification.LyingStrategy, lieProb float64) {
	fmt.Printf("\n########################################\n")
	fmt.Printf("# SCENARIO: %s\n", name)
	fmt.Printf("########################################\n\n")

	sim := engine.NewSimulation()
	topology := network.NewPathTopology()
	leoPath := topology.CreateDetailedLEOPath("path_leo_fast")
	geoPath := topology.CreateDetailedGEOPath("path_geo_slow")

	fmt.Println("=== PATH TOPOLOGY ===")
	fmt.Printf("LEO path: %s\n", leoPath.Name)
	fmt.Printf("    Hops: %d, Total Delay: %.4fs\n", len(leoPath.SubPaths), leoPath.TotalDelay)
	fmt.Printf("    Merkle Root: %s\n", leoPath.ComputeMerkleRoot())
	for i, sp := range leoPath.SubPaths {
		fmt.Printf("    [%d] %s -> %s (%.4fs) hash=%s\n", i, sp.FromNode, sp.ToNode, sp.LinkDelay, sp.ComputeHash())
	}

	fmt.Printf("GEO path: %s\n", geoPath.Name)
	fmt.Printf("    Hops: %d, Total Delay: %.4fs\n", len(geoPath.SubPaths), geoPath.TotalDelay)
	fmt.Printf("    Merkle Root: %s\n", geoPath.ComputeMerkleRoot())
	for i, sp := range geoPath.SubPaths {
		fmt.Printf("    [%d] %s -> %s (%.4fs) hash=%s\n", i, sp.FromNode, sp.ToNode, sp.LinkDelay, sp.ComputeHash())
	}
	fmt.Println()

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

	// pathInfos := []verification.PathInfo{
	// 	{Name: pathLEO.Name, BaseDelay: pathLEO.Delay, IsShortest: true},
	// 	{Name: pathGEO.Name, BaseDelay: pathGEO.Delay, IsShortest: false},
	// }

	// verifier := verification.NewVerifier(oracle, pathInfos, 0.05, 2.5) // min delay, max jitter
	probeManager := verification.NewProbeManager(topology)

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
		// pathHash := verification.HashPath(info.PathUsed)
		// verifier.RecordPathCommitment(info.PacketID, pathHash, info.SentTime)
		// verifier.RecordGroundTruth(record)

		if probe := probeManager.GetProbe(info.PacketID); probe != nil {
			result := &verification.ProbeResult{
				Probe:        probe,
				ReceivedTime: info.ReceivedTime,
				ActualDelay:  info.ActualDelay,
				ReportedPath: info.PathUsed,
			}

			if probe.ForcedPath != "" {
				result.PathMatchesForced = (info.PathUsed == probe.ForcedPath)
			}

			if probe.ExpectedMinDelay > 0 && info.ActualDelay < probe.ExpectedMinDelay {
				result.AddIssue(fmt.Sprintf("Timing violation: %.4fs < min expected %.4fs for path %s", info.ActualDelay, probe.ExpectedMinDelay, info.PathUsed))
			}

			probeManager.RecordResult(info.PacketID, result)
		}
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

	probeSchedule := probeManager.CreateProbeSchedule(1.0, 15.0, 3.0, []string{"path_leo_fast", "path_geo_slow"})
	fmt.Printf("\n=== PROBE INJECCTION ===")
	fmt.Println("Probe packets are routed on FORCED paths to verify path-specific behavior.")
	fmt.Println("Unlike regular packets, probes specify exactly which path to use.")
	fmt.Printf("Scheduling %d probe packets to verify path behaviour ...\n\n", len(probeSchedule.Probes))

	for _, probe := range probeSchedule.Probes {
		p := probe
		sim.Schedule(p.SentTime, func() {
			pkt := network.NewPacket(p.ID, stationA.Name, sim.Now)
			fmt.Printf("[%.2fs] PROBE %d SENT (forced path: %s, expected delay: %.4f-%.4fs)\n", sim.Now, p.ID, p.ForcedPath, p.ExpectedMinDelay, p.ExpectedMaxDelay)
			router.ForwardOnPath(sim, pkt, stationB, p.ForcedPath)
		})
	}

	sim.Run(30.0)

	fmt.Println()
	fmt.Println("=== TRANSMISSION PHASE COMPLETE ===")
	fmt.Printf("Recorded %d transmissions (including %d probes)\n", len(oracle.GroundTruth), len(probeSchedule.Probes))
	fmt.Println()

	fmt.Println("=== PROBE ANALYSIS ===")
	probeContradictions := probeManager.AnalyseResults()
	fmt.Println(probeManager.Summary())

	// Show detailed probe results
	for probeID := range probeManager.GetAllProbes() {
		probe := probeManager.GetProbe(probeID)
		result := probeManager.GetResult(probeID)
		if result == nil {
			fmt.Printf("  Probe %d: NO RESULT (packet may have been lost)\n", probeID)
			continue
		}

		status := "OK"
		if result.HasIssues() || result.ReportedPath != probe.ForcedPath {
			status = "ISSUE"
		}

		fmt.Printf("  Probe %d [%s]: forced=%s, actual=%s, delay=%.4fs\n",
			probeID, status, probe.ForcedPath, result.ReportedPath, result.ActualDelay)

		if result.ReportedPath != probe.ForcedPath {
			fmt.Printf("    -> WARNING: Router did not respect forced path!\n")
		}
		for _, issue := range result.Issues {
			fmt.Printf("    -> %s\n", issue)
		}
	}

	if len(probeContradictions) > 0 {
		fmt.Printf("Probe contradictions found: %d\n", len(probeContradictions))
		for _, pc := range probeContradictions {
			fmt.Printf("    - %s\n", pc)
		}
	} else {
		fmt.Println("No probe contradictions detected")
	}
	fmt.Println()

	fmt.Println("=== VERIFICATION PHASE ===")
	fmt.Println("Interrogating the network about its behaviour...")
	fmt.Println()

	// intervals := []verification.TimeInterval{
	// 	{Start: 0.0, End: 5.0},
	// 	{Start: 5.0, End: 10.0},
	// 	{Start: 10.0, End: 15.0},
	// 	{Start: 15.0, End: 20.0},
	// }

	// result := verifier.RunVerification(intervals, numPackets, sim.Now)
	// fmt.Println(result)

	fmt.Println("=== MERKLE PROOF DEMONSTRATION ===")
	proof := leoPath.GenerateMerkleProof(1)
	if proof != nil {
		fmt.Printf("Generated proof for LEO subpath %d: %s -> %s\n",
			proof.SubPathIndex, leoPath.SubPaths[1].FromNode, leoPath.SubPaths[1].ToNode)
		fmt.Printf("  SubPath Hash: %s\n", proof.SubPathHash)

		fmt.Printf("    Siblings: %v\n", proof.Siblings)
		fmt.Printf("    Positions: %v\n", proof.Positions)
		verified := network.VerifyMerkleProof(proof, leoPath.ComputeMerkleRoot())
		fmt.Printf("   Verification against Merkle root: %v\n", verified)
	}
	fmt.Println()

	fmt.Println("=== FINAL CONCLUSION ===")
	// totalContradictions := result.ContradictionsFound + len(probeContradictions)
	// if totalContradictions == 0 {
	// 	fmt.Println(">>> CONCLUSION: Network appears trustworthy (no contradictions detected)")
	// } else {
	// 	fmt.Println(">>> CONCLUSION: Network is LYING! Contradictions detected!")
	// 	fmt.Printf(">>> Found %d query contradictions + %d probe contradictions = %d total\n", result.ContradictionsFound, len(probeContradictions), totalContradictions)
	// }
}
