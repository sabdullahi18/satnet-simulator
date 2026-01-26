package main

import (
	"fmt"
	"satnet-simulator/internal/verification"
)

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     NAIVE STRATEGIES DEMONSTRATION")
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("This demo shows the two key adversarial strategy dimensions:")
	fmt.Println("  Strategy 1 (Flagging): Which packets does SNP claim had congestion?")
	fmt.Println("  Strategy 2 (Answering): How does SNP answer comparison queries?")
	fmt.Println()

	records := generateSampleRecords()

	fmt.Println("=== GROUND TRUTH (Simulated Transmissions) ===")
	fmt.Println("PacketID | Sent   | MinDelay | ActualDelay | WasDelayed")
	fmt.Println("---------------------------------------------------------")
	for _, rec := range records {
		delayed := "  "
		if rec.WasDelayed {
			delayed = "**"
		}
		fmt.Printf("   %2d    | %5.2f  |  %5.3f   |    %5.3f    |    %s\n",
			rec.PacketID, rec.SentTime, rec.MinDelay, rec.ActualDelay, delayed)
	}
	fmt.Println()
	fmt.Println("** = Maliciously delayed packets")
	fmt.Println()

	// Test different strategy combinations
	testStrategyCombination("NAIVE CASE 1", verification.FlagRandom, verification.AnswerRandom, records)
	testStrategyCombination("NAIVE CASE 2", verification.FlagRandom, verification.AnswerClaimLowerObserved, records)
	// testStrategyCombination("HONEST BASELINE", verification.FlagNone, verification.AnswerHonest, records)
	// testStrategyCombination("COVER-UP ATTEMPT", verification.FlagActualDelayed, verification.AnswerConsistent, records)
}

func generateSampleRecords() []verification.TransmissionRecord {
	records := []verification.TransmissionRecord{
		{PacketID: 0, SentTime: 0.0, MinDelay: 0.05, ActualDelay: 0.08, PathUsed: "LEO_FAST", WasDelayed: false},
		{PacketID: 1, SentTime: 0.5, MinDelay: 0.25, ActualDelay: 0.30, PathUsed: "GEO_SLOW", WasDelayed: false},
		{PacketID: 2, SentTime: 1.0, MinDelay: 0.05, ActualDelay: 0.12, PathUsed: "LEO_FAST", WasDelayed: false},
		{PacketID: 3, SentTime: 1.5, MinDelay: 0.05, ActualDelay: 1.50, PathUsed: "LEO_FAST", WasDelayed: true, MaliciousDelay: 1.40},
		{PacketID: 4, SentTime: 2.0, MinDelay: 0.25, ActualDelay: 0.28, PathUsed: "GEO_SLOW", WasDelayed: false},
		{PacketID: 5, SentTime: 2.5, MinDelay: 0.05, ActualDelay: 0.07, PathUsed: "LEO_FAST", WasDelayed: false},
		{PacketID: 6, SentTime: 3.0, MinDelay: 0.25, ActualDelay: 0.35, PathUsed: "GEO_SLOW", WasDelayed: false},
		{PacketID: 7, SentTime: 3.5, MinDelay: 0.05, ActualDelay: 2.00, PathUsed: "LEO_FAST", WasDelayed: true, MaliciousDelay: 1.90},
		{PacketID: 8, SentTime: 4.0, MinDelay: 0.05, ActualDelay: 0.09, PathUsed: "LEO_FAST", WasDelayed: false},
		{PacketID: 9, SentTime: 4.5, MinDelay: 0.25, ActualDelay: 0.32, PathUsed: "GEO_SLOW", WasDelayed: false},
	}

	for i := range records {
		records[i].ReceivedTime = records[i].SentTime + records[i].ActualDelay
		records[i].IsShortestPath = records[i].MinDelay == 0.05
	}

	return records
}

func testStrategyCombination(name string, flagStrat verification.FlaggingStrategy, answerStrat verification.AnsweringStrategy, records []verification.TransmissionRecord) {
	fmt.Printf("=== %s ===\n", name)
	fmt.Printf("Flagging Strategy:  %s\n", flagStrat)
	fmt.Printf("Answering Strategy: %s\n", answerStrat)
	fmt.Println()

	oracle := verification.NewStrategicOracle(flagStrat, answerStrat, "LEO_FAST", 0.05)
	oracle.FlagProbability = 0.5
	oracle.LowDelayPercentile = 0.3

	for _, rec := range records {
		oracle.RecordTransmission(rec)
	}

	oracle.FlagPackets()

	fmt.Print("Flagged packets (SNP claims had congestion): ")
	flagged := []int{}
	for _, rec := range records {
		if oracle.IsFlagged(rec.PacketID) {
			flagged = append(flagged, rec.PacketID)
		}
	}
	fmt.Println(flagged)
	fmt.Println()

	fmt.Println("Comparison Queries:")
	fmt.Println("Query: Which packet had minimum possible delay?")
	fmt.Println()

	queries := [][2]int{
		{3, 5},
		{7, 8},
		{0, 1},
		{3, 7},
	}

	for _, pair := range queries {
		p1, p2 := pair[0], pair[1]
		rec1 := findRecord(records, p1)
		rec2 := findRecord(records, p2)

		if rec1 == nil || rec2 == nil {
			continue
		}

		answer := oracle.AnswerComparison(p1, p2)

		var truth verification.ComparisonResult
		if rec1.MinDelay < rec2.MinDelay-0.001 {
			truth = verification.Packet1Faster
		} else if rec2.MinDelay < rec1.MinDelay-0.001 {
			truth = verification.Packet2Faster
		} else {
			truth = verification.PacketsEqual
		}

		lied := ""
		if answer != truth {
			lied = " [LIE!]"
		}

		fmt.Printf("  Pkt %d vs Pkt %d:\n", p1, p2)
		fmt.Printf("    Ground Truth:    %s (min_delay: %.3f vs %.3f)\n", truth, rec1.MinDelay, rec2.MinDelay)
		fmt.Printf("    Observed:        actual_delay: %.3f vs %.3f\n", rec1.ActualDelay, rec2.ActualDelay)
		fmt.Printf("    SNP's Answer:    %s%s\n", answer, lied)
		fmt.Printf("    Pkt %d delayed?  %v | Pkt %d delayed? %v\n", p1, rec1.WasDelayed, p2, rec2.WasDelayed)
		fmt.Printf("    Pkt %d flagged?  %v | Pkt %d flagged? %v\n", p1, oracle.IsFlagged(p1), p2, oracle.IsFlagged(p2))
		fmt.Println()
	}

	fmt.Println("Oracle Stats:", oracle.GetStats())
	fmt.Println()
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println()
}

func findRecord(records []verification.TransmissionRecord, packetID int) *verification.TransmissionRecord {
	for i := range records {
		if records[i].PacketID == packetID {
			return &records[i]
		}
	}
	return nil
}
