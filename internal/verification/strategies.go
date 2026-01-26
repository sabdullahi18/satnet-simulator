package verification

import (
	"fmt"
	"math/rand"
	"sort"
)

// =============================================================================
// STRATEGY 1: FLAGGING STRATEGY
// =============================================================================
// Determines which packets the SNP *claims* had legitimate congestion/delay.
// This is separate from whether the packet was actually maliciously delayed.

type FlaggingStrategy int

const (
	FlagNone FlaggingStrategy = iota
	FlagRandom
	FlagLowDelay
	FlagActualDelayed
)

func (f FlaggingStrategy) String() string {
	switch f {
	case FlagNone:
		return "FLAG_NONE"
	case FlagRandom:
		return "FLAG_RANDOM"
	case FlagLowDelay:
		return "FLAG_LOW_DELAY"
	case FlagActualDelayed:
		return "FLAG_ACTUAL_DELAYED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// STRATEGY 2: ANSWERING STRATEGY
// =============================================================================
// Determines how the SNP answers comparison queries.
// Given two packets, the verifier asks: "Which had minimum possible delay?"

type AnsweringStrategy int

const (
	AnswerHonest AnsweringStrategy = iota
	AnswerRandom
	AnswerClaimLowerObserved
	AnswerConsistent
)

func (a AnsweringStrategy) String() string {
	switch a {
	case AnswerHonest:
		return "ANSWER_HONEST"
	case AnswerRandom:
		return "ANSWER_RANDOM"
	case AnswerClaimLowerObserved:
		return "ANSWER_CLAIM_LOWER_OBSERVED"
	case AnswerConsistent:
		return "ANSWER_CONSISTENT"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// STRATEGIC ORACLE
// =============================================================================
// A new oracle that cleanly separates flagging and answering strategies

type StrategicOracle struct {
	FlaggingStrat  FlaggingStrategy
	AnsweringStrat AnsweringStrategy

	FlagProbability    float64 // for FlagRandom
	LowDelayPercentile float64 // for FlagLowDelay

	GroundTruth   []TransmissionRecord
	ShortestPath  string
	ShortestDelay float64

	flaggedPackets    map[int]bool
	claimedMinDelays  map[int]float64
	comparisonHistory map[string]ComparisonResult

	QueriesAnswered int
	LiesTold        int
	PacketsFlagged  int
}

func NewStrategicOracle(flagStrat FlaggingStrategy, answerStrat AnsweringStrategy, shortestPath string, shortestDelay float64) *StrategicOracle {
	return &StrategicOracle{
		FlaggingStrat:      flagStrat,
		AnsweringStrat:     answerStrat,
		FlagProbability:    0.5,
		LowDelayPercentile: 0.1,
		ShortestPath:       shortestPath,
		ShortestDelay:      shortestDelay,
		GroundTruth:        make([]TransmissionRecord, 0),
		flaggedPackets:     make(map[int]bool),
		claimedMinDelays:   make(map[int]float64),
		comparisonHistory:  make(map[string]ComparisonResult),
	}
}

func (o *StrategicOracle) RecordTransmission(record TransmissionRecord) {
	o.GroundTruth = append(o.GroundTruth, record)
}

func (o *StrategicOracle) FlagPackets() {
	o.flaggedPackets = make(map[int]bool)
	o.PacketsFlagged = 0

	switch o.FlaggingStrat {
	case FlagNone:
		return

	case FlagRandom:
		for _, rec := range o.GroundTruth {
			if rand.Float64() < o.FlagProbability {
				o.flaggedPackets[rec.PacketID] = true
				o.PacketsFlagged++
			}
		}

	case FlagLowDelay:
		o.flagLowDelayPackets()

	case FlagActualDelayed:
		for _, rec := range o.GroundTruth {
			if rec.WasDelayed {
				o.flaggedPackets[rec.PacketID] = true
				o.PacketsFlagged++
			}
		}
	}
}

func (o *StrategicOracle) flagLowDelayPackets() {
	sorted := make([]TransmissionRecord, len(o.GroundTruth))
	copy(sorted, o.GroundTruth)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ActualDelay < sorted[j].ActualDelay
	})

	threshold := int(float64(len(sorted)) * o.LowDelayPercentile)
	for i := 0; i < threshold && i < len(sorted); i++ {
		o.flaggedPackets[sorted[i].PacketID] = true
		o.PacketsFlagged++
	}
}

func (o *StrategicOracle) IsFlagged(packetID int) bool {
	return o.flaggedPackets[packetID]
}

func (o *StrategicOracle) FindRecordByID(packetID int) *TransmissionRecord {
	for i := range o.GroundTruth {
		if o.GroundTruth[i].PacketID == packetID {
			return &o.GroundTruth[i]
		}
	}
	return nil
}

func (o *StrategicOracle) AnswerComparison(packetID1, packetID2 int) ComparisonResult {
	o.QueriesAnswered++

	rec1 := o.FindRecordByID(packetID1)
	rec2 := o.FindRecordByID(packetID2)

	if rec1 == nil || rec2 == nil {
		return PacketsEqual
	}

	key := fmt.Sprintf("%d-%d", packetID1, packetID2)
	reverseKey := fmt.Sprintf("%d-%d", packetID2, packetID1)

	if prev, exists := o.comparisonHistory[key]; exists {
		return prev
	}
	if prev, exists := o.comparisonHistory[reverseKey]; exists {
		return o.reverseComparison(prev)
	}

	truth := o.computeTruth(rec1, rec2)

	var answer ComparisonResult

	switch o.AnsweringStrat {
	case AnswerHonest:
		answer = truth

	case AnswerRandom:
		answer = o.answerRandom()

	case AnswerClaimLowerObserved:
		answer = o.answerClaimLowerObserved(rec1, rec2)

	case AnswerConsistent:
		answer = o.answerConsistent(rec1, rec2)
	}

	if answer != truth {
		o.LiesTold++
	}

	o.comparisonHistory[key] = answer
	return answer
}

func (o *StrategicOracle) computeTruth(rec1, rec2 *TransmissionRecord) ComparisonResult {
	if rec1.MinDelay < rec2.MinDelay-0.001 {
		return Packet1Faster
	} else if rec2.MinDelay < rec1.MinDelay-0.001 {
		return Packet2Faster
	}
	return PacketsEqual
}

func (o *StrategicOracle) reverseComparison(c ComparisonResult) ComparisonResult {
	switch c {
	case Packet1Faster:
		return Packet2Faster
	case Packet2Faster:
		return Packet1Faster
	default:
		return PacketsEqual
	}
}

// =============================================================================
// ANSWERING STRATEGY IMPLEMENTATIONS
// =============================================================================

func (o *StrategicOracle) answerRandom() ComparisonResult {
	options := []ComparisonResult{Packet1Faster, Packet2Faster, PacketsEqual}
	return options[rand.Intn(len(options))]
}

func (o *StrategicOracle) answerClaimLowerObserved(rec1, rec2 *TransmissionRecord) ComparisonResult {
	if rec1.ActualDelay < rec2.ActualDelay-0.001 {
		return Packet1Faster
	} else if rec2.ActualDelay < rec1.ActualDelay-0.001 {
		return Packet2Faster
	}
	return PacketsEqual
}

func (o *StrategicOracle) answerConsistent(rec1, rec2 *TransmissionRecord) ComparisonResult {
	flagged1 := o.IsFlagged(rec1.PacketID)
	flagged2 := o.IsFlagged(rec2.PacketID)

	claimed1, has1 := o.claimedMinDelays[rec1.PacketID]
	claimed2, has2 := o.claimedMinDelays[rec2.PacketID]

	if has1 && has2 {
		if claimed1 < claimed2-0.001 {
			return Packet1Faster
		} else if claimed2 < claimed1-0.001 {
			return Packet2Faster
		}
		return PacketsEqual
	}

	if !has1 {
		if flagged1 {
			claimed1 = rec1.ActualDelay * 0.9
		} else {
			claimed1 = rec1.MinDelay
		}
		o.claimedMinDelays[rec1.PacketID] = claimed1
	}

	if !has2 {
		if flagged2 {
			claimed2 = rec2.ActualDelay * 0.9
		} else {
			claimed2 = rec2.MinDelay
		}
		o.claimedMinDelays[rec2.PacketID] = claimed2
	}

	if claimed1 < claimed2-0.001 {
		return Packet1Faster
	} else if claimed2 < claimed1-0.001 {
		return Packet2Faster
	}
	return PacketsEqual
}

// =============================================================================
// QUERY INTERFACE
// =============================================================================

func (o *StrategicOracle) Answer(q Query, simTime float64) Response {
	resp := Response{
		QueryID:    q.ID,
		Query:      q,
		AnswerTime: simTime,
	}

	switch q.Type {
	case QueryComparison:
		resp.ComparisonAnswer = o.AnswerComparison(q.PacketID, q.PacketID2)

	case QueryDelayBound:
		rec := o.FindRecordByID(q.PacketID)
		if rec == nil {
			resp.BoolAnswer = false
		} else {
			claimed, exists := o.claimedMinDelays[rec.PacketID]
			if !exists {
				if o.IsFlagged(rec.PacketID) {
					claimed = rec.ActualDelay * 0.9
				} else {
					claimed = rec.MinDelay
				}
				o.claimedMinDelays[rec.PacketID] = claimed
			}
			resp.BoolAnswer = claimed > q.DelayThreshold
		}

	case QueryCongestionFlag:
		flaggedCount := 0
		totalCount := 0
		for _, rec := range o.GroundTruth {
			if q.Interval.Contains(rec.SentTime) {
				totalCount++
				if o.IsFlagged(rec.PacketID) {
					flaggedCount++
				}
			}
		}
		resp.BoolAnswer = flaggedCount > 0
		if totalCount > 0 {
			resp.FloatAnswer = float64(flaggedCount) / float64(totalCount)
		}
	}

	return resp
}

func (o *StrategicOracle) GetStats() string {
	lieRate := 0.0
	if o.QueriesAnswered > 0 {
		lieRate = float64(o.LiesTold) / float64(o.QueriesAnswered) * 100
	}
	return fmt.Sprintf("Flagging: %s, Answering: %s, Queries: %d, Lies: %d (%.1f%%), Flagged: %d",
		o.FlaggingStrat, o.AnsweringStrat, o.QueriesAnswered, o.LiesTold, lieRate, o.PacketsFlagged)
}

func (o *StrategicOracle) Reset() {
	o.flaggedPackets = make(map[int]bool)
	o.claimedMinDelays = make(map[int]float64)
	o.comparisonHistory = make(map[string]ComparisonResult)
	o.QueriesAnswered = 0
	o.LiesTold = 0
	o.PacketsFlagged = 0
}
