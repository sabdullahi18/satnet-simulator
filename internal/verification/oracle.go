package verification

import (
	"math/rand"
)

// TargetingStrategy defines which packets get malicious delay
type TargetingStrategy string

const (
	TargetNone   TargetingStrategy = "TARGET_NONE"
	TargetRandom TargetingStrategy = "TARGET_RANDOM"
	TargetByID   TargetingStrategy = "TARGET_BY_ID"
	TargetByTime TargetingStrategy = "TARGET_BY_TIME"
)

// AnsweringStrategy defines how the oracle responds to queries
type AnsweringStrategy string

const (
	AnswerHonest AnsweringStrategy = "ANSWER_HONEST"
	AnswerRandom AnsweringStrategy = "ANSWER_RANDOM"
	AnswerSmart  AnsweringStrategy = "ANSWER_SMART" // Hides malicious as Flagged
	AnswerBold   AnsweringStrategy = "ANSWER_BOLD"  // Gaslights as Minimal
)

type AdversaryConfig struct {
	AnsweringStr  AnsweringStrategy
	MaliciousRate float64 // Used for consistency if needed, or remove
}

type Oracle struct {
	Config       AdversaryConfig
	Packets      map[int]*PacketRecord
	Queries      int
	QueryHistory map[int][]QueryRecord // PacketID -> List of previous answers
}

type QueryRecord struct {
	Answer Answer
	Time   float64 // When the query was asked (simulation time steps, if we track it)
}

func NewOracle(config AdversaryConfig) *Oracle {
	return &Oracle{
		Config:       config,
		Packets:      make(map[int]*PacketRecord),
		QueryHistory: make(map[int][]QueryRecord),
	}
}

// Targeting logic is handled by the Router/Simulation, not the Oracle.
// The Oracle only observes the result (PacketRecord) and decides how to answer.

func (o *Oracle) RecordTransmission(p PacketRecord) {
	o.Packets[p.ID] = &p
}

// AnswerQuery handles the new single-packet query: "Did packet P achieve minimal delay?"
func (o *Oracle) AnswerQuery(q Query) Answer {
	o.Queries++

	p, ok := o.Packets[q.PktID]
	if !ok {
		// Default to Minimal if we don't know (shouldn't happen)
		return AnswerMinimal
	}

	answer := o.decideAnswer(p)

	// Record history for consistency checking
	if _, exists := o.QueryHistory[q.PktID]; !exists {
		o.QueryHistory[q.PktID] = make([]QueryRecord, 0)
	}
	o.QueryHistory[q.PktID] = append(o.QueryHistory[q.PktID], QueryRecord{
		Answer: answer,
		Time:   q.Time,
	})

	return answer
}

func (o *Oracle) decideAnswer(p *PacketRecord) Answer {
	// Logic variables used below
	hasMalicious := p.WasDelayed

	// Threshold for "Legit Congestion" to be worth flagging?
	// If we flag everything, the flag rate is 100%. The prompt implies flagging is for "congestion".
	// Let's use a threshold, e.g., > 10ms over base?
	hasCongestion := (p.ActualDelay - p.BaseDelay - p.MaliciousDelay) > 0.010

	switch o.Config.AnsweringStr {
	case AnswerHonest:
		if hasMalicious {
			// An honest network wouldn't have malicious delay, but if it did (by accident?), it would admittingly flag it?
			// Or maybe "Honest" here implies the strategy the network *should* follow.
			// Ideally, malicious packets shouldn't exist in honest status.
			// But if we are simulating an attacker who decides to be honest about this packet:
			return AnswerFlagged
		}
		if hasCongestion {
			return AnswerFlagged
		}
		return AnswerMinimal

	case AnswerRandom:
		if rand.Float64() < 0.5 {
			return AnswerMinimal
		}
		return AnswerFlagged

	case AnswerSmart: // "Hide" strategy
		if hasMalicious {
			// Malicious packet! We want to hide it.
			// If we say Minimal -> We claim delay is base. But obs delay is high. Risk of Logical Contradiction.
			// If we say Flagged -> We claim delay is legit congestion. Obs delay is high. Plausible!
			// Smart strategy: Claim Flagged.
			return AnswerFlagged
		}
		// Non-malicious packets: Be honest to maintain credibility?
		// Or random? Usually honest is best to minimize flag rate abuse.
		if hasCongestion {
			return AnswerFlagged
		}
		return AnswerMinimal

	case AnswerBold: // "Gaslight" strategy
		if hasMalicious {
			// Try to claim it's minimal!
			// Only works if the delay isn't HUGE compared to minimal.
			// If (Obs - Base) is small enough, maybe we get away with it.
			return AnswerMinimal
		}
		// Non-malicious
		if hasCongestion {
			return AnswerFlagged
		}
		return AnswerMinimal
	}

	return AnswerMinimal
}

func (o *Oracle) GetPacket(id int) *PacketRecord {
	return o.Packets[id]
}

func (o *Oracle) GetAllPackets() []*PacketRecord {
	result := make([]*PacketRecord, 0, len(o.Packets))
	for _, p := range o.Packets {
		result = append(result, p)
	}
	return result
}
