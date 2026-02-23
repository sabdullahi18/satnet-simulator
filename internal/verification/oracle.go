package verification

import (
	"math/rand"
)

type AnsweringStrategy string

const (
	AnswerHonest          AnsweringStrategy = "ANSWER_HONEST"
	AnswerRandom          AnsweringStrategy = "ANSWER_RANDOM"
	AnswerDelayedHonest   AnsweringStrategy = "ANSWER_DELAYED_HONEST"   // hides malicious as congestion
	AnswerLiesThatMinimal AnsweringStrategy = "ANSWER_LIES_THAT_MINIMAL" // claims malicious packets are minimal
)

type AdversaryConfig struct {
	AnsweringStr  AnsweringStrategy
	MaliciousRate float64
}

type Oracle struct {
	Config       AdversaryConfig
	Packets      map[int]*PacketRecord
	Queries      int
	QueryHistory map[int][]QueryRecord // PacketID -> list of previous answers
}

type QueryRecord struct {
	Answer Answer
	Time   float64
}

func NewOracle(config AdversaryConfig) *Oracle {
	return &Oracle{
		Config:       config,
		Packets:      make(map[int]*PacketRecord),
		QueryHistory: make(map[int][]QueryRecord),
	}
}

func (o *Oracle) RecordTransmission(p PacketRecord) {
	o.Packets[p.ID] = &p
}

// AnswerQuery handles the query: "Did packet P achieve minimal delay?"
// Returns Answer{IsMinimal, IsFlagged}.
func (o *Oracle) AnswerQuery(q Query) Answer {
	o.Queries++

	p, ok := o.Packets[q.PktID]
	if !ok {
		return Answer{IsMinimal: true, IsFlagged: false}
	}

	answer := o.decideAnswer(p)

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
	hasMalicious := p.WasDelayed
	hasCongestion := p.HasCongestion

	switch o.Config.AnsweringStr {
	case AnswerHonest:
		// Honest: report truthfully based on ground truth
		isMinimal := !hasCongestion && !hasMalicious
		return Answer{IsMinimal: isMinimal, IsFlagged: hasCongestion}

	case AnswerRandom:
		// Coin-flip IsMinimal; if not minimal, coin-flip IsFlagged
		isMinimal := rand.Float64() < 0.5
		isFlagged := false
		if !isMinimal {
			isFlagged = rand.Float64() < 0.5
		}
		return Answer{IsMinimal: isMinimal, IsFlagged: isFlagged}

	case AnswerDelayedHonest:
		// Hide malicious delay as congestion: claim malicious packets were flagged (congested)
		// Non-malicious packets: answer truthfully
		if hasMalicious {
			return Answer{IsMinimal: false, IsFlagged: true}
		}
		isMinimal := !hasCongestion
		return Answer{IsMinimal: isMinimal, IsFlagged: hasCongestion}

	case AnswerLiesThatMinimal:
		// Gaslight: claim malicious packets achieved minimal delay
		// Non-malicious packets: answer truthfully
		if hasMalicious {
			return Answer{IsMinimal: true, IsFlagged: false}
		}
		isMinimal := !hasCongestion
		return Answer{IsMinimal: isMinimal, IsFlagged: hasCongestion}
	}

	return Answer{IsMinimal: true, IsFlagged: false}
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
