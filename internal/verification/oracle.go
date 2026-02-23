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
	AnsweringStr AnsweringStrategy
}

type Oracle struct {
	Config  AdversaryConfig
	Packets map[int]*PacketRecord
	Queries int
}

func NewOracle(config AdversaryConfig) *Oracle {
	return &Oracle{
		Config:  config,
		Packets: make(map[int]*PacketRecord),
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

	return o.decideAnswer(p)
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
