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
	hasDeliberate := p.WasDelayed
	hasIncompetence := p.HasIncompetence

	switch o.Config.AnsweringStr {
	case AnswerHonest:
		// Honest: report truthfully based on ground truth
		isMinimal := !hasIncompetence && !hasDeliberate
		return Answer{IsMinimal: isMinimal, IsFlagged: hasIncompetence}

	case AnswerRandom:
		// Coin-flip IsMinimal; if not minimal, coin-flip IsFlagged
		isMinimal := rand.Float64() < 0.5
		isFlagged := false
		if !isMinimal {
			isFlagged = rand.Float64() < 0.5
		}
		return Answer{IsMinimal: isMinimal, IsFlagged: isFlagged}

	case AnswerDelayedHonest:
		// Hide deliberate delay as incompetence: claim deliberately delayed packets were flagged
		// Non-deliberately-delayed packets: answer truthfully
		if hasDeliberate {
			return Answer{IsMinimal: false, IsFlagged: true}
		}
		isMinimal := !hasIncompetence
		return Answer{IsMinimal: isMinimal, IsFlagged: hasIncompetence}

	case AnswerLiesThatMinimal:
		// Gaslight: claim deliberately delayed packets achieved minimal delay
		// Non-deliberately-delayed packets: answer truthfully
		if hasDeliberate {
			return Answer{IsMinimal: true, IsFlagged: false}
		}
		isMinimal := !hasIncompetence
		return Answer{IsMinimal: isMinimal, IsFlagged: hasIncompetence}
	}

	return Answer{IsMinimal: true, IsFlagged: false}
}
