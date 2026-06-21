package verification

import (
	"math/rand"

	"satnet-simulator/internal/network"
)

type AnsweringStrategy string

const (
	AnswerHonest            AnsweringStrategy = "ANSWER_HONEST"
	AnswerInconsistent      AnsweringStrategy = "ANSWER_INCONSISTENT"
	AnswerRandom            AnsweringStrategy = "ANSWER_RANDOM"
	AnswerDelayedHonest     AnsweringStrategy = "ANSWER_DELAYED_HONEST"
	AnswerLiesThatMinimal   AnsweringStrategy = "ANSWER_LIES_THAT_MINIMAL"
	AnswerLiesAboutTargeted AnsweringStrategy = "ANSWER_LIES_ABOUT_TARGETED"
	AnswerUnreliable        AnsweringStrategy = "ANSWER_UNRELIABLE"
	AnswerParametric        AnsweringStrategy = "ANSWER_PARAMETRIC"
)

type AdversaryConfig struct {
	AnsweringStr        AnsweringStrategy
	FlaggingHonestyRate float64
	AnswerErrorRate     float64
	LieRate             float64 // p_lie: P(claim minimal | targeted, unflagged, queried)
}

type Prover struct {
	Config  AdversaryConfig
	Packets []*network.Packet
	Queries int
	// O(1) indexing cache to look up packets based on their BatchID and TotalDelay when the verifier queries them.
	byTimeDelay map[int]map[float64]*network.Packet
}

func NewProver(config AdversaryConfig) *Prover {
	return &Prover{
		Config:      config,
		Packets:     make([]*network.Packet, 0),
		byTimeDelay: make(map[int]map[float64]*network.Packet),
	}
}

func (p *Prover) RecordTransmission(rec network.Packet) {
	ptr := new(network.Packet)
	*ptr = rec
	p.Packets = append(p.Packets, ptr)

	timeKey := rec.BatchID
	if p.byTimeDelay[timeKey] == nil {
		p.byTimeDelay[timeKey] = make(map[float64]*network.Packet)
	}
	p.byTimeDelay[timeKey][rec.TotalDelay] = ptr
}

func (p *Prover) AnswerQuery(q query) answer {
	p.Queries++

	timeKey := q.batchID
	var rec *network.Packet
	if byDelay, ok := p.byTimeDelay[timeKey]; ok {
		rec = byDelay[q.observedDelay]
	}

	if rec == nil {
		return answer{isMinimal: true}
	}

	return p.decideAnswer(rec)
}

func (p *Prover) decideAnswer(rec *network.Packet) answer {
	isTargeted := rec.IsTargeted
	hasIncompetence := rec.HasIncompetence

	switch p.Config.AnsweringStr {
	case AnswerHonest, AnswerInconsistent, AnswerDelayedHonest:
		// AnswerInconsistent and AnswerDelayedHonest model nodes that might experience
		// delays due to incompetence, but are strictly honest when queried by the verifier.
		return answer{isMinimal: !hasIncompetence && !isTargeted}

	case AnswerRandom:
		return answer{isMinimal: rand.Float64() < 0.5}

	case AnswerLiesThatMinimal:
		return answer{isMinimal: true}

	case AnswerLiesAboutTargeted:
		if isTargeted {
			return answer{isMinimal: true}
		}
		return answer{isMinimal: !hasIncompetence}

	case AnswerUnreliable:
		if hasIncompetence && rand.Float64() < p.Config.AnswerErrorRate {
			return answer{isMinimal: true}
		}
		return answer{isMinimal: !hasIncompetence && !isTargeted}

	case AnswerParametric:
		if isTargeted {
			if rec.IsFlagged {
				return answer{isMinimal: false}
			}
			if rand.Float64() < p.Config.LieRate {
				return answer{isMinimal: true}
			}
			return answer{isMinimal: false}
		}
		return answer{isMinimal: !hasIncompetence}
	}

	return answer{isMinimal: true}
}
