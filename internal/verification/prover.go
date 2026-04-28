package verification

import (
	"math/rand"
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
	Config      AdversaryConfig
	Packets     map[int]*PacketRecord
	Queries     int
	byTimeDelay map[int]map[float64]*PacketRecord
}

func NewProver(config AdversaryConfig) *Prover {
	return &Prover{
		Config:      config,
		Packets:     make(map[int]*PacketRecord),
		byTimeDelay: make(map[int]map[float64]*PacketRecord),
	}
}

func (p *Prover) RecordTransmission(rec PacketRecord) {
	p.Packets[rec.ID] = &rec

	timeKey := rec.BatchID
	if p.byTimeDelay[timeKey] == nil {
		p.byTimeDelay[timeKey] = make(map[float64]*PacketRecord)
	}
	p.byTimeDelay[timeKey][rec.ActualDelay] = p.Packets[rec.ID]
}

func (p *Prover) AnswerQuery(q Query) Answer {
	p.Queries++

	timeKey := q.BatchID
	var rec *PacketRecord
	if byDelay, ok := p.byTimeDelay[timeKey]; ok {
		rec = byDelay[q.ObservedDelay]
	}

	if rec == nil {
		return Answer{IsMinimal: true}
	}

	return p.decideAnswer(rec)
}

func (p *Prover) decideAnswer(rec *PacketRecord) Answer {
	hasDeliberate := rec.WasDelayed
	hasIncompetence := rec.HasIncompetence

	switch p.Config.AnsweringStr {
	case AnswerHonest, AnswerInconsistent:
		return Answer{IsMinimal: !hasIncompetence && !hasDeliberate}

	case AnswerRandom:
		return Answer{IsMinimal: rand.Float64() < 0.5}

	case AnswerDelayedHonest:
		return Answer{IsMinimal: !hasIncompetence && !hasDeliberate}

	case AnswerLiesThatMinimal:
		return Answer{IsMinimal: true}

	case AnswerLiesAboutTargeted:
		if hasDeliberate {
			return Answer{IsMinimal: true}
		}
		return Answer{IsMinimal: !hasIncompetence}

	case AnswerUnreliable:
		if hasIncompetence && rand.Float64() < p.Config.AnswerErrorRate {
			return Answer{IsMinimal: true}
		}
		return Answer{IsMinimal: !hasIncompetence && !hasDeliberate}

	case AnswerParametric:
		if hasDeliberate {
			if rec.IsFlagged {
				return Answer{IsMinimal: false}
			}
			if rand.Float64() < p.Config.LieRate {
				return Answer{IsMinimal: true}
			}
			return Answer{IsMinimal: false}
		}
		return Answer{IsMinimal: !hasIncompetence}
	}

	return Answer{IsMinimal: true}
}
