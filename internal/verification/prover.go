package verification

import (
	"math/rand"
)

type AnsweringStrategy string

const (
	AnswerHonest            AnsweringStrategy = "ANSWER_HONEST"
	AnswerRandom            AnsweringStrategy = "ANSWER_RANDOM"
	AnswerDelayedHonest     AnsweringStrategy = "ANSWER_DELAYED_HONEST"      // hides malicious as congestion
	AnswerLiesThatMinimal   AnsweringStrategy = "ANSWER_LIES_THAT_MINIMAL"   // blanket denial: claims all packets are minimal
	AnswerLiesAboutTargeted AnsweringStrategy = "ANSWER_LIES_ABOUT_TARGETED" // lies only about deliberately delayed packets
)

type AdversaryConfig struct {
	AnsweringStr AnsweringStrategy
}

// Prover represents the network operator's self-reporting mechanism. It has access to ground
// truth (every PacketRecord) because it is the operator. The question is whether it tells the truth.
//
// Flagging is network-initiated and happens in RecordTransmission (before any queries). The
// prover sets IsFlagged on each record according to its strategy, proactively admitting
// "honest errors" before the verifier asks questions.
type Prover struct {
	Config      AdversaryConfig
	Packets     map[int]*PacketRecord
	Queries     int
	byTimeDelay map[int]map[float64]*PacketRecord // secondary index: int(SentTime) -> actualDelay -> record
}

func NewProver(config AdversaryConfig) *Prover {
	return &Prover{
		Config:      config,
		Packets:     make(map[int]*PacketRecord),
		byTimeDelay: make(map[int]map[float64]*PacketRecord),
	}
}

// RecordTransmission stores the packet's ground truth
func (p *Prover) RecordTransmission(rec PacketRecord) {
	p.Packets[rec.ID] = &rec

	// Populate secondary index by (BatchKey(SentTime), ActualDelay) for query lookup.
	timeKey := BatchKey(rec.SentTime)
	if p.byTimeDelay[timeKey] == nil {
		p.byTimeDelay[timeKey] = make(map[float64]*PacketRecord)
	}
	p.byTimeDelay[timeKey][rec.ActualDelay] = p.Packets[rec.ID]
}

// AnswerQuery handles the query: "Was delay X minimal for packets sent at time t?"
// The prover looks up the packet by (SentTime, ObservedDelay) and answers based on its strategy.
func (p *Prover) AnswerQuery(q Query) Answer {
	p.Queries++

	timeKey := BatchKey(q.SentTime)
	var rec *PacketRecord
	if byDelay, ok := p.byTimeDelay[timeKey]; ok {
		rec = byDelay[q.ObservedDelay]
	}

	if rec == nil {
		// Unknown packet — default to claiming minimal (cannot prove otherwise)
		return Answer{IsMinimal: true}
	}

	return p.decideAnswer(rec)
}

func (p *Prover) decideAnswer(rec *PacketRecord) Answer {
	hasDeliberate := rec.WasDelayed
	hasIncompetence := rec.HasIncompetence

	switch p.Config.AnsweringStr {
	case AnswerHonest:
		// Truthful: minimal only if no extra delay of any kind
		return Answer{IsMinimal: !hasIncompetence && !hasDeliberate}

	case AnswerRandom:
		// Coin-flip: naive adversary with no attempt at consistency
		return Answer{IsMinimal: rand.Float64() < 0.5}

	case AnswerDelayedHonest:
		// Never claims IsMinimal for any packet with extra delay. Deliberately delayed
		// packets were already flagged in RecordTransmission, so the prover's story is
		// consistent: "it was congested (flagged), so of course not minimal."
		return Answer{IsMinimal: !hasIncompetence && !hasDeliberate}

	case AnswerLiesThatMinimal:
		// Blanket denial: claims every packet achieved minimal delay, regardless of
		// whether it was targeted, congested, or both. Never flags anything. This is
		// the most reckless strategy — it completely denies the existence of any added
		// delay, making it highly vulnerable to contradiction checks.
		return Answer{IsMinimal: true}

	case AnswerLiesAboutTargeted:
		// Targeted lie: lies only about deliberately delayed packets, claiming they
		// achieved minimal delay. Answers honestly about incompetence-affected packets
		// and flags them as usual. Deliberately delayed packets are not flagged, since
		// flagging would contradict the minimal claim.
		if hasDeliberate {
			return Answer{IsMinimal: true}
		}
		return Answer{IsMinimal: !hasIncompetence}
	}

	return Answer{IsMinimal: true}
}
