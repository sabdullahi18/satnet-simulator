package verification

import (
	"math/rand"
	"sort"
)

type LyingStrategy string

const (
	StrategyHonest        LyingStrategy = "HONEST"
	StrategyRandomLies    LyingStrategy = "RANDOM_LIES"
	StrategyMinimiseDelay LyingStrategy = "MINIMISE_DELAY"
	StrategySophisticated LyingStrategy = "SOPHISTICATED"
	StrategyTargeted      LyingStrategy = "TARGETED"
)

type FlaggingStrategy string
type AnsweringStrategy string

const (
	FlagRandom   FlaggingStrategy  = "FLAG_RANDOM"
	FlagSmart    FlaggingStrategy  = "FLAG_SMART"
	AnswerRandom AnsweringStrategy = "ANSWER_RANDOM"
	AnswerSmart  AnsweringStrategy = "ANSWER_SMART"
)

type Oracle struct {
	Strategy        LyingStrategy
	LieProbability  float64
	Packets         map[int]*PacketRecord
	Queries         int
	FlagProbability float64
	FlagStrategy    FlaggingStrategy
	AnswerStrategy  AnsweringStrategy
}

func NewNetworkOracle(strategy LyingStrategy, lieProbability float64) *Oracle {
	return &Oracle{
		Strategy:       strategy,
		LieProbability: lieProbability,
		Packets:        make(map[int]*PacketRecord),
	}
}

func NewStrategicOracle(f FlaggingStrategy, a AnsweringStrategy) *Oracle {
	strategy := StrategyHonest
	lieProbability := 0.0

	if f == FlagSmart && a == AnswerSmart {
		strategy = StrategySophisticated
		lieProbability = 0.8
	} else if a == AnswerRandom {
		strategy = StrategyRandomLies
		lieProbability = 0.5
	} else if a == AnswerSmart {
		strategy = StrategyMinimiseDelay
	}

	return &Oracle{
		Strategy:        strategy,
		LieProbability:  lieProbability,
		Packets:         make(map[int]*PacketRecord),
		FlagStrategy:    f,
		AnswerStrategy:  a,
		FlagProbability: 0.5,
	}
}

func (o *Oracle) RecordTransmission(p PacketRecord) {
	o.Packets[p.ID] = &p
}

func (o *Oracle) FlagPackets() {
	allPackets := make([]*PacketRecord, 0, len(o.Packets))
	for _, p := range o.Packets {
		allPackets = append(allPackets, p)
	}

	sort.Slice(allPackets, func(i, j int) bool {
		return allPackets[i].ActualDelay < allPackets[j].ActualDelay
	})

	fastThresholdIdx := int(float64(len(allPackets)) * 0.10)
	fastThreshold := 0.0
	if len(allPackets) > fastThresholdIdx {
		fastThreshold = allPackets[fastThresholdIdx].ActualDelay
	}

	for _, p := range o.Packets {
		shouldFlag := false

		switch o.FlagStrategy {
		case FlagRandom:
			shouldFlag = rand.Float64() < o.FlagProbability

		case FlagSmart:
			if p.ActualDelay <= fastThreshold {
				shouldFlag = false
			} else {
				overhead := p.ActualDelay - p.MinDelay
				if overhead > 0.15 {
					shouldFlag = true
				}
			}

		default:
			if o.Strategy == StrategySophisticated || o.Strategy == StrategyTargeted {
				if p.ActualDelay > fastThreshold {
					overhead := p.ActualDelay - p.MinDelay
					if overhead > 0.15 {
						shouldFlag = true
					}
				}
			}
		}

		p.IsFlagged = shouldFlag
	}
}

func (o *Oracle) Answer(q Query) Answer {
	o.Queries++

	p1, ok1 := o.Packets[q.Pkt1]
	p2, ok2 := o.Packets[q.Pkt2]

	if !ok1 || !ok2 {
		return Pkt1Lower
	}

	truthAnswer := Pkt1Lower
	if p2.MinDelay < p1.MinDelay {
		truthAnswer = Pkt2Lower
	}

	switch o.Strategy {
	case StrategyHonest:
		return truthAnswer

	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
			if truthAnswer == Pkt1Lower {
				return Pkt2Lower
			}
			return Pkt1Lower
		}
		return truthAnswer

	case StrategyMinimiseDelay:
		if p1.ActualDelay < p2.ActualDelay {
			return Pkt1Lower
		}
		return Pkt2Lower

	case StrategySophisticated:
		return o.sophisticatedAnswer(p1, p2, truthAnswer)

	case StrategyTargeted:
		return o.targetedAnswer(p1, p2, truthAnswer)

	default:
		return truthAnswer
	}
}

func (o *Oracle) sophisticatedAnswer(p1, p2 *PacketRecord, truth Answer) Answer {
	if !p1.WasDelayed && !p2.WasDelayed {
		return truth
	}

	if p1.WasDelayed && p2.WasDelayed {
		if p1.ActualDelay < p2.ActualDelay {
			return Pkt1Lower
		}
		return Pkt2Lower
	}

	if p1.WasDelayed {
		if p1.ActualDelay >= p2.ActualDelay {
			return Pkt2Lower
		}
		return truth
	}

	if p2.ActualDelay >= p1.ActualDelay {
		return Pkt1Lower
	}
	return truth
}

func (o *Oracle) targetedAnswer(p1, p2 *PacketRecord, truth Answer) Answer {
	if !p1.WasDelayed && !p2.WasDelayed {
		return truth
	}

	if rand.Float64() < o.LieProbability {
		if truth == Pkt1Lower {
			return Pkt2Lower
		}
		return Pkt1Lower
	}

	return truth
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

func (o *Oracle) SetShortestPath(name string, delay float64) {}
