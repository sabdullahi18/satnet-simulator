package verification

import (
	"math/rand"
	"sort"
)

type FlaggingStrategy string
type AnsweringStrategy string

const (
	FlagRandom FlaggingStrategy = "FLAG_RANDOM"
	FlagSmart  FlaggingStrategy = "FLAG_SMART"

	AnswerRandom AnsweringStrategy = "ANSWER_RANDOM"
	AnswerSmart  AnsweringStrategy = "ANSWER_SMART"
)

type Oracle struct {
	FlagStrategy    FlaggingStrategy
	AnswerStrategy  AnsweringStrategy
	Packets         map[int]*PacketRecord
	FlagProbability float64
	Queries         int
}

func NewStrategicOracle(f FlaggingStrategy, a AnsweringStrategy) *Oracle {
	return &Oracle{
		FlagStrategy:    f,
		AnswerStrategy:  a,
		Packets:         make(map[int]*PacketRecord),
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
	if len(allPackets) > 0 {
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
				if !p.WasDelayed {
					overhead := p.ActualDelay - p.MinDelay
					if overhead > 0.15 {
						shouldFlag = true
					} else {
						shouldFlag = false
					}
				} else {
					overhead := p.ActualDelay - p.MinDelay
					if overhead > 0.15 {
						shouldFlag = true
					} else {
						shouldFlag = false
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

	switch o.AnswerStrategy {
	case AnswerRandom:
		return Answer(rand.Intn(2))

	case AnswerSmart:
		if p1.ActualDelay < p2.ActualDelay {
			return Pkt1Lower
		} else {
			return Pkt2Lower
		}
	}

	return Pkt2Lower
}

func (o *Oracle) SetShortestPath(name string, delay float64) {}
