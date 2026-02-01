package network

import (
	"fmt"
	"math/rand"
	"satnet-simulator/internal/engine"
)

type TargetingMode int

const (
	TargetNone TargetingMode = iota
	TargetRandom
	TargetByID
	TargetByTime
)

func (m TargetingMode) String() string {
	switch m {
	case TargetNone:
		return "HONEST"
	case TargetRandom:
		return "RANDOM"
	case TargetByID:
		return "BY_ID"
	case TargetByTime:
		return "BY_TIME"
	default:
		return "UNKNOWN"
	}
}

type TargetingConfig struct {
	Mode            TargetingMode
	TargetFraction  float64
	TargetTimeStart float64
	TargetTimeEnd   float64
	TargetIDs       []int
}

func DefaultHonestTargeting() TargetingConfig {
	return TargetingConfig{
		Mode:           TargetNone,
		TargetFraction: 0,
	}
}

func DefaultAdversarialTargeting(fraction float64) TargetingConfig {
	return TargetingConfig{
		Mode:           TargetRandom,
		TargetFraction: fraction,
	}
}

type TransmissionCallback func(info TransmissionInfo)

type TransmissionInfo struct {
	PacketID         int
	Source           string
	SentTime         float64
	ReceivedTime     float64
	BaseDelay        float64
	LegitDelay       float64
	MaliciousDelay   float64
	TotalDelay       float64
	MinPossibleDelay float64
	WasDelayed       bool
}

type Router struct {
	DelayModel      *DelayModel
	TargetingCfg    TargetingConfig
	OnTransmission  TransmissionCallback
	PacketsRouted   int
	PacketsTargeted int
	targetIDSet     map[int]bool
}

func NewRouter(delayModel *DelayModel, targeting TargetingConfig) *Router {
	r := &Router{
		DelayModel:   delayModel,
		TargetingCfg: targeting,
		targetIDSet:  make(map[int]bool),
	}

	for _, id := range targeting.TargetIDs {
		r.targetIDSet[id] = true
	}

	return r
}

func (r *Router) isTargeted(pkt Packet, sendTime float64) bool {
	switch r.TargetingCfg.Mode {
	case TargetNone:
		return false

	case TargetRandom:
		return rand.Float64() < r.TargetingCfg.TargetFraction

	case TargetByID:
		return r.targetIDSet[pkt.ID]

	case TargetByTime:
		return sendTime >= r.TargetingCfg.TargetTimeStart &&
			sendTime <= r.TargetingCfg.TargetTimeEnd

	default:
		return false
	}
}

func (r *Router) Forward(sim *engine.Simulation, pkt Packet, dest Destination) {
	r.PacketsRouted++
	sendTime := sim.Now
	isTargeted := r.isTargeted(pkt, sendTime)
	if isTargeted {
		r.PacketsTargeted++
	}

	delays := r.DelayModel.ComputeTotalDelay(sendTime, isTargeted)
	sim.Schedule(delays.TotalDelay, func() {
		if r.OnTransmission != nil {
			r.OnTransmission(TransmissionInfo{
				PacketID:         pkt.ID,
				Source:           pkt.Src,
				SentTime:         sendTime,
				ReceivedTime:     sim.Now,
				BaseDelay:        delays.BaseDelay,
				LegitDelay:       delays.LegitDelay,
				MaliciousDelay:   delays.MaliciousDelay,
				TotalDelay:       delays.TotalDelay,
				MinPossibleDelay: delays.MinPossible,
				WasDelayed:       isTargeted,
			})
		}

		dest.Receive(sim, pkt, "")
	})
}

func (r *Router) Initialise(duration float64) {
	r.DelayModel.Initialise(duration)
}

func (r *Router) GetStats() string {
	targetRate := 0.0
	if r.PacketsRouted > 0 {
		targetRate = float64(r.PacketsTargeted) / float64(r.PacketsRouted) * 100
	}
	return fmt.Sprintf("Mode: %s, Routed: %d, Targeted: %d (%.1f%%)",
		r.TargetingCfg.Mode, r.PacketsRouted, r.PacketsTargeted, targetRate)
}

func (r *Router) Reset() {
	r.PacketsRouted = 0
	r.PacketsTargeted = 0
}

type Destination interface {
	Receive(sim *engine.Simulation, pkt Packet, pathUsed string)
}
