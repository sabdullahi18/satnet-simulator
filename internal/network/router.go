package network

import (
	"math/rand"
	"satnet-simulator/internal/engine"
)

type TargetingMode int

const (
	TargetNone TargetingMode = iota
	TargetRandom
)

func (m TargetingMode) String() string {
	switch m {
	case TargetNone:
		return "HONEST"
	case TargetRandom:
		return "RANDOM"
	default:
		return "UNKNOWN"
	}
}

type TargetingConfig struct {
	Mode           TargetingMode
	TargetFraction float64
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
	PacketID       int
	SentTime       float64
	BaseDelay      float64
	LegitDelay     float64
	MaliciousDelay float64
	TotalDelay     float64
	WasDelayed     bool
	HasCongestion  bool
}

type Router struct {
	DelayModel      *DelayModel
	TargetingCfg    TargetingConfig
	OnTransmission  TransmissionCallback
	PacketsRouted   int
	PacketsTargeted int
}

func NewRouter(delayModel *DelayModel, targeting TargetingConfig) *Router {
	return &Router{
		DelayModel:   delayModel,
		TargetingCfg: targeting,
	}
}

func (r *Router) isTargeted() bool {
	if r.TargetingCfg.Mode == TargetRandom {
		return rand.Float64() < r.TargetingCfg.TargetFraction
	}
	return false
}

func (r *Router) Forward(sim *engine.Simulation, pkt Packet, dest Destination) {
	r.PacketsRouted++
	sendTime := sim.Now
	isTargeted := r.isTargeted()
	if isTargeted {
		r.PacketsTargeted++
	}

	hasCongestion := rand.Float64() < r.DelayModel.CongestionRate

	delays := r.DelayModel.ComputeTotalDelay(sendTime, hasCongestion, isTargeted)
	sim.Schedule(delays.TotalDelay, func() {
		if r.OnTransmission != nil {
			r.OnTransmission(TransmissionInfo{
				PacketID:       pkt.ID,
				SentTime:       sendTime,
				BaseDelay:      delays.BaseDelay,
				LegitDelay:     delays.LegitDelay,
				MaliciousDelay: delays.MaliciousDelay,
				TotalDelay:     delays.TotalDelay,
				WasDelayed:     isTargeted,
				HasCongestion:  hasCongestion,
			})
		}

		dest.Receive(sim, pkt, "")
	})
}

type Destination interface {
	Receive(sim *engine.Simulation, pkt Packet, pathUsed string)
}
