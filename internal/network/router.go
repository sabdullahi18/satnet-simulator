package network

import (
	"math/rand"
	"satnet-simulator/internal/engine"
)

type TargetingMode int

const (
	TargetNone TargetingMode = iota
	TargetRandom
	TargetPeriodic
)

func (m TargetingMode) String() string {
	switch m {
	case TargetNone:
		return "HONEST"
	case TargetRandom:
		return "RANDOM"
	case TargetPeriodic:
		return "PERIODIC"
	default:
		return "UNKNOWN"
	}
}

type TargetingConfig struct {
	Mode           TargetingMode
	TargetFraction float64
	Period         int
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

func DefaultPeriodicTargeting(period int) TargetingConfig {
	return TargetingConfig{
		Mode:   TargetPeriodic,
		Period: period,
	}
}

type TransmissionCallback func(info TransmissionInfo)
type FlaggingFn func(hasIncompetence, wasDelayed bool) bool

type TransmissionInfo struct {
	PacketID          int
	BatchID           int
	SentTime          float64
	BaseDelay         float64
	IncompetenceDelay float64
	DeliberateDelay   float64
	TotalDelay        float64
	WasDelayed        bool
	HasIncompetence   bool
	IsFlagged         bool
}

type Router struct {
	DelayModel      *DelayModel
	TargetingCfg    TargetingConfig
	OnTransmission  TransmissionCallback
	Flagging        FlaggingFn
	PacketsRouted   int
	PacketsTargeted int
}

func NewRouter(delayModel *DelayModel, targeting TargetingConfig, flagging FlaggingFn) *Router {
	return &Router{
		DelayModel:   delayModel,
		TargetingCfg: targeting,
		Flagging:     flagging,
	}
}

func (r *Router) isTargeted() bool {
	switch r.TargetingCfg.Mode {
	case TargetRandom:
		return rand.Float64() < r.TargetingCfg.TargetFraction
	case TargetPeriodic:
		return r.TargetingCfg.Period > 0 && r.PacketsRouted%r.TargetingCfg.Period == 0
	}
	return false
}

func (r *Router) Forward(sim *engine.Simulation, pkt Packet, dest Destination) {
	sendTime := sim.Now
	isTargeted := r.isTargeted()
	r.PacketsRouted++
	if isTargeted {
		r.PacketsTargeted++
	}

	hasIncompetence := r.TargetingCfg.Mode == TargetNone && rand.Float64() < r.DelayModel.IncompetenceRate

	isFlagged := false
	if r.Flagging != nil {
		isFlagged = r.Flagging(hasIncompetence, isTargeted)
	}
	pkt.IsFlagged = isFlagged

	delays := r.DelayModel.ComputeTotalDelay(sendTime, hasIncompetence, isTargeted)
	sim.Schedule(delays.TotalDelay, func() {
		if r.OnTransmission != nil {
			r.OnTransmission(TransmissionInfo{
				PacketID:          pkt.ID,
				BatchID:           pkt.BatchID,
				SentTime:          sendTime,
				BaseDelay:         delays.BaseDelay,
				IncompetenceDelay: delays.IncompetenceDelay,
				DeliberateDelay:   delays.DeliberateDelay,
				TotalDelay:        delays.TotalDelay,
				WasDelayed:        isTargeted,
				HasIncompetence:   hasIncompetence,
				IsFlagged:         isFlagged,
			})
		}

		dest.Receive(sim, pkt, "")
	})
}

type Destination interface {
	Receive(sim *engine.Simulation, pkt Packet, pathUsed string)
}
