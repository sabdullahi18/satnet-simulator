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
	TargetQuota
	TargetAll
)

func (m TargetingMode) String() string {
	switch m {
	case TargetNone:
		return "HONEST"
	case TargetRandom:
		return "RANDOM"
	case TargetPeriodic:
		return "PERIODIC"
	case TargetQuota:
		return "QUOTA"
	case TargetAll:
		return "ALL"
	default:
		return "UNKNOWN"
	}
}

type TargetingConfig struct {
	Mode           TargetingMode
	TargetFraction float64
	Period         int
	Quota          int
	BatchSize      int
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

func DefaultQuotaTargeting(quota, batchSize int) TargetingConfig {
	return TargetingConfig{
		Mode:      TargetQuota,
		Quota:     quota,
		BatchSize: batchSize,
	}
}

func DefaultAllTargeting() TargetingConfig {
	return TargetingConfig{
		Mode: TargetAll,
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

type batchQuotaState struct {
	Seen     int
	Targeted int
}

type Router struct {
	DelayModel      *DelayModel
	TargetingCfg    TargetingConfig
	OnTransmission  TransmissionCallback
	Flagging        FlaggingFn
	PacketsRouted   int
	PacketsTargeted int
	quotaState      map[int]*batchQuotaState
}

func NewRouter(delayModel *DelayModel, targeting TargetingConfig, flagging FlaggingFn) *Router {
	return &Router{
		DelayModel:   delayModel,
		TargetingCfg: targeting,
		Flagging:     flagging,
		quotaState:   make(map[int]*batchQuotaState),
	}
}

func (r *Router) isTargeted(batchID int) bool {
	switch r.TargetingCfg.Mode {
	case TargetRandom:
		return rand.Float64() < r.TargetingCfg.TargetFraction
	case TargetPeriodic:
		return r.TargetingCfg.Period > 0 && r.PacketsRouted%r.TargetingCfg.Period == 0
	case TargetAll:
		return true
	case TargetQuota:
		return r.isTargetedQuota(batchID)
	}
	return false
}

func (r *Router) isTargetedQuota(batchID int) bool {
	B := r.TargetingCfg.BatchSize
	k := r.TargetingCfg.Quota
	if B <= 0 || k <= 0 {
		return false
	}
	if k >= B {
		return true
	}
	st, ok := r.quotaState[batchID]
	if !ok {
		st = &batchQuotaState{}
		r.quotaState[batchID] = st
	}
	remainingSlots := k - st.Targeted
	remainingPackets := B - st.Seen
	st.Seen++
	if remainingSlots <= 0 {
		return false
	}
	if remainingSlots >= remainingPackets {
		st.Targeted++
		return true
	}
	if rand.Float64() < float64(remainingSlots)/float64(remainingPackets) {
		st.Targeted++
		return true
	}
	return false
}

func (r *Router) Forward(sim *engine.Simulation, pkt Packet, dest Destination) {
	sendTime := sim.Now
	isTargeted := r.isTargeted(pkt.BatchID)
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
