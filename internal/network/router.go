package network

import (
	"fmt"
	"math/rand"
	"satnet-simulator/internal/engine"
)

type AdversarialMode int

const (
	ModeHonest AdversarialMode = iota
	ModeRandomDelay
	ModeTargetedDelay
	ModeTimeBased
	ModeSelectiveByPath
)

func (m AdversarialMode) String() string {
	switch m {
	case ModeHonest:
		return "HONEST"
	case ModeRandomDelay:
		return "RANDOM_DELAY"
	case ModeTargetedDelay:
		return "TARGETED_DELAY"
	case ModeTimeBased:
		return "TIME_BASED"
	case ModeSelectiveByPath:
		return "SELECTIVE_BY_PATH"
	default:
		return "UNKNOWN"
	}
}

type AdversarialConfig struct {
	Mode              AdversarialMode
	DelayFraction     float64
	MinMaliciousDelay float64
	MaxMaliciousDelay float64
	TargetTimeStart   float64
	TargetTimeEnd     float64
	TargetPath        string
}

func DefaultHonestConfig() AdversarialConfig {
	return AdversarialConfig{
		Mode:          ModeHonest,
		DelayFraction: 0,
	}
}

func DefaultAdversarialConfig(fraction float64) AdversarialConfig {
	return AdversarialConfig{
		Mode:              ModeRandomDelay,
		DelayFraction:     fraction,
		MinMaliciousDelay: 0.5,
		MaxMaliciousDelay: 2.0,
	}
}

type TransmissionCallback func(info TransmissionInfo)

type TransmissionInfo struct {
	PacketID       int
	Source         string
	SentTime       float64
	ReceivedTime   float64
	PathUsed       string
	PathBaseDelay  float64
	MinDelay       float64
	ActualDelay    float64
	MaliciousDelay float64
	Jitter         float64
	IsShortestPath bool
	WasDelayed     bool
	ShortestPath   string
}

type VerifiableRouter struct {
	Paths          []SatellitePath
	AdversarialCfg AdversarialConfig
	OnTransmission TransmissionCallback

	shortestPathName string
	shortestDelay    float64

	PacketsRouted  int
	PacketsDelayed int
}

func NewVerifiableRouter(paths []SatellitePath, config AdversarialConfig) *VerifiableRouter {
	r := &VerifiableRouter{
		Paths:          paths,
		AdversarialCfg: config,
	}

	if len(paths) > 0 {
		r.shortestPathName = paths[0].Name
		r.shortestDelay = paths[0].Delay
		for _, p := range paths {
			if p.Delay < r.shortestDelay {
				r.shortestDelay = p.Delay
				r.shortestPathName = p.Name
			}
		}
	}

	return r
}

func (r *VerifiableRouter) GetShortestPath() (string, float64) {
	return r.shortestPathName, r.shortestDelay
}

func (r *VerifiableRouter) SelectPath(strategy PathSelectionStrategy) SatellitePath {
	if len(r.Paths) == 0 {
		return SatellitePath{}
	}

	switch strategy {
	case StrategyShortest:
		for _, p := range r.Paths {
			if p.Name == r.shortestPathName {
				return p
			}
		}
		return r.Paths[0]

	case StrategyRandom:
		return r.Paths[rand.Intn(len(r.Paths))]

	case StrategyWeighted:
		totalWeight := 0.0
		for _, p := range r.Paths {
			totalWeight += 1.0 / p.Delay
		}
		choice := rand.Float64() * totalWeight
		cumulative := 0.0
		for _, p := range r.Paths {
			cumulative += 1.0 / p.Delay
			if choice <= cumulative {
				return p
			}
		}
		return r.Paths[0]
	}
	return r.Paths[0]
}

func (r *VerifiableRouter) shouldDelay(pkt Packet, simTime float64, pathName string) bool {
	switch r.AdversarialCfg.Mode {
	case ModeHonest:
		return false

	case ModeRandomDelay:
		return rand.Float64() < r.AdversarialCfg.DelayFraction

	case ModeTargetedDelay:
		// Target specific packet IDs (e.g., even-numbered)
		return pkt.ID%2 == 0 && rand.Float64() < r.AdversarialCfg.DelayFraction*2

	case ModeTimeBased:
		if simTime >= r.AdversarialCfg.TargetTimeStart &&
			simTime <= r.AdversarialCfg.TargetTimeEnd {
			return rand.Float64() < r.AdversarialCfg.DelayFraction
		}
		return false

	case ModeSelectiveByPath:
		if pathName == r.AdversarialCfg.TargetPath {
			return rand.Float64() < r.AdversarialCfg.DelayFraction
		}
		return false
	}

	return false
}

func (r *VerifiableRouter) computeMaliciousDelay() float64 {
	if r.AdversarialCfg.MinMaliciousDelay >= r.AdversarialCfg.MaxMaliciousDelay {
		return r.AdversarialCfg.MinMaliciousDelay
	}

	delayRange := r.AdversarialCfg.MaxMaliciousDelay - r.AdversarialCfg.MinMaliciousDelay
	return r.AdversarialCfg.MinMaliciousDelay + rand.Float64()*delayRange
}

func (r *VerifiableRouter) Forward(sim *engine.Simulation, pkt Packet, dest Destination, strategy PathSelectionStrategy) {
	if len(r.Paths) == 0 {
		fmt.Println("[Router Error] No paths available!")
		return
	}

	selectedPath := r.SelectPath(strategy)
	r.forwardOnPath(sim, pkt, dest, selectedPath)
}

func (r *VerifiableRouter) ForwardOnPath(sim *engine.Simulation, pkt Packet, dest Destination, pathName string) {
	for _, p := range r.Paths {
		if p.Name == pathName {
			r.forwardOnPath(sim, pkt, dest, p)
			return
		}
	}

	fmt.Printf("[Router Warning] Path '%s' not found, using random\n", pathName)
	r.Forward(sim, pkt, dest, StrategyRandom)
}

func (r *VerifiableRouter) forwardOnPath(sim *engine.Simulation, pkt Packet, dest Destination, selectedPath SatellitePath) {
	r.PacketsRouted++

	isShortestPath := selectedPath.Name == r.shortestPathName
	sentTime := sim.Now
	baseDelay := selectedPath.Delay
	jitter := 0.5 + rand.Float64()*1.5

	spikeDelay := 0.0
	if rand.Float64() < selectedPath.SpikeProb {
		spikeDelay = selectedPath.SpikeDelay
		// [SILENCED] - Pollution removed
		// fmt.Printf("  [!] SPIKE: Packet %d delayed by %.2fs on %s\n",
		// 	pkt.ID, spikeDelay, selectedPath.Name)
	}

	minDelay := baseDelay
	legitimateDelay := baseDelay + jitter + spikeDelay

	maliciousDelay := 0.0
	wasDelayed := false
	if r.shouldDelay(pkt, sim.Now, selectedPath.Name) {
		maliciousDelay = r.computeMaliciousDelay()
		wasDelayed = true
		r.PacketsDelayed++
	}

	totalDelay := legitimateDelay + maliciousDelay
	sim.Schedule(totalDelay, func() {
		if r.OnTransmission != nil {
			r.OnTransmission(TransmissionInfo{
				PacketID:       pkt.ID,
				Source:         pkt.Src,
				SentTime:       sentTime,
				ReceivedTime:   sim.Now,
				PathUsed:       selectedPath.Name,
				PathBaseDelay:  baseDelay,
				MinDelay:       minDelay,
				ActualDelay:    totalDelay,
				MaliciousDelay: maliciousDelay,
				Jitter:         jitter,
				IsShortestPath: isShortestPath,
				WasDelayed:     wasDelayed,
				ShortestPath:   r.shortestPathName,
			})
		}

		dest.Receive(sim, pkt, selectedPath.Name)
	})
}

func (r *VerifiableRouter) GetStats() string {
	delayRate := 0.0
	if r.PacketsRouted > 0 {
		delayRate = float64(r.PacketsDelayed) / float64(r.PacketsRouted) * 100
	}
	return fmt.Sprintf("Mode: %s, Routed: %d, Delayed: %d (%.1f%%)",
		r.AdversarialCfg.Mode, r.PacketsRouted, r.PacketsDelayed, delayRate)
}

type PathSelectionStrategy int

const (
	StrategyShortest PathSelectionStrategy = iota
	StrategyRandom
	StrategyWeighted
)

type SatellitePath struct {
	Name       string
	Delay      float64
	SpikeProb  float64
	SpikeDelay float64
}

type Destination interface {
	Receive(sim *engine.Simulation, pkt Packet, pathUsed string)
}

func (r *VerifiableRouter) GetPathByName(name string) *SatellitePath {
	for i := range r.Paths {
		if r.Paths[i].Name == name {
			return &r.Paths[i]
		}
	}
	return nil
}
