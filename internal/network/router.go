package network

import (
	"fmt"
	"math/rand"
	"satnet-simulator/internal/engine"
)

type PathSelectionStrategy int

const (
	StrategyShortest PathSelectionStrategy = iota
	StrategyRandom
	// StrategyWeighted picks randomly but weighted by inverse delay
	StrategyWeighted
)

type TransmissionCallback func(record TransmissionInfo)

type TransmissionInfo struct {
	PacketID       int
	Source         string
	SentTime       float64
	ReceivedTime   float64
	PathUsed       string
	PathBaseDelay  float64
	ActualDelay    float64
	IsShortestPath bool
	ShortestPath   string
}

type VerifiableRouter struct {
	Paths            []SatellitePath
	Strategy         PathSelectionStrategy
	OnTransmission   TransmissionCallback
	shortestPathName string
	shortestDelay    float64
}

func NewVerifiableRouter(paths []SatellitePath, strategy PathSelectionStrategy) *VerifiableRouter {
	r := &VerifiableRouter{
		Paths:    paths,
		Strategy: strategy,
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

func (r *VerifiableRouter) SelectPath() SatellitePath {
	if len(r.Paths) == 0 {
		return SatellitePath{}
	}

	switch r.Strategy {
	case StrategyShortest:
		best := r.Paths[0]
		for _, p := range r.Paths {
			if p.Delay < best.Delay {
				best = p
			}
		}
		return best

	case StrategyRandom:
		return r.Paths[rand.Intn(len(r.Paths))]

	case StrategyWeighted:
		totalWeight := 0.0
		for _, p := range r.Paths {
			totalWeight += 1.0 / p.Delay
		}
		rand := rand.Float64() * totalWeight
		cumulative := 0.0
		for _, p := range r.Paths {
			cumulative += 1.0 / p.Delay
			if rand <= cumulative {
				return p
			}
		}
		return r.Paths[0]
	}

	return r.Paths[0]
}

func (r *VerifiableRouter) GetPathByName(name string) *SatellitePath {
	for i := range r.Paths {
		if r.Paths[i].Name == name {
			return &r.Paths[i]
		}
	}
	return nil
}

func (r *VerifiableRouter) ForwardOnPath(sim *engine.Simulation, pkt Packet, dest Destination, forcedPathName string) {
	if len(r.Paths) == 0 {
		fmt.Println("[Router Error] No paths available!")
		return
	}

	var selectedPath *SatellitePath
	for i := range r.Paths {
		if r.Paths[i].Name == forcedPathName {
			selectedPath = &r.Paths[i]
			break
		}
	}

	if selectedPath == nil {
		fmt.Printf("[Router Error] Forced path '%s' not found, falling back to random\n", forcedPathName)
		r.Forward(sim, pkt, dest)
		return
	}

	r.forwardOnPath(sim, pkt, dest, *selectedPath)
}

func (r *VerifiableRouter) Forward(sim *engine.Simulation, pkt Packet, dest Destination) {
	if len(r.Paths) == 0 {
		fmt.Println("[Router Error] No paths available!")
		return
	}

	selectedPath := r.SelectPath()
	r.forwardOnPath(sim, pkt, dest, selectedPath)
}

func (r *VerifiableRouter) forwardOnPath(sim *engine.Simulation, pkt Packet, dest Destination, selectedPath SatellitePath) {
	isShortestPath := selectedPath.Name == r.shortestPathName

	sentTime := sim.Now

	fmt.Printf("[SatNet Internal] Routing pkt %d from %s via %s (Base Delay: %.2fs, Shortest: %v)\n",
		pkt.ID, pkt.Src, selectedPath.Name, selectedPath.Delay, isShortestPath)

	totalDelay := selectedPath.Delay
	jitter := 0.5 + rand.Float64()*(2.0-0.5)
	totalDelay += jitter

	hasSpike := false
	if rand.Float64() < selectedPath.SpikeProb {
		hasSpike = true
		fmt.Printf(" [!] DELAY EVENT: Packet %d from %s delayed by %.2fs on %s\n",
			pkt.ID, pkt.Src, selectedPath.SpikeDelay, selectedPath.Name)
		totalDelay += selectedPath.SpikeDelay
	}

	_ = hasSpike

	sim.Schedule(totalDelay, func() {
		if r.OnTransmission != nil {
			r.OnTransmission(TransmissionInfo{
				PacketID:       pkt.ID,
				Source:         pkt.Src,
				SentTime:       sentTime,
				ReceivedTime:   sim.Now,
				PathUsed:       selectedPath.Name,
				PathBaseDelay:  selectedPath.Delay,
				ActualDelay:    totalDelay,
				IsShortestPath: isShortestPath,
				ShortestPath:   r.shortestPathName,
			})
		}

		dest.Receive(sim, pkt, selectedPath.Name)
	})
}

type VerifiableDestination struct {
	Dest Destination
}

func (vd *VerifiableDestination) Receive(sim *engine.Simulation, pkt Packet, pathUsed string) {
	vd.Dest.Receive(sim, pkt, pathUsed)
}
