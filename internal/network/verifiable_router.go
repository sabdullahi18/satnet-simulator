package network

import (
	"fmt"
	"math/rand"
	"satnet-simulator/internal/engine"
)

// PathSelectionStrategy determines how the router picks a path
type PathSelectionStrategy int

const (
	// StrategyShortest always picks the shortest path
	StrategyShortest PathSelectionStrategy = iota
	// StrategyRandom picks a random path
	StrategyRandom
	// StrategyWeighted picks randomly but weighted by inverse delay
	StrategyWeighted
)

// TransmissionCallback is called when a packet transmission is recorded
type TransmissionCallback func(record TransmissionInfo)

// TransmissionInfo contains details about a packet's journey
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

// VerifiableRouter is a router that records ground truth for verification
type VerifiableRouter struct {
	Paths            []SatellitePath
	Strategy         PathSelectionStrategy
	OnTransmission   TransmissionCallback
	shortestPathName string
	shortestDelay    float64
}

// NewVerifiableRouter creates a router that can record transmission data
func NewVerifiableRouter(paths []SatellitePath, strategy PathSelectionStrategy) *VerifiableRouter {
	r := &VerifiableRouter{
		Paths:    paths,
		Strategy: strategy,
	}

	// Find the shortest path
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

// GetShortestPath returns the name and delay of the shortest path
func (r *VerifiableRouter) GetShortestPath() (string, float64) {
	return r.shortestPathName, r.shortestDelay
}

// SelectPath chooses a path based on the current strategy
func (r *VerifiableRouter) SelectPath() SatellitePath {
	if len(r.Paths) == 0 {
		return SatellitePath{}
	}

	switch r.Strategy {
	case StrategyShortest:
		// Find path with lowest base delay
		best := r.Paths[0]
		for _, p := range r.Paths {
			if p.Delay < best.Delay {
				best = p
			}
		}
		return best

	case StrategyRandom:
		// Pick uniformly at random
		return r.Paths[rand.Intn(len(r.Paths))]

	case StrategyWeighted:
		// Weighted random selection (favor faster paths)
		totalWeight := 0.0
		for _, p := range r.Paths {
			totalWeight += 1.0 / p.Delay
		}
		randVal := rand.Float64() * totalWeight
		cumulative := 0.0
		for _, p := range r.Paths {
			cumulative += 1.0 / p.Delay
			if randVal <= cumulative {
				return p
			}
		}
		return r.Paths[0]
	}

	return r.Paths[0]
}

// Forward sends a packet through a selected path and records ground truth
func (r *VerifiableRouter) Forward(sim *engine.Simulation, pkt Packet, dest Destination) {
	if len(r.Paths) == 0 {
		fmt.Println("[Router Error] No paths available!")
		return
	}

	selectedPath := r.SelectPath()
	isShortestPath := selectedPath.Name == r.shortestPathName

	sentTime := sim.Now

	fmt.Printf("[SatNet Internal] Routing pkt %d from %s via %s (Base Delay: %.2fs, Shortest: %v)\n",
		pkt.ID, pkt.Src, selectedPath.Name, selectedPath.Delay, isShortestPath)

	// Calculate the actual delay (same logic as Traverse)
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

	_ = hasSpike // Could be used for more detailed recording

	// Schedule delivery and record ground truth
	sim.Schedule(totalDelay, func() {
		// Record the transmission before delivery
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

// VerifiableDestination wraps a destination to track received packets
type VerifiableDestination struct {
	Dest Destination
}

func (vd *VerifiableDestination) Receive(sim *engine.Simulation, pkt Packet, pathUsed string) {
	vd.Dest.Receive(sim, pkt, pathUsed)
}
