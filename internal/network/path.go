package network

import (
	"fmt"
	"math/rand"
	"satnet-simulator/internal/engine"
)

func (p SatellitePath) Traverse(sim *engine.Simulation, pkt Packet, dest Destination) {
	totalDelay := p.Delay

	jitter := 0.5 + rand.Float64()*(2.0-0.5)
	totalDelay += jitter

	if rand.Float64() < p.SpikeProb {
		fmt.Printf(" [!] DELAY EVENT: Packet %d from %s delayed by %.2fs on %s\n",
			pkt.ID, pkt.Src, p.SpikeDelay, p.Name)
		totalDelay += p.SpikeDelay
	}

	sim.Schedule(totalDelay, func() {
		dest.Receive(sim, pkt, p.Name)
	})
}
