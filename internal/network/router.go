package network

import (
	"fmt"
	"satnet-simulator/internal/engine"
)

type SatNetRouter struct {
	Paths []SatellitePath
}

func (r *SatNetRouter) Forward(sim *engine.Simulation, pkt Packet, dest Destination) {
	if len(r.Paths) == 0 {
		fmt.Println("[Router Error] No paths available!")
		return
	}

	bestPath := r.Paths[0]
	for _, path := range r.Paths {
		if path.Delay < bestPath.Delay {
			bestPath = path
		}
	}

	fmt.Printf("[SatNet Internal] Routing pkt %d from %s via %s (Base Delay: %.2fs)\n",
		pkt.ID, pkt.Src, bestPath.Name, bestPath.Delay)

	bestPath.Traverse(sim, pkt, dest)
}
