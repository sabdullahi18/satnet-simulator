package nodes

import (
	"fmt"
	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
)

type GroundStation struct {
	Name   string
	Router *network.VerifiableRouter
}

func NewGroundStation(name string, router *network.VerifiableRouter) *GroundStation {
	return &GroundStation{
		Name:   name,
		Router: router,
	}
}

func (g *GroundStation) Send(sim *engine.Simulation, dest network.Destination, count int) {
	for i := range count {
		packetID := i

		sim.Schedule(float64(i)*1.0, func() {
			pkt := network.NewPacket(packetID, g.Name, sim.Now)
			fmt.Printf("[%5.2fs] %s SENT pkt %d\n", sim.Now, g.Name, pkt.ID)
			g.Router.Forward(sim, pkt, dest)
		})
	}
}

func (g *GroundStation) Receive(sim *engine.Simulation, pkt network.Packet, pathUsed string) {
	latency := sim.Now - pkt.CreationTime
	fmt.Printf("[%5.2fs] %s RECEIVED pkt %d (from %s via %s, latency: %.2fs)\n",
		sim.Now, g.Name, pkt.ID, pkt.Src, pathUsed, latency)
}
