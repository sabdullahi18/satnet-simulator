package nodes

import (
	"fmt"
	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
)

type GroundStation struct {
	Name     string
	Received int
}

func NewGroundStation(name string) *GroundStation {
	return &GroundStation{
		Name:     name,
		Received: 0,
	}
}

func (g *GroundStation) Receive(sim *engine.Simulation, pkt network.Packet, pathUsed string) {
	g.Received++
	latency := sim.Now - pkt.CreationTime
	fmt.Printf("[%5.2fs] %s RECEIVED pkt %d (from %s, latency: %.4fs)\n",
		sim.Now, g.Name, pkt.ID, pkt.Src, latency)
}

type MockGroundStation struct {
	Name     string
	Received int
}

func NewMockGroundStation(name string) *MockGroundStation {
	return &MockGroundStation{Name: name}
}

func (m *MockGroundStation) Receive(sim *engine.Simulation, pkt network.Packet, pathUsed string) {
	m.Received++
}
