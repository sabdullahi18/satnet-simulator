package main

import (
	"fmt"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/nodes"
)

func main() {
	sim := engine.NewSimulation()

	fastPath := network.SatellitePath{
		Name:       "path_leo_fast",
		Delay:      0.1,
		SpikeProb:  0.3,
		SpikeDelay: 2.0,
	}

	slowPath := network.SatellitePath{
		Name:       "path_geo_slow",
		Delay:      0.8,
		SpikeProb:  0.0,
		SpikeDelay: 0.0,
	}

	satnet := &network.SatNetRouter{
		Paths: []network.SatellitePath{fastPath, slowPath},
	}

	nodeA := nodes.NewGroundStation("station_A", satnet)
	nodeB := nodes.NewGroundStation("station_B", satnet)

	fmt.Println("--- Starting SatNet Simulation ---")
	nodeA.Send(sim, nodeB, 10)
	nodeB.Send(sim, nodeA, 10)

	sim.Run(20.0)
	fmt.Println("--- Simulation Complete ---")
}
