package main

import (
	"fmt"
	"math/rand"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/nodes"
)

func main() {
	rand.Seed(time.Now().UnixNano())
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

	sender := nodes.NewGroundStation("client", satnet)
	receiver := nodes.NewGroundStation("server", nil) 

	fmt.Println("--- Starting SatNet Simulation ---")
	sender.Send(sim, receiver, 10)

	sim.Run(20.0)
	fmt.Println("--- Simulation Complete ---")
}
