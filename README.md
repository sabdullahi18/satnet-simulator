# satnet-simulator

This discrete-event simulator models ground stations, routers, and satellite paths with variable delays, jitter, and network spikes.

## Project Structure

- **`cmd/satnet/main.go`**: Defines paths (LEO/GEO), initialises stations, and starts the event loop
- **`internal/engine/simulation.go`**: Priority-queue-based event scheduler
- **`internal/network/`**
    - `packet.go`: Defines the `Packet` struct and metadata (ID, Source, CreationTime)
    - `path.go`: Implements `SatellitePath`. Handles latency calculations, uniform jitter (0.5s-2.0s), and random spike events
    - `router.go`: Contains logic for path selection. Currently implements a "lowest-delay" routing strategy
- **`internal/nodes/station.go`**: Defines `GroundStation`. Handles packet generation at 1-second intervals

## Simulation Logic
- **Lowest-Delay Routing**: The router examines all available paths and forwards packets to the one with the smallest base delay
- **Network Jitter**: Every path introduces a random uniform delay between 0.5s and 2.0s per packet
- **Spike Events**: Paths can be configured with a `spike_prob`. If triggered, an additional `spike_delay` is added to the packet's traversal time

## Getting Started

### Prerequisites
- Go 1.18 or higher

### Installation
```bash
go mod init satnet-simulator
go mod tidy
