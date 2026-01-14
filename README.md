# satnet-simulator

This discrete-event simulator analyses trust and verifies performance claims in satellite networks. This tool models the interaction between a client (verifier) and a network operator (oracle). The simulator generates traffic across paths with variable latency and jitter, allows the network to lie about its performance using various strategies, and then attempts to detect those lies using a consistency-based verification engine.

## Project Structure
```text
├── cmd/satnet/           # Entry point
│   └── main.go           # Scenario configuration and simulation loop
├── internal/
│   ├── engine/           # Event scheduling and virtual clock
│   │   └── simulation.go 
│   ├── network/          
│   │   ├── packet.go     
│   │   ├── path.go   
│   │   └── router.go
│   ├── nodes/            
│   │   └── station.go    # Ground stations (Senders/Receivers)
│   └── verification/     # Core logic for the oracle and verifier
│       ├── oracle.go     # Implements lying strategies
│       ├── verifier.go   # Implements contradiction detection
│       └── query.go      # Defines the query/response protocol
└── go.mod                
```
## Summary
### Network Simulation
- **Discrete-Event Engine**: Uses a priority queue for precise timing.
- **Satellite Paths**: Models LEO (Low Earth Orbit) and GEO (Geostationary) path characteristics.
- **Link Behaviour**: Variable base delays, random jitter (0.5s - 2.0s), probabilistic 'spike' events.

### The Lying Oracle
The network reports on its own behaviour but can be configured with specific lying strategies:
- **HONEST**: Always reports the truth.
- **ALWAYS_CLAIM_SHORTEST**: Claims every packet took the shortest path, regardless of reality.
- **MINIMISE_DELAY**: Reports falsified lower latency figures.
- **RANDOM_LIES**: Lies probabilistically to confuse the verifier.
- **SMART**: Attempts to maintain internal consistency (e.g., matching delay claims to path claims) to evade detection.

### Verification Framework
The verifier audits the network without needing access to the ground truth. It detects dishonesty via:
- **Internal Contradictions**: Checking if answers to different queries (path used vs. delay vs. shortest path boolean) logically align.
- **Physical Bounds Checks**: Flagging delays that violate the min and max thresholds.
- **Cryptographic Commitments**: Verifying path usage against SHA-256 hashes committed during transmission.
- **Statistical Aggregation**: Comparing individual packet reports against aggregate counts.

## Getting Started
### Prerequisites
- Go 1.25+ or higher

### Installation and Usage
```bash
go mod init satnet-simulator
go mod tidy
```

To run:
```bash
go run cmd/satnet/main.go
```
