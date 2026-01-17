# satnet-simulator

This discrete-event simulator verifies performance claims in satellite networks. This tool models the interaction between a client (verifier) and a network operator (oracle). The simulator generates traffic across paths with variable latency and jitter, allows the network to lie about its performance using various strategies, and then attempts to detect those lies using ZKP-style questioning combined with statistical analysis.

## Project Structure
```
satnet-simulator/
├── cmd/satnet/
│   └── main.go              # Entry point with experiments
├── internal/
│   ├── engine/
│   │   └── simulation.go    # Discrete event simulation engine
│   ├── experiment/
│   │   └── runner.go        # Experiment orchestration
│   ├── network/
│   │   ├── packet.go        # Packet model with sampling
│   │   └── router.go        # Adversarial router with delay injection
│   └── verification/
│       ├── query.go         # Query types and responses
│       ├── oracle.go        # SNP oracle with lying strategies
│       ├── contradiction.go # Contradiction detection system
│       ├── statistics.go    # Bayesian/SPRT analysis
│       └── verifier.go      # Main verification engine
├── go.mod
└── README.md
```
## Summary
### Query Types
- `QueryComparison`: "Which packet had better optimal delay: P_i or P_j?"
- `QueryOrdering`: "Rank these packets by optimal delay"
- `QueryPathHash`: "What is the hash of the path used for packet P_i?"
- `QueryDelayBound`: "Was the optimal delay above or below threshold X?"
- `QueryCongestionFlag`: "Was there congestion during time interval [t1, t2]?"

### The Lying Oracle
The network reports on its own behaviour but can be configured with specific lying strategies:
- `StrategyHonest`: Always tells the truth
- `StrategyAlwaysClaimShortest`: Always claims shortest path was used
- `StrategyRandomLies`: Lies with configurable probability
- `StrategySophisticated`: Maintains internally consistent lies
- `StrategyTargeted`: Lies specifically about delayed packets

### Contradiction Detection
- **Transitivity**: Builds directed graph of comparisons, detects cycles
- **Temporal Consistency**: Compares claimed vs observed delays
- **Physical Constraint**: Validates against speed-of-light bounds
- **Commitment**: Detects inconsistent answers to same queries

### Statistical Analysis
- **Bayesian Tracker**: Updates $P(\text{honest}|\text{evidence})$ after each query
- **SPRT Test**: Sequential hypothesis testing with early stopping
- **Probability Model**: Estimates queries needed for desired confidence

### Verification Framework
The verifier audits the network without needing access to the ground truth. It detects dishonesty via:
- **ZKP-Style Questioning**: Comparison queries that force the SNP into making claims that can be checked for consistency
- **Contradiction Detection**: Multiple detection methods including transitivity checking, temporal consistency, and physical constraint validation
- **Statistical Analysis**: Bayesian updating and Sequential Probability Ratio Testing (SPRT) for confidence-based detection

## Getting Started
### Prerequisites
- Go 1.25+ or higher

### Installation and Usage
```bash
go mod tidy
go build -o satnet ./cmd/satnet
./satnet
```

### Configuration
```go
config := experiment.ExperimentConfig{
    Name:        "my_experiment",
    NumPackets:  200,
    NumTrials:   20,
    SimDuration: 30.0,
    
    Paths: []network.SatellitePath{
        {Name: "LEO_FAST", Delay: 0.05, SpikeProb: 0.1, SpikeDelay: 0.5},
        {Name: "GEO_SLOW", Delay: 0.25, SpikeProb: 0.02, SpikeDelay: 0.3},
    },
    
    AdversarialConfig: network.AdversarialConfig{
        Mode:              network.ModeRandomDelay,
        DelayFraction:     0.10,  // Delay 10% of packets
        MinMaliciousDelay: 0.5,
        MaxMaliciousDelay: 2.0,
    },
    
    LyingStrategy:  verification.StrategySophisticated,
    LieProbability: 0.8,
    
    VerificationConfig: verification.VerificationConfig{
        SamplingRate:      0.10,
        MaxQueries:        500,
        TargetConfidence:  0.95,
        QueryStrategy:     verification.StrategyAdaptive,
    },
}
```
