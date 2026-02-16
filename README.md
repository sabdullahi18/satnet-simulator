# satnet-simulator
***OUTDATED!!***
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
### Strategy 1: Flagging Strategy
**Question: Which packets does the SNP *claim* had legitimate congestion?**

| Strategy | Description |
|----------|-------------|
| `FlagNone` | Never flag any packets |
| `FlagRandom` | Randomly flag packets with probability `FlagProbability` (e.g., 50%) |
| `FlagLowDelay` | Flag packets with lowest observed delays (harder to catch lies about these) |
| `FlagActualDelayed` | Flag packets that were actually maliciously delayed |

### Strategy 2: Answering Strategy  
**Question: How does the SNP answer "Which packet had minimum possible delay?"**

| Strategy | Description |
|----------|-------------|
| `AnswerHonest` | Always tell the truth about minimum delays |
| `AnswerRandom` | Randomly choose an answer |
| `AnswerClaimLowerObserved` | Always claim the packet with lower observed delay had min delay |
| `AnswerConsistent` | Maintain consistency with flagging claims |

The best strategy 2 should always claim the packet with lower observed delay was minimal, since the verifier can only see the relative delays (d1 vs d2), not the absolute minimum possible delay.

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
