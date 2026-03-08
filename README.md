# satnet-simulator

A discrete-event simulator for studying contradiction-based verification of satellite network performance claims. The simulator models an adversarial interaction between a **verifier** (a client auditing a network) and an **oracle** (the network operator being audited), and tests whether the verifier can detect dishonest delay reporting using only observable packet delays and queried claims — without any trusted third party or ground truth access.

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Simulation Engine](#simulation-engine)
4. [Delay Model](#delay-model)
5. [Packet Targeting](#packet-targeting)
6. [Oracle and Answering Strategies](#oracle-and-answering-strategies)
7. [Verifier and Contradiction Detection](#verifier-and-contradiction-detection)
8. [Experiment Structure](#experiment-structure)
9. [Running the Simulator](#running-the-simulator)

---

## Overview

Satellite network providers (SNPs) are trusted to report accurate performance metrics to clients who pay for quality-of-service guarantees. A dishonest SNP might selectively delay certain packets while claiming to deliver all traffic at minimal delay. The client, observing only their own packets' arrival times, cannot easily detect malice.

This simulator explores a contradiction-based verification scheme: the verifier sends packets in batches sharing the same send time, observes their actual delivery delays, and then queries the oracle with questions of the form _"Did packet P achieve minimal delay?"_ Two packets sent simultaneously traverse the same network path at the same moment, so their base propagation delay is identical. If one packet is maliciously delayed and the oracle claims it was minimal, but the verifier observed another packet from the same batch arrive sooner -- that is a logical contradiction that exposes dishonesty.

The simulator tests several oracle strategies and measures the verifier's ability to detect each one.

---

## System Architecture

```
satnet-simulator/
├── cmd/satnet/
│   └── main.go                   # Entry point; defines and runs experiments
├── internal/
│   ├── engine/
│   │   └── simulation.go         # Discrete-event simulation engine
│   ├── experiment/
│   │   └── runner.go             # Experiment and trial orchestration
│   ├── network/
│   │   ├── packet.go             # Packet type
│   │   ├── delay_model.go        # Statistical delay model
│   │   └── router.go             # Adversarial router with targeting logic
│   └── verification/
│       ├── types.go              # Query, Answer, and PacketRecord types
│       ├── oracle.go             # Oracle with configurable answering strategies
│       └── verifier.go           # Verifier with contradiction detection
├── go.mod
└── README.md
```

The flow through the system during a single trial is:

```
Packets scheduled in batches
        |
        v
Router.Forward()
  |-- Determines if packet is targeted (adversarial delay)
  |-- Determines if packet experiences congestion (legitimate delay)
  |-- Calls DelayModel.ComputeTotalDelay()
  +-- Schedules delivery event at sim.Now + totalDelay
        |
        v
OnTransmission callback fires on delivery
  +-- Writes PacketRecord to Oracle (ground truth stored internally)
        |
        v
Verifier.RunVerification()
  |-- Groups records into same-send-time batches
  |-- For each batch, finds the minimum observed delay
  |-- Queries Oracle: "Was packet P minimal?"
  +-- Checks oracle answer against batch minimum for contradictions
        |
        v
VerificationResult: TRUSTED / SUSPICIOUS_FLAG_RATE / MALICIOUS
```

---

## Simulation Engine

**File:** `internal/engine/simulation.go`

The engine is a standard discrete-event simulation. Simulation time is a continuous `float64` representing seconds; no real wall-clock time elapses between events.

The core data structure is an event queue: a sorted slice of `Event{Time float64, Action func()}`. Two operations drive the engine:

- `Schedule(delay float64, action func())` inserts a new event at `sim.Now + delay`, keeping the queue sorted by timestamp.
- `Run(until float64)` pops events from the front of the queue in chronological order, advances `sim.Now` to the event's timestamp, and executes its action. It stops when the queue is empty or the next event's time exceeds `until`.

Because `sim.Now` is only advanced when an event is actually processed, time only moves forward to instants where something happens.

---

## Delay Model

**File:** `internal/network/delay_model.go`

Every packet's end-to-end delay is evaluated on a per-packet basis. The total time it takes for a packet to traverse the network is decomposed into three independent, additive components:

```
totalDelay = baseDelay + legitDelay + maliciousDelay
```

- Minimal Delay Path: Packets taking the optimal path experience only baseDelay
- Congested Path: Packets experiencing normal network congestion will take baseDelay + legitDelay
- Malicious Path: If the network decides to actively target a packet, it will experience baseDelay + legitDelay + maliciousDelay

### Base Delay

The base delay models the fundamental propagation delay of a satellite path -- the minimum time a signal takes to travel through the network given the current orbital geometry, routing topology, etc. In real satellite networks this varies slowly as satellites move relative to ground stations. It is identical for all packets sent at the exact same instant (a batch), assuming they take the optimal path.

The base delay is modelled as a piecewise-constant function of time, generated once per trial during `DelayModel.Initialise(duration)`:

1. An initial base delay is sampled uniformly from `[BaseDelayMin, BaseDelayMax]`.
2. Transition times are generated using a Poisson process with rate `TransitionRate`. The inter-arrival time between successive transitions is sampled via the inverse-CDF method for the Exponential distribution:

$$\Delta t = -\frac{\ln(1 - U)}{\lambda}, \quad U \sim \text{Uniform}(0, 1)$$

A Poisson process is appropriate because transitions (satellite handoffs, routing changes) occur randomly and independently over time.

3. At each transition, a new base delay is sampled uniformly from `[BaseDelayMin, BaseDelayMax]`.

The resulting function is a step function: the base delay is constant within each interval, then jumps discontinuously at each transition. `GetBaseDelay(t)` retrieves the active segment for a given simulation time using binary search (`sort.Search`) over the transition timestamps.

**Default parameters:** `BaseDelayMin=20ms`, `BaseDelayMax=80ms`, `TransitionRate=0.05` transitions/second (on average one transition every 20 seconds over a 100-second simulation).

### Legitimate Congestion Delay

Each packet independently experiences congestion with probability `CongestionRate`. If congested, an extra delay is sampled from a log-normal distribution:

$$\text{legitDelay} = e^{\mu + \sigma Z}, \quad Z \sim \mathcal{N}(0, 1)$$

The log-normal is a natural choice for queuing delay: it is strictly positive, right-skewed (most congestion events add small delays but occasional bursts add large ones), and arises naturally from multiplicative effects in queuing networks.

**Default parameters:** `CongestionRate=0.2` (20% of packets), `LegitMu=-4.6`, `LegitSigma=0.8`. With these parameters, the median legitimate congestion delay is $e^{-4.6} \approx 10\text{ms}$ with substantial variance.

### Malicious Delay

The adversary evaluates manipulation on a per-packet basis, e.g. the router selectively delays every 100th or every 1000th packet. If a packet is targeted by the adversarial router (see next section), an additional delay is sampled uniformly from `[MaliciousMin, MaliciousMax]`:

$$\text{maliciousDelay} \sim \text{Uniform}(\text{MaliciousMin}, \text{MaliciousMax})$$

**Default parameters:** `MaliciousMin=100ms`, `MaliciousMax=200ms`. These values are chosen to be meaningfully larger than typical legitimate congestion, making targeted packets observably slower within a batch.

---

## Packet Targeting

**File:** `internal/network/router.go`

The Router wraps the delay model and applies adversarial targeting on a strictly per-packet basis. Rather than assuming all packets within a batch are maliciously delayed together, the adversary selectively targets specific individual packets.

- `TargetNone` — honest router; no packet is ever maliciously delayed.
- `TargetRandom` — each packet is independently targeted with probability `TargetFraction`, drawn fresh per packet via `rand.Float64() < TargetFraction`.
- `TargetPeriodic` — The adversary deterministically targets every $n$-th packet, such as every 100th or 1000th packet.

`TargetRandom` is a Bernoulli sampling scheme: each packet is an independent Bernoulli trial, so the number of targeted packets across a batch follows a Binomial distribution. This means some batches may have zero targeted packets and others may have all packets targeted, purely by chance.

When `Router.Forward(sim, pkt, dest)` is called:

1. It determines whether the packet is targeted based on the targeting mode (TargetRandom or TargetPeriodic)
2. It determines if the packet independently experiences legitimate congestion based on the `CongestionRate`
3. It calls DelayModel.ComputeTotalDelay() to get the full delay breakdown
4. It schedules a delivery event `totalDelay` seconds into the future via `sim.Schedule`
5. When that event fires, it invokes the `OnTransmission` callback (which writes the record to the oracle) and then calls `dest.Receive` to deliver the packet.

The `OnTransmission` callback is the handoff point between the simulation layer and the verification layer. It fires at the moment of delivery, after all delays have elapsed.

Because targeting is evaluated per-packet rather than per-batch, the packets within a single batch will experience completely different conditions. In a given batch, some packets might take the minimal delay path, some could be legitimately congested, and others could be maliciously delayed.

---

## Oracle and Answering Strategies

**File:** `internal/verification/oracle.go`

The oracle represents the network operator's self-reporting mechanism, i.e. the interface through which the verifier asks the operator to attest to its own behaviour. In the simulation, the oracle has access to the full ground truth (every `PacketRecord` including whether each packet was maliciously delayed) because it _is_ the operator. The question is whether it tells the truth.

### Query Interface

The verifier asks one question per packet:

> _"Did packet P achieve minimal delay?"_

The oracle answers with `Answer{IsMinimal bool, IsFlagged bool}`:

- `IsMinimal = true` claims the packet experienced no extra delay of any kind -- just the base delay
- `IsFlagged = true` claims the packet experienced legitimate congestion (but not manipulation)

### Answering Strategies

The oracle's behaviour is controlled by `AdversaryConfig.AnsweringStr`:

#### Honest

The network is trustworthy and does not maliciously delay any packets. Consequently, the oracle answers every query completely honestly. A packet is reported as minimal if it experienced no congestion, and it is flagged if it experienced legitimate congestion. This serves as our trusted baseline.

#### Random

- `AnswerRandomMinimal`: The oracle coin-flips its answer strictly for the "Was it minimal?" claim, regardless of actual delays
- `AnswerRandomFlagging`: The oracle coin-flips whether it flags a packet for congestion, regardless of whether it actually experienced congestion or malicious delay

#### Naive Gaslighting (`AnswerLiesThatMinimal`)

The oracle claims that all packets, including the ones that were maliciously delayed, achieved minimal delay. It never flags anything. This is a reckless strategy; it completely denies the existence of any added delay, making it highly vulnerable to contradiction checks when compared to other packets in the same batch.

#### Flagging Inconsistency

If the oracle flags a packet with delay $d_1$ (claiming it was congested) but does not flag a packet with delay $d_2$, and $d_1 < d_2$ is true. If the oracle then claims that $d_2$ was minimal, this results in a clear, easily verified contradiction.

Otherwise, if the oracle claims that $d_2$ was not minimal, they are effectively admitting they failed to flag a severely delayed packet. This indicates incompetence. In terms of our verification records, we consider this packet as one that should have been flagged, and we artificially increase the oracle's tracked flagging rate. This pushes them closer to the suspicious threshold.

### Lying Budget

Ultimately, what is the "lying budget" the network is allowed before they get caught? By forcing the network to maintain internal consistency across minimum claims, flagging rates, and observed delays, the verifier constrains the adversary. What is the frequency of lying they can reasonably get away with before hitting a definitive contradiction or exceeding the acceptable flagging rate?  Evaluating this budget is one of the primary outputs of this simulator.

---

## Verifier and Contradiction Detection

**File:** `internal/verification/verifier.go`

The verifier operates without access to ground truth. It knows only:

- The `ActualDelay` of every packet it observed (measured directly).
- The `SentTime` of every packet.
- The oracle's answers to its queries.

### Batch Grouping

The verifier groups all `TransmissionRecord`s by `int(SentTime)`, i.e. the send time truncated to the nearest integer second. Every packet sent within the same one-second window forms a batch.

Because packets in the same batch are sent simultaneously, they all encounter the same base delay (the piecewise-constant base delay function returns the same value for all of them). Any difference in their observed delays must come from either congestion or malicious delay, both of which are the things the oracle is being asked to attest to.

### Contradiction Check

Batches are shuffled into random order before processing (to avoid systematic bias) and iterated up to `MaxQueries` total oracle queries.

For each batch:

1. Find `minDelay`: the smallest `ActualDelay` observed across all packets in the batch.
2. For each packet `p` in the batch, query the oracle: _"Was packet `p` minimal?"_
3. If `ans.IsMinimal == true` **and** `p.ActualDelay > minDelay`, record a **contradiction**.

If the oracle says packet P was minimal, it is claiming P experienced only the base propagation delay. But another packet Q in the same batch (same send time, same base delay) arrived sooner. Therefore P could not have been minimal — the oracle is lying.

This is a zero-false-positive detection mechanism: it is logically impossible for an honest oracle to produce a contradiction, because an honest oracle would never claim a non-minimal packet was minimal.

### Flag Rate Analysis

Independently of contradiction detection, the verifier tracks the fraction of oracle answers where `IsFlagged=true`. A high flag rate suggests the oracle is attributing many packets to congestion, which may indicate it is using congestion as a cover story for malicious delays (as in the `AnswerDelayedHonest` strategy).

If `flaggingRate > FlagRateThreshold` (default 30%) and no contradictions were found, the verdict is `SUSPICIOUS_FLAG_RATE`.

### Verdict Logic

| Condition                                 | Verdict                | `Trustworthy` | `Confidence`         |
| ----------------------------------------- | ---------------------- | ------------- | -------------------- |
| Any contradictions found                  | `MALICIOUS`            | `false`       | `1.0`                |
| No contradictions, flag rate > threshold  | `SUSPICIOUS_FLAG_RATE` | `false`       | `flaggingRate`       |
| No contradictions, flag rate <= threshold | `TRUSTED`              | `true`        | `1.0 - flaggingRate` |

The `MALICIOUS` verdict is issued with certainty (`Confidence=1.0`) because a contradiction is a deductive proof of dishonesty: no probabilistic inference is required. The `SUSPICIOUS_FLAG_RATE` verdict is a probabilistic signal, not a proof.

---

## Experiment Structure

**File:** `internal/experiment/runner.go`, `cmd/satnet/main.go`

### Packet Batching

Packets are scheduled in batches during trial setup. For a trial with `NumPackets` packets and `BatchSize` packets per batch, there are `NumPackets / BatchSize` batches. Batch `b` is sent at simulation time:

```
sendTime = b * (SimDuration / numBatches)
```

All packets within a batch are scheduled at exactly the same `sendTime`, which is what makes the batch-minimum comparison valid in the verifier.

### Trial Execution

Each trial:

1. Creates a fresh simulation, delay model, router, and oracle.
2. Initialises the delay model (generates the piecewise-constant base delay function for the trial's duration).
3. Schedules all packets.
4. Runs the simulation to completion.
5. Collects all `PacketRecord`s from the oracle into a flat list.
6. Instantiates a `Verifier`, ingests the records, and runs verification.
7. Returns a `TrialResult` with verdict, confidence, query count, contradiction count, and ground-truth statistics.

### Aggregate Metrics

After all trials, the runner computes standard binary classification metrics over the trial verdicts, treating each trial as a binary classification of whether the oracle was adversarial:

- **True Positive Rate (TPR):** fraction of adversarial trials correctly identified as untrustworthy.
- **False Negative Rate (FNR):** fraction of adversarial trials incorrectly trusted.
- **True Negative Rate (TNR):** fraction of honest trials correctly trusted.
- **False Positive Rate (FPR):** fraction of honest trials incorrectly flagged.

### Experiments Defined in `main.go`

Three experiments are run by default:

| Experiment                            | Targeting | Fraction | Oracle Strategy         | Expected Detection                       |
| ------------------------------------- | --------- | -------- | ----------------------- | ---------------------------------------- |
| `honest_baseline`                     | None      | —        | `AnswerHonest`          | Should be trusted (low FPR)              |
| `adversarial_10pct_delayed_honest`    | Random    | 10%      | `AnswerDelayedHonest`   | Elevated flag rate may trigger suspicion |
| `adversarial_20pct_lies_that_minimal` | Random    | 20%      | `AnswerLiesThatMinimal` | Direct contradiction -> MALICIOUS        |

---

## Running the Simulator

### Prerequisites

- Go 1.25 or higher

### Build and Run

```bash
go mod tidy
go build -o satnet ./cmd/satnet
./satnet
```

### Output

Each trial prints its verdict, confidence, query count, contradiction count, and flag rate. After all experiments, a summary table prints TPR/FNR or TNR/FPR for each experiment, along with the mean number of queries executed per detection.

### Configuration

All experiment parameters are set in `cmd/satnet/main.go` by constructing an `ExperimentConfig`. The key fields are:

```go
experiment.ExperimentConfig{
    Name:        string,         // Label for output
    NumPackets:  int,            // Total packets per trial
    BatchSize:   int,            // Packets sent simultaneously (>= 2 required)
    NumTrials:   int,            // Independent repetitions
    SimDuration: float64,        // Simulated seconds

    DelayModelConfig: network.DelayModelConfig{
        BaseDelayMin:   float64, // Minimum base propagation delay (seconds)
        BaseDelayMax:   float64, // Maximum base propagation delay (seconds)
        TransitionRate: float64, // Poisson rate of base delay transitions (per second)
        CongestionRate: float64, // Per-packet probability of legitimate congestion
        LegitMu:        float64, // Log-normal mu for congestion delay
        LegitSigma:     float64, // Log-normal sigma for congestion delay
        MaliciousMin:   float64, // Minimum adversarial delay added to targeted packets
        MaliciousMax:   float64, // Maximum adversarial delay added to targeted packets
    },

    TargetingConfig: network.TargetingConfig{
        Mode:           network.TargetNone | network.TargetRandom,
        TargetFraction: float64, // Fraction of packets targeted (for TargetRandom)
    },

    AdversaryConfig: verification.AdversaryConfig{
        AnsweringStr: verification.AnswerHonest |
                      verification.AnswerRandom |
                      verification.AnswerDelayedHonest |
                      verification.AnswerLiesThatMinimal,
    },

    VerificationConfig: verification.VerificationConfig{
        MaxQueries:        int,     // Maximum oracle queries per trial
        FlagRateThreshold: float64, // Flag rate above which SUSPICIOUS_FLAG_RATE is issued
    },
}
```
