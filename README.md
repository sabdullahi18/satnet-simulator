# satnet-simulator

A discrete-event simulator for studying query-based verification of satellite network performance claims. The simulator models an adversarial interaction between a **verifier** (a client auditing a network) and a **prover** (the network operator being audited), and tests whether the verifier can detect dishonest delay reporting using only observable packet delays and queried claims — without any trusted third party or ground truth access.

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Simulation Engine](#simulation-engine)
4. [Delay Model](#delay-model)
5. [Packet Targeting](#packet-targeting)
6. [Prover and Answering Strategies](#prover-and-answering-strategies)
7. [Verifier and Contradiction Detection](#verifier-and-contradiction-detection)
8. [Experiment Structure](#experiment-structure)
9. [Running the Simulator](#running-the-simulator)

---

## Overview

Satellite network providers (SNPs) are trusted to report accurate performance metrics to clients who pay for quality-of-service guarantees. A misbehaving SNP might selectively delay certain packets while claiming to deliver all traffic at minimal delay. The client, observing only their own packets' arrival times, cannot easily detect misbehaviour.

This simulator explores a query-based verification scheme: the verifier sends packets in batches sharing the same send time, observes their actual delivery delays, and then queries the prover with questions of the form _"Was delay X minimal for packets sent at time t"_ where X is the delay that the verifier observed for a randomly selected packet from the batch corresponding to time t. Two packets sent simultaneously traverse the same network path at the same moment, so their base propagation delay is identical. This holds because all packets in a batch enter the network at the same time and therefore encounter the same orbital geometry, the same routing topology, and the same physical path through the satellite constellation, meaning the speed-of-light propagation component is the same for all of them. This also assumes that packet prioritisation or bandwidth reservation is in place to guarantee the base propagation remains identical.

If one packet experienced additional delay and the prover claims the observed delay was minimal, but the verifier observed another packet from the same batch arrive sooner -- that is a logical contradiction that exposes misbehaviour (whether caused by deliberate manipulation or incompetence). While exact time contradictions are the base case for this project, in practice, sending packets at the exact same instant can be infeasible, and satellite network paths continuously change delays, so tiny delay differences within a batch may be normal.

The simulator tests several prover strategies and measures the verifier's ability to detect each one. In particular, the architecture enables testing four classes of network behaviour: (i) honest and well-behaving; (ii) honest but incompetent; (iii) malicious and well-behaving; (iv) malicious and incompetent -- all while experimenting with different levels of incompetence and different attack strategies.

---

## System Architecture

$\color{Red}{\textsf{ADD SYSTEM ARCHITECTURE}}$

The flow through the system during a single trial is:

```
Packets scheduled in batches
        |
        v
Router.Forward()
  |-- Determines if packet is targeted (deliberate delay)
  |-- Determines if packet experiences higher delay due to network incompetence (e.g. suboptimal routing, longer path, etc.)
  |-- Sets delayed-packet flag in packet metadata (networks admits 'honest errors' before verification)
  |-- Calls DelayModel.ComputeTotalDelay()
  +-- Schedules delivery event at sim.Now + totalDelay
        |
        v
OnTransmission callback fires on delivery
  +-- Writes PacketRecord to Prover (ground truth stored internally)
        |
        v
Verifier.RunVerification()
  |-- Groups records into same-send-time batches
  |-- For each batch, finds the minimum observed delay
  |-- Randomly selects a packet P from the batch
  |-- Queries Prover: "Was delay X minimal for packets sent at time t?" (where X is observed delay for P, t is batch send time)
  +-- Checks prover answer against batch minimum for contradictions
        |
        v
VerificationResult: TRUSTED / SUSPICIOUS_FLAG_RATE / DISHONEST
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
totalDelay = baseDelay + incompetenceDelay + deliberateDelay
```

### Base Delay

The base delay models the fundamental propagation delay of a satellite path -- the minimum time a signal takes to travel through the network given the current orbital geometry, routing topology, etc. In real satellite networks this varies slowly as satellites move relative to ground stations. It is identical for all packets sent at the exact same instant (a batch), assuming they take the optimal path.

The base delay is generated once per trial during `DelayModel.Initialise(duration)`:

1. An initial base delay is sampled uniformly from `[BaseDelayMin, BaseDelayMax]`.
2. Transition times are generated using a Poisson process with rate `TransitionRate`. The inter-arrival time between successive transitions is sampled via the inverse-CDF method for the Exponential distribution:

$$\Delta t = -\frac{\ln(1 - U)}{\lambda}, \quad U \sim \text{Uniform}(0, 1)$$

A Poisson process is appropriate because transitions (satellite handoffs, routing changes) occur randomly and independently over time.

3. At each transition, a new base delay is sampled uniformly from `[BaseDelayMin, BaseDelayMax]`.

The resulting function is a step function: the base delay is constant within each interval, then jumps discontinuously at each transition. `GetBaseDelay(t)` retrieves the active segment for a given simulation time using binary search (`sort.Search`) over the transition timestamps.

**Default parameters:** `BaseDelayMin=20ms`, `BaseDelayMax=80ms`, `TransitionRate=0.05` transitions/second (on average one transition every 20 seconds over a 100-second simulation).

### Incompetence Delay

An incompetent network can introduce additional delay through various operational failures: routing a packet along a suboptimal or longer path, sending it through a congested link, or otherwise failing to deliver optimal performance. Each packet independently experiences congestion with probability `IncompetenceRate`. If affected, an extra delay is sampled from a log-normal distribution:

$$\text{incompetenceDelay} = e^{\mu + \sigma Z}, \quad Z \sim \mathcal{N}(0, 1)$$

The log-normal is a natural choice for queuing delay: it is strictly positive, right-skewed (most congestion events add small delays but occasional bursts add large ones), and arises naturally from multiplicative effects in queuing networks.

**Default parameters:** `IncompetenceRate=0.2` (20% of packets), `IncompetenceMu=-4.6`, `IncompetenceSigma=0.8`. With these parameters, the median incompetence delay is $e^{-4.6} \approx 10\text{ms}$ with substantial variance.

### Deliberate Delay

Thee adversary evaluates manipulation on a per-packet basis, e.g. the router selectively delays every 100th or every 1000th packet. If a packet is targeted by the adversarial router (see next section), an additional delay is sampled uniformly from `[DeliberateMin, DeliberateMax]`:

$$\text{deliberateDelay} \sim \text{Uniform}(\text{DeliberateMin}, \text{DeliberateMax})$$

**Default parameters:** `DeliberateMin=100ms`, `DeliberateMax=200ms`. These values are chosen to be meaningfully larger than typical incompetence delays, making targeted packets observably slower within a batch.

$\color{Red}{\textsf{JUSTIFY THESE PARAMS}}$

---

## Packet Targeting

**File:** `internal/network/router.go`

The Router wraps the delay model and applies adversarial targeting on a per-packet basis. Rather than assuming all packets within a batch are maliciously delayed together, the adversary selectively targets specific individual packets.

- `TargetNone` — honest router; no packet is ever maliciously delayed.
- `TargetRandom` — each packet is independently targeted with probability `TargetFraction`, drawn fresh per packet via `rand.Float64() < TargetFraction`.
- `TargetPeriodic` — The adversary deterministically targets every $n$-th packet, such as every 100th or 1000th packet.

These strategies represent the baseline attacker models: purely probabilistic (`TargetRandom`) and strictly deterministic (`TargetPeriodic`). $\color{Red}{\textsf{WHY SHOULD WE FOCUS ON THESE STRATS?}}$

`TargetRandom` is a Bernoulli sampling scheme: each packet is an independent Bernoulli trial, so the number of targeted packets across a batch follows a Binomial distribution. This means some batches may have zero targeted packets and others may have all packets targeted, purely by chance.

When `Router.Forward(sim, pkt, dest)` is called:

1. It determines whether the packet is targeted (`isTargeted()`) and whether it experiences an incompetence event (`IncompetenceRate`)
2. It calls DelayModel.ComputeTotalDelay() to get the full delay breakdown
3. It sets the `IsFlagged` metadata on the packet if the network determines it experienced an incompetence event. This flag is the network proactively admitting 'honest errors' in packet delivery before the verifier can discover them through queries
4. It schedules a delivery event `totalDelay` seconds into the future via `sim.Schedule`
5. When that event fires, it invokes the `OnTransmission` callback (which writes the record to the prover) and then calls `dest.Receive` to deliver the packet.

The `OnTransmission` callback is the handoff point between the simulation layer and the verification layer. It fires at the moment of delivery, after all delays have elapsed.

Because targeting is evaluated per-packet rather than per-batch, the packets within a single batch will experience completely different conditions. In a given batch, some packets might take the minimal delay path, some could be legitimately congested, and others could be maliciously delayed.

---

## Prover and Answering Strategies

**File:** `internal/verification/prover.go`

The prover represents the network operator's self-reporting mechanism, i.e. the interface through which the verifier asks the operator to attest to its own behaviour. In the simulation, the prover has access to the full ground truth (every `PacketRecord` including whether each packet was deliberately delayed) because it _is_ the operator. The question is whether it tells the truth.

### Query Interface

The verifier asks one question per randomly selected packet:

> _"Was delay X minimal for packets sent at time t?"_

Asking about the observed delay makes it more operationally feasible for the satellite network to respond, since the prover does not need to keep track of all individually forwarded packets. The prover answers with `Answer{IsMinimal bool}`:

- `IsMinimal = true` claims the observed delay corresponds to a packet that experienced no extra delay of any kind -- just the base propagation delay

### Answering Strategies

The prover's behaviour is controlled by `AdversaryConfig.AnsweringStr`:

#### `AnswerHonest`

The network is trustworthy and does not deliberately delay any packets. Consequently, the prover answers every query completely honestly. A packet is reported as minimal if it experienced no congestion, and it is flagged if it experienced incompetence delay. This serves as our trusted baseline.

#### `AnswerRandom`

The prover coin-flips its answer strictly for the "Was it minimal?" claim, regardless of actual delays. This is a naive adversary that makes no attempt at consistency and is trivially caught.

#### `AnswerLiesThatMinimal`

The prover claims that all packets, including the ones that were deliberately delayed, achieved minimal delay. It never flags anything. This is a reckless strategy; it completely denies the existence of any added delay, making it highly vulnerable to contradiction checks when compared to other packets in the same batch.

#### `AnswerLiesAboutTargeted`

The prover lies only about deliberately delayed packets, claiming they achieved minimal delay, while answering honestly about everything else. A packet that experienced only incompetence delay is correctly reported as non-minimal, and genuinely congested packets are flagged as usual. However, deliberately delayed packets are not flagged, since the prover intends to claim they were minimal. Flagging them would contradict that claim. The weakness is that if the verifier happens to query a targeted packet from a batch where another packet arrived sooner, the minimal claim is a direct contradiction.

#### `AnswerDelayedHonest`

The prover accurately reports honest packets, but for deliberately delayed packets, it relies on the flag to cover the delay. If the packet was not flagged, the prover still reports IsMinimal=false. This way, it never claims a targeted packet was minimal (so no direct contradiction is possible), but the overall pattern of non-minimal answers may raise the flag rate suspiciously high.
The weakness: if enough packets are targeted, the flag rate exceeds the FlagRateThreshold and the verifier becomes suspicious.

#### Flagging Inconsistency

If the prover flags a packet with delay $d_1$ (claiming it was congested) but does not flag a packet with delay $d_2$, and $d_1 < d_2$ is true. If the prover then claims that $d_2$ was minimal, this results in a clear, easily verified contradiction.

Otherwise, if the prover claims that $d_2$ was not minimal, they are effectively admitting they failed to flag a severely delayed packet. This indicates incompetence. In terms of our verification records, we consider this packet as one that should have been flagged, and we increase the prover's tracked flagging rate. This pushes them closer to the suspicious threshold.

### Flagging Strategies

In addition to answering queries, the network can employ different flagging strategies. While an honest network should always flag packets delivered with non-minimal delay, a dishonest network might strategically flag only a subset of delayed packets, hoping to evade detection on the remaining ones. The simulator can evaluate whether this partial flagging approach is viable for an attacker. More on this in next section.

### Lying Budget

Ultimately, what is the "lying budget" the network is allowed before they get caught? What is the frequency of lying they can reasonably get away with before hitting a definitive contradiction or exceeding the acceptable flagging rate? A question for the evaluation is identifying the optimal combination of answering and flagging strategies for malicious networks. By formulating hypotheses about these optimal combinations, we can verify if their success rate is better than all other evaluated strategies.

$\color{Red}{\textsf{THERE ARE MORE ADVERSARIAL STRATEGIES}}$

---

## Verifier and Contradiction Detection

**File:** `internal/verification/verifier.go`

The verifier operates without access to ground truth. It knows only:

- The `ActualDelay` of every packet it observed (measured directly)
- The `SentTime` of every packet
- The `IsFlagged` metadata on each delivered packet (set by the network during forwarding)
- The prover's answers to its queries

### Flagging Before Querying

It is critical to understand the chronological flow of information. The interaction happens in two distinct phases:

- Flagging (Network-Initiated): Before any queries are made, the network can proactively flag packets it claims experienced legitimate congestion
- Querying (Verifier-Initiated): After observing the delays and the network's congestion flags, the verifier actively queries the network about specific packets

### Classification

- `Honest`: The network accurately reports minimal packets, correctly flags packets affected by incompetence, and does not inject deliberate delay
- `Dishonest`: This encompasses both malicious actors and incompetent networks. If a network lies to cover up targeted delays (malice) or fails to accurately flag severely delayed packets (incompetence), it is classified as Dishonest. From the customer's perspective, both behaviours violate the service level agreement and warrant switching providers

### Batch Grouping

The verifier groups all `TransmissionRecord`s by `int(SentTime)`, i.e. the send time truncated to the nearest integer second. Every packet sent within the same one-second window forms a batch.

Because packets in the same batch are sent simultaneously, they all encounter the same base delay (the piecewise-constant base delay function returns the same value for all of them). Any difference in their observed delays must come from either congestion or malicious delay, both of which are the things the prover is being asked to attest to.

### Contradiction Check

Batches are processed and iterated up to `MaxQueries` total prover queries. $\color{Red}{\textsf{DO WE NEED MAX QUERIES?}}$

For each batch:

1. Find `minDelay`: the smallest `ActualDelay` observed across all packets in the batch.
2. For a packet `p` in the batch, query the prover: _"Was delay X minimal for packets sent at time t?"_
3. If `ans.IsMinimal == true` **and** `p.ActualDelay > minDelay`, record a **contradiction**.

If the prover says delay X was minimal, it is claiming P experienced only the base propagation delay. But another packet Q in the same batch (same send time, same base delay) arrived sooner. Therefore P could not have been minimal — the prover is lying.

This is a zero-false-positive detection mechanism: it is logically impossible for an honest prover to produce a contradiction, because an honest prover would never claim a non-minimal packet was minimal. In this context, a "false positive" would mean incorrectly classifying an honest network as dishonest, while a "true positive" means successfully catching a genuinely malicious network.

Also, as mentioned in [Flagging Inconsistency](#flagging-inconsistency), if a packet with delay $d_1$ is flagged, but a packet with delay $d_2$ is not flagged (where $d_1 < d_2$), the verifier queries $d_2$. If the prover claims $d_2$ was minimal, it triggers a direct contradiction. If the prover claims $d_2$ was not minimal, the network admits it failed to flag a delayed packet. The verifier penalises this incompetence by treating $d_2$ as a packet that should have been flagged, inflating the network's tracked flagging rate. If this rate exceeds the acceptable threshold $\tau$, the network is caught.

### Statistical Framework

The framework evaluates the network's behaviour by tracking the probabilities of three distinct modes:

- **$H_0$ (Honest):** The SNP operates truthfully, answering queries accurately
- **$H_1$ (Incompetent):** The SNP provides unreliable answers
- **$H_2$ (Malicious):** The SNP deliberately delays targeted packets

(Note: $H_1$ and $H_2$ both ultimately result in a "Dishonest" verdict from a customer SLA perspective.)

#### Prior Distribution

The verifier begins each trial with no prior knowledge of the SNP's behaviour. Initialise the posterior with a uniform (uninformative) prior:
$$P(H_0) = P(H_1) = P(H_2) = \frac{1}{3}$$

#### Bayesian Updating
 
As the verifier processes batches and accumulates evidence $E_1, E_2, \dots, E_n$, it updates the posterior probability of each hypothesis using Bayes' theorem. After observing evidence $E_n$, the posterior is updated as:
 
$$P(H_j \mid E_1, \dots, E_n) = \frac{P(E_n \mid H_j) \cdot P(H_j \mid E_1, \dots, E_{n-1})}{\sum_{k=0}^{2} P(E_n \mid H_k) \cdot P(H_k \mid E_1, \dots, E_{n-1})}$$
 
where $P(E_n \mid H_j)$ is the likelihood of the observed evidence under hypothesis $H_j$, and the denominator is a normalising constant ensuring the posteriors sum to 1.

#### Logical Contradictions
 
**Under $H_0$ (Honest):** An honest prover never claims a non-minimal packet was minimal:
 
$$P(\text{contradiction} \mid H_0) = \epsilon \approx 10^{-9}$$
 
This is set to a near-zero value (rather than exactly zero) to prevent numerical issues where a single contradiction would drive $P(H_0 \mid E) = 0$ irrecoverably. Conceptually, this represents the vanishingly small probability of a system-level error.
 
**Under $H_1$ (Incompetent):** An incompetent prover is not actively trying to deceive but may give unreliable answers. The probability of an incompetent prover accidentally producing a contradiction is also near zero:
 
$$P(\text{contradiction} \mid H_1) = \epsilon \approx 10^{-9}$$
 
**Under $H_2$ (Malicious):** A malicious prover deliberately delays packets and then could lie about them. When queried about a targeted packet, it risks claiming it was minimal when another packet in the same batch arrived sooner. The probability of a contradiction under $H_2$ is high:
 
$$P(\text{contradiction} \mid H_2) = 1 - \epsilon \approx 1.0$$
 
A single contradiction therefore produces an overwhelming Bayesian shift toward $H_2$, reflecting the fact that contradictions are essentially impossible under honest or merely incompetent operation but are a natural consequence of malicious lying.
 
#### Clean Queries (No Contradiction)
 
When a query produces no contradiction, this is mild evidence in favour of honesty. The likelihoods are the complements of the contradiction likelihoods:
 
$$P(\text{clean} \mid H_0) = 1 - \epsilon \approx 1.0$$
 
$$P(\text{clean} \mid H_1) = 1 - \eta$$
 
$$P(\text{clean} \mid H_2) = \eta$$
 
A single clean query barely moves the posteriors, but many consecutive clean queries gradually accumulate evidence for $H_0$ and against $H_2$. The rate at which this accumulation occurs is governed by $\eta$: a small $\eta$ means each clean query provides stronger evidence against malice (since $P(\text{clean} \mid H_2) = \eta$ is very small), while a large $\eta$ makes each clean query less informative.
 
#### Flagging Inconsistencies
 
When the verifier detects an unflagged packet whose delay exceeds a flagged packet in the same batch, and the prover admits it was not minimal, this is evidence of operational incompetence. The likelihoods penalise $H_0$ (honest networks should flag consistently) and favour $H_1$:
 
$$P(\text{flag inconsistency} \mid H_0) \ll P(\text{flag inconsistency} \mid H_1)$$
 
#### The Error Tolerance Parameter $\eta$
 
Rather than hard-coding the likelihood constants, the framework introduces a single tunable parameter $\eta \in (0, 1)$ that represents the **maximum tolerable error rate** — the fraction of the time the network is permitted to give an incorrect answer before the verifier considers it dishonest.
 
This parameter governs the sensitivity of the Bayesian update. Setting $\eta = 0.01$ means _"the network cannot be wrong more than 1% of the time."_ The likelihoods for contradiction evidence are then derived from $\eta$:
 
$$P(\text{contradiction} \mid H_0) = \epsilon \quad \text{(system-level error, fixed at } \approx 10^{-9}\text{)}$$
 
$$P(\text{contradiction} \mid H_1) = \eta \quad \text{(incompetent prover's error rate)}$$
 
$$P(\text{contradiction} \mid H_2) = 1 - \eta \quad \text{(malicious prover, high contradiction risk)}$$
 
By adjusting $\eta$, we control how forgiving the verifier is toward the network. A smaller $\eta$ (e.g., 0.001) makes the verifier very strict — even rare contradictions strongly implicate dishonesty. A larger $\eta$ (e.g., 0.10) allows more room for legitimate errors before the posteriors shift decisively.
 
The experimental evaluation systematically sweeps over $\eta$ to determine:
- At what tolerance levels can the verifier reliably distinguish honest from dishonest networks?
- How does the number of queries required to reach a confident verdict change with $\eta$?
- What is the "lying budget" — the maximum fraction of dishonest answers the network can give while remaining undetected under a given $\eta$?
 
#### Sequential Stopping
 
The framework does not require a fixed number of queries. Instead, it operates sequentially. The verifier continuously issues queries and accumulates evidence until the posterior probability of any single hypothesis exceeds a predefined confidence threshold $\alpha$ (e.g., 0.95).
 
Formally, the protocol halts and issues a definitive verdict when:
 
$$\max_j \, P(H_j \mid E_1, \dots, E_n) > \alpha$$
 
This sequential approach guarantees statistical rigour while dynamically minimising the number of network queries required to catch a dishonest provider. Alternatively, the verifier halts if it exhausts all available batches.
 
#### Verdict Derivation
 
After processing concludes (either by reaching the confidence threshold or exhausting batches), the verifier issues a verdict:
 
| Condition                          | Verdict       | `Trustworthy` |
| ---------------------------------- | ------------- | ------------- |
| $P(H_0 \mid E) > \alpha$          | `TRUSTED`     | `true`        |
| $P(H_1 \mid E) > \alpha$          | `DISHONEST`   | `false`       |
| $P(H_2 \mid E) > \alpha$          | `DISHONEST`   | `false`       |
| No posterior exceeds $\alpha$      | `INCONCLUSIVE`| depends on $P(H_0)$ |
 
Both $H_1$ and $H_2$ map to `DISHONEST` because, from the customer's SLA perspective, an incompetent network that fails to flag delayed packets is indistinguishable from a malicious one — both result in degraded service that the provider misrepresents.

$\color{Red}{\textsf{DOUBLE CHECK PARAMETERS HERE}}$
 
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

1. Creates a fresh simulation, delay model, router, and prover.
2. Initialises the delay model (generates the piecewise-constant base delay function for the trial's duration).
3. Schedules all packets.
4. Runs the simulation to completion.
5. Collects all `PacketRecord`s from the prover into a flat list.
6. Instantiates a `Verifier`, ingests the records, and runs verification.
7. Returns a `TrialResult` with verdict, confidence, query count, contradiction count, and ground-truth statistics.

### Sweeping the Error Tolerance $\eta$
 
The primary experimental axis is the error tolerance parameter $\eta$. For each prover strategy, the simulator runs a sweep over a range of $\eta$ values (e.g., $\eta \in \{0.001, 0.005, 0.01, 0.05, 0.10, 0.20\}$) and records how the detection outcome changes. This reveals the relationship between the verifier's strictness and its ability to classify different types of network behaviour.
 
For each combination of (prover strategy, $\eta$ value), multiple independent trials are executed to produce statistically stable results. The key metrics recorded per configuration are:
 
- **Detection rate:** fraction of trials that correctly classified the network's true behaviour
- **Mean queries to verdict:** how many prover queries were needed before $\alpha$ was reached
- **Final posterior distribution:** the terminal values of $P(H_0)$, $P(H_1)$, and $P(H_2)$
- **Contradiction count:** how many logical contradictions were observed

### Aggregate Metrics

After all trials, the runner computes standard binary classification metrics over the trial verdicts, treating each trial as a binary classification of whether the prover was adversarial:

- **True Positive Rate (TPR):** fraction of adversarial trials correctly identified as untrustworthy.
- **False Negative Rate (FNR):** fraction of adversarial trials incorrectly trusted.
- **True Negative Rate (TNR):** fraction of honest trials correctly trusted.
- **False Positive Rate (FPR):** fraction of honest trials incorrectly flagged.

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
 
Each trial prints its verdict, posterior probabilities ($P(H_0)$, $P(H_1)$, $P(H_2)$), query count, and contradiction count. After all trials for a given configuration, a summary reports TPR/FNR or TNR/FPR. When running an $\eta$-sweep, results are grouped by tolerance level so the effect of the parameter is immediately visible.
 
### Configuration
 
All experiment parameters are set in `cmd/satnet/main.go` by constructing an `ExperimentConfig`. The key fields are:
 
$\color{Red}{\textsf{ADD THIS LATER}}$
