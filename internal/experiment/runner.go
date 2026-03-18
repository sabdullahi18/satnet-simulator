package experiment

import (
	"fmt"
	"math/rand"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

type ExperimentConfig struct {
	Name               string
	NumPackets         int
	BatchSize          int
	NumTrials          int
	SimDuration        float64
	DelayModelConfig   network.DelayModelConfig
	TargetingConfig    network.TargetingConfig
	AdversaryConfig    verification.AdversaryConfig
	VerificationConfig verification.VerificationConfig
}

func DefaultExperimentConfig() ExperimentConfig {
	return ExperimentConfig{
		Name:        "default",
		NumPackets:  1000,
		BatchSize:   2,
		NumTrials:   5,
		SimDuration: 100.0,

		DelayModelConfig: network.DelayModelConfig{
			// BaseDelayMin / BaseDelayMax — one-way propagation + ground-segment
			// delay for a Starlink-class LEO constellation (~550 km altitude).
			//
			// Measured Starlink RTT is ~40–60 ms (25th–75th pct), with a
			// confirmed minimum of 20 ms:
			//   "The minimum measured latency was 20 ms, as publicly advertised."
			//   "The RTT to the European anchors remained constant — around 50 ms
			//    median, ranging from 40 ms (25th percentile) to 60 ms (75th)."
			//   — APNIC Blog, "Fact-checking Starlink's performance figures"
			//     (Nov 2022), https://blog.apnic.net/2022/11/28/fact-checking-starlinks-performance-figures/
			//
			// Halving the RTT range gives ~20–30 ms one-way under typical load.
			// The upper bound of 80 ms captures high-load/long-ground-path
			// conditions where RTT reaches ~150 ms (confirmed in the same dataset
			// and in SpaceX's own latency improvement reporting).
			//
			// See also: Handley, M. (2018). "Delay is Not an Option: Low Latency
			// Routing in Space." ACM HotNets'18. doi:10.1145/3286062.3286075
			// (Derives propagation delay from orbital mechanics at 550 km altitude
			// and shows LEO end-to-end delay is dominated by ground-segment path
			// length rather than orbital altitude for sub-continental distances.)
			BaseDelayMin: 0.020,
			BaseDelayMax: 0.080,

			// TransitionRate — Poisson rate (events/s) at which the piecewise
			// base delay changes segment (satellite handoff or beam switch).
			//
			// Starlink uses a globally time-synchronised controller that reassigns
			// satellite-to-ground links every 15 seconds:
			//   "Starlink employs a globally time-synchronized controller to manage
			//    the association of satellite-to-ground communication links with an
			//    interval of 15 seconds, at fixed 12-27-42-57 seconds of every
			//    minute."
			//   — Multiple measurement studies; confirmed in:
			//     Kassem et al., "A Browser-Based Measurement Study of Starlink,"
			//     ACM IMC 2022; and
			//     "A Detailed Characterization of Starlink One-way Delay,"
			//     ACM LEO Networking Workshop 2025 (doi:10.1145/3748749.3749090),
			//     which notes uplink delays are dominated by the 15-second
			//     reconfiguration cycle.
			//
			// A Poisson rate of 0.05/s gives a mean inter-transition time of
			// 1/0.05 = 20 s, which approximates the 15-second empirical cycle
			// while adding stochastic variation for paths spanning multiple beams.
			TransitionRate: 0.05,

			// IncompetenceRate — fraction of packets that incur anomalous extra
			// delay (misrouting, scheduling jitter, transient congestion bursts).
			//
			// 20% is a conservative upper bound for degraded conditions. Under
			// nominal Starlink operation, Ookla reports <1% packet loss and
			// infrequent anomalous delay spikes; 20% stress-tests the verifier
			// without rendering the network entirely unusable.
			// (Design parameter; no single external citation.)
			IncompetenceRate: 0.2,

			// IncompetenceMu / IncompetenceSigma — parameters of the log-normal
			// distribution (natural-log parameterisation) for the anomalous-delay
			// component.
			//
			// Implied statistics:
			//   median  = exp(-4.6)              ≈ 10 ms
			//   mean    = exp(-4.6 + 0.8²/2)     ≈ 14 ms
			//   95th pct = exp(-4.6 + 1.645·0.8) ≈ 38 ms
			//
			// Log-normal is well-established for queuing and forwarding delay in
			// packet networks. A seminal result:
			//   "At the most loaded time of day, the distribution of average
			//    queueing delays among different path segments follows closely a
			//    log-normal distribution."
			//   — Paxson, V. & Floyd, S. (1994). "Wide-Area Traffic: The Failure
			//     of Poisson Modeling." ACM SIGCOMM '94 / IEEE/ACM Trans.
			//     Networking 3(3):226–244 (1995). doi:10.1145/190314.190338
			//
			// The parameter values place the median anomalous delay (10 ms) well
			// below the base delay minimum (20 ms), so incompetence alone is
			// unlikely to produce delays that look deliberate.
			IncompetenceMu:    -4.6,
			IncompetenceSigma: 0.8,

			// DeliberateMin / DeliberateMax — uniform extra delay (s) injected by
			// an adversarial relay attempting to manipulate timing.
			//
			// The 100–200 ms range is chosen to be materially larger than the
			// base delay (20–80 ms) and the anomalous-delay 95th percentile
			// (~38 ms), so the verifier can statistically distinguish deliberate
			// manipulation from natural network variation.
			//
			// The floor of 100 ms is consistent with the threshold at which human
			// users perceive interactive-communication degradation (the ITU-T G.114
			// recommendation cites 150 ms one-way as the limit for "most
			// applications"; 100 ms is therefore the lower bound at which an
			// adversary begins imposing noticeable harm):
			//   ITU-T G.114 (2003). "One-way transmission time." §7: "The
			//   preferred maximum one-way delay is 150 ms."
			// (Design parameter; upper bound of 200 ms chosen to remain within a
			// single order of magnitude of the base delay for model tractability.)
			DeliberateMin: 0.100,
			DeliberateMax: 0.200,
		},

		TargetingConfig: network.DefaultHonestTargeting(),

		AdversaryConfig: verification.AdversaryConfig{
			AnsweringStr: verification.AnswerHonest,
		},

		VerificationConfig: verification.DefaultVerificationConfig(),
	}
}

// flaggingFnForStrategy returns the FlaggingFn that the router should use for a
// given answering strategy. This determines which packets the network proactively
// flags as having experienced 'honest errors' during forwarding, before the
// verifier issues any queries.
func flaggingFnForStrategy(strategy verification.AnsweringStrategy) network.FlaggingFn {
	switch strategy {
	case verification.AnswerHonest:
		// Only flag packets that genuinely experienced incompetence delay.
		return func(hasIncompetence, wasDelayed bool) bool {
			return hasIncompetence
		}

	case verification.AnswerDelayedHonest:
		// Flag deliberately delayed packets as "congestion" to provide cover,
		// in addition to genuinely congested packets. This pushes the flag rate
		// higher, which may eventually exceed the FlagRateThreshold and trigger
		// SUSPICIOUS_FLAG_RATE.
		return func(hasIncompetence, wasDelayed bool) bool {
			return hasIncompetence || wasDelayed
		}

	case verification.AnswerLiesThatMinimal:
		// Never flag anything — the prover intends to claim every packet was
		// minimal, so flagging any packet would contradict that blanket claim.
		return func(hasIncompetence, wasDelayed bool) bool {
			return false
		}

	case verification.AnswerLiesAboutTargeted:
		// Only flag genuinely congested packets; deliberately delayed packets
		// are not flagged because the prover intends to claim they were minimal.
		return func(hasIncompetence, wasDelayed bool) bool {
			return hasIncompetence
		}

	case verification.AnswerRandom:
		return func(hasIncompetence, wasDelayed bool) bool {
			return rand.Float64() < 0.5
		}

	default:
		return func(hasIncompetence, wasDelayed bool) bool {
			return hasIncompetence
		}
	}
}

type TrialResult struct {
	TrialNum            int
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	QueriesExecuted     int
	ContradictionsFound int
	FlaggingRate        float64
	PosteriorH0         float64
	PosteriorH1         float64
	PosteriorH2         float64
	TrueDelayedPackets  int
	TrueDelayFraction   float64
	DetectedCorrectly   bool
	Duration            time.Duration
}

type ExperimentResult struct {
	Config                  ExperimentConfig
	Trials                  []TrialResult
	TruePositiveRate        float64
	FalsePositiveRate       float64
	TrueNegativeRate        float64
	FalseNegativeRate       float64
	MeanQueriesPerDetection float64
	MeanConfidence          float64
	WasAdversarial          bool
	TargetDelayFraction     float64
}

type MockGroundStation struct {
	Name     string
	Received int
}

func (m *MockGroundStation) Receive(sim *engine.Simulation, pkt network.Packet, pathUsed string) {
	m.Received++
}

func NewMockGroundStation(name string) *MockGroundStation {
	return &MockGroundStation{Name: name}
}

type Runner struct {
	Results []ExperimentResult
}

func NewRunner() *Runner {
	return &Runner{
		Results: make([]ExperimentResult, 0),
	}
}

func (r *Runner) RunExperiment(config ExperimentConfig) ExperimentResult {
	fmt.Printf("\n>>> Running experiment: %s (%d trials)\n", config.Name, config.NumTrials)
	fmt.Printf("    Strategy: %s, Targeting: %s\n", config.AdversaryConfig.AnsweringStr, config.TargetingConfig.Mode)

	trials := make([]TrialResult, config.NumTrials)

	for trial := 0; trial < config.NumTrials; trial++ {
		startTime := time.Now()
		result := r.runSingleTrial(config, trial)
		result.Duration = time.Since(startTime)

		trials[trial] = result

		fmt.Printf("  Trial %d: %s (confidence=%.2f%%, queries=%d, contradictions=%d, flagRate=%.2f%%, H0=%.2f H1=%.2f H2=%.2f)\n",
			trial+1, result.Verdict, result.Confidence*100, result.QueriesExecuted, result.ContradictionsFound, result.FlaggingRate*100,
			result.PosteriorH0, result.PosteriorH1, result.PosteriorH2)
	}

	aggregated := r.aggregateResults(config, trials)
	r.Results = append(r.Results, aggregated)

	return aggregated
}

func (r *Runner) runSingleTrial(config ExperimentConfig, trialNum int) TrialResult {
	sim := engine.NewSimulation()

	delayModel := network.NewDelayModelConfig(config.DelayModelConfig)
	delayModel.Initialise(config.SimDuration + 10.0)

	flaggingFn := flaggingFnForStrategy(config.AdversaryConfig.AnsweringStr)
	router := network.NewRouter(delayModel, config.TargetingConfig, flaggingFn)
	prover := verification.NewProver(config.AdversaryConfig)

	dest := NewMockGroundStation("DestStation")
	delayedCount := 0

	router.OnTransmission = func(info network.TransmissionInfo) {
		record := verification.TransmissionRecord{
			ID:                info.PacketID,
			SentTime:          info.SentTime,
			BaseDelay:         info.BaseDelay,
			IncompetenceDelay: info.IncompetenceDelay,
			DeliberateDelay:   info.DeliberateDelay,
			ActualDelay:       info.TotalDelay,
			WasDelayed:        info.WasDelayed,
			HasIncompetence:   info.HasIncompetence,
			IsFlagged:         info.IsFlagged,
		}

		prover.RecordTransmission(record)

		if info.WasDelayed {
			delayedCount++
		}
	}

	// Schedule packets in batches — all packets in a batch share the same send time
	batchSize := config.BatchSize
	if batchSize < 2 {
		batchSize = 2
	}
	numBatches := config.NumPackets / batchSize
	if numBatches < 1 {
		numBatches = 1
	}

	pktID := 0
	for b := 0; b < numBatches; b++ {
		sendTime := float64(b) * (config.SimDuration / float64(numBatches))

		for j := 0; j < batchSize; j++ {
			currentPktID := pktID
			pktID++

			sim.Schedule(sendTime, func() {
				pkt := network.NewPacket(currentPktID, "SourceStation", sim.Now)
				router.Forward(sim, pkt, dest)
			})
		}
	}

	sim.Run(config.SimDuration + 10.0)

	finalRecords := make([]verification.TransmissionRecord, 0)
	for _, pPtr := range prover.Packets {
		finalRecords = append(finalRecords, *pPtr)
	}

	verifyConfig := config.VerificationConfig

	verifier := verification.NewVerifier(prover, verifyConfig)
	verifier.IngestRecords(finalRecords)
	result := verifier.RunVerification()

	wasAdversarial := config.TargetingConfig.Mode != network.TargetNone
	detectedDishonest := !result.Trustworthy
	correctDetection := (wasAdversarial && detectedDishonest) || (!wasAdversarial && !detectedDishonest)

	return TrialResult{
		TrialNum:            trialNum,
		Verdict:             result.Verdict,
		Confidence:          result.Confidence,
		Trustworthy:         result.Trustworthy,
		QueriesExecuted:     result.TotalQueries,
		ContradictionsFound: result.ContradictionsFound,
		FlaggingRate:        result.FlaggingRate,
		PosteriorH0:         result.PosteriorH0,
		PosteriorH1:         result.PosteriorH1,
		PosteriorH2:         result.PosteriorH2,
		TrueDelayedPackets:  delayedCount,
		TrueDelayFraction:   float64(delayedCount) / float64(config.NumPackets),
		DetectedCorrectly:   correctDetection,
	}
}

func (r *Runner) aggregateResults(config ExperimentConfig, trials []TrialResult) ExperimentResult {
	wasAdversarial := config.TargetingConfig.Mode != network.TargetNone

	truePositives := 0
	falsePositives := 0
	trueNegatives := 0
	falseNegatives := 0

	totalQueries := 0
	totalConfidence := 0.0
	detectionsQueries := 0
	detectionsCount := 0

	for _, trial := range trials {
		detectedDishonest := !trial.Trustworthy

		if wasAdversarial {
			if detectedDishonest {
				truePositives++
				detectionsQueries += trial.QueriesExecuted
				detectionsCount++
			} else {
				falseNegatives++
			}
		} else {
			if detectedDishonest {
				falsePositives++
			} else {
				trueNegatives++
			}
		}

		totalQueries += trial.QueriesExecuted
		totalConfidence += trial.Confidence
	}

	n := float64(len(trials))

	result := ExperimentResult{
		Config:              config,
		Trials:              trials,
		WasAdversarial:      wasAdversarial,
		TargetDelayFraction: config.TargetingConfig.TargetFraction,
		MeanConfidence:      totalConfidence / n,
	}

	if wasAdversarial {
		result.TruePositiveRate = float64(truePositives) / n
		result.FalseNegativeRate = float64(falseNegatives) / n
		if detectionsCount > 0 {
			result.MeanQueriesPerDetection = float64(detectionsQueries) / float64(detectionsCount)
		}
	} else {
		result.TrueNegativeRate = float64(trueNegatives) / n
		result.FalsePositiveRate = float64(falsePositives) / n
		result.MeanQueriesPerDetection = float64(totalQueries) / n
	}

	return result
}

func (r *Runner) PrintSummary() {
	fmt.Println("\n================================================================================")
	fmt.Println("                        EXPERIMENT SUMMARY")
	fmt.Println("================================================================================")

	for _, result := range r.Results {
		fmt.Printf("\n%s:\n", result.Config.Name)
		fmt.Printf("  Strategy: %s\n", result.Config.AdversaryConfig.AnsweringStr)

		if result.WasAdversarial {
			fmt.Printf("  TPR: %.1f%%, FNR: %.1f%%, Mean Queries: %.1f\n",
				result.TruePositiveRate*100,
				result.FalseNegativeRate*100,
				result.MeanQueriesPerDetection)
		} else {
			fmt.Printf("  TNR: %.1f%%, FPR: %.1f%%, Mean Queries: %.1f\n",
				result.TrueNegativeRate*100,
				result.FalsePositiveRate*100,
				result.MeanQueriesPerDetection)
		}
	}

	fmt.Println("\n================================================================================")
}
