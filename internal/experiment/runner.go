package experiment

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
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
			BaseDelayMin:      0.020,
			BaseDelayMax:      0.080,
			TransitionRate:    0.05,
			IncompetenceRate:  0.2,
			IncompetenceMu:    -4.6,
			IncompetenceSigma: 0.8,
			DeliberateMin:     0.100,
			DeliberateMax:     0.200,
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
		return func(hasIncompetence, wasDelayed bool) bool {
			return hasIncompetence
		}

	case verification.AnswerDelayedHonest:
		// Flag deliberately delayed packets as "congestion" to provide cover,
		// in addition to genuinely congested packets.
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
	EtaValue                float64 // η used for this result (mirrors Config.VerificationConfig.ErrorTolerance)
	Trials                  []TrialResult
	TruePositiveRate        float64
	FalsePositiveRate       float64
	TrueNegativeRate        float64
	FalseNegativeRate       float64
	MeanQueriesPerTrial     float64 // mean queries to verdict across all trials
	MeanConfidence          float64
	MeanPosteriorH0         float64 // mean terminal P(H0) across trials
	MeanPosteriorH1         float64 // mean terminal P(H1) across trials
	MeanPosteriorH2         float64 // mean terminal P(H2) across trials
	MeanContradictions      float64 // mean contradiction count across trials
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
	fmt.Printf("\n>>> Running experiment: %s (η=%.3f, %d trials)\n",
		config.Name, config.VerificationConfig.ErrorTolerance, config.NumTrials)
	fmt.Printf("    Strategy: %s, Targeting: %s\n", config.AdversaryConfig.AnsweringStr, config.TargetingConfig.Mode)

	trials := make([]TrialResult, config.NumTrials)

	for trial := 0; trial < config.NumTrials; trial++ {
		startTime := time.Now()
		result := r.runSingleTrial(config, trial)
		result.Duration = time.Since(startTime)

		trials[trial] = result

		fmt.Printf("  Trial %d: %s (confidence=%.2f%%, queries=%d, contradictions=%d, H0=%.2f H1=%.2f H2=%.2f)\n",
			trial+1, result.Verdict, result.Confidence*100, result.QueriesExecuted, result.ContradictionsFound,
			result.PosteriorH0, result.PosteriorH1, result.PosteriorH2)
	}

	aggregated := r.aggregateResults(config, trials)
	r.Results = append(r.Results, aggregated)

	return aggregated
}

// RunEtaFractionSweep runs one experiment per (η, fraction) combination, sweeping
// both axes. Results are appended to r.Results and returned.
func (r *Runner) RunEtaFractionSweep(baseConfig ExperimentConfig, etaValues, fractionValues []float64) []ExperimentResult {
	fmt.Printf("\n=== η×fraction-sweep: %s | Strategy: %s ===\n",
		baseConfig.Name, baseConfig.AdversaryConfig.AnsweringStr)

	results := make([]ExperimentResult, 0, len(etaValues)*len(fractionValues))
	for _, eta := range etaValues {
		for _, f := range fractionValues {
			cfg := baseConfig
			cfg.VerificationConfig.ErrorTolerance = eta
			cfg.TargetingConfig.TargetFraction = f
			cfg.Name = fmt.Sprintf("%s_eta%.3f_frac%.2f", baseConfig.Name, eta, f)
			result := r.RunExperiment(cfg)
			result.EtaValue = eta
			results = append(results, result)
		}
	}
	return results
}

// SaveResultsToFile writes results to a JSON file, creating parent directories
// as needed.
func (r *Runner) SaveResultsToFile(path string, results []ExperimentResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		return err
	}
	fmt.Printf("  Results saved to %s\n", path)
	return nil
}

// RunEtaSweep runs one experiment per η value, overriding the base config's
// ErrorTolerance for each iteration. Results are grouped by η in the output.
func (r *Runner) RunEtaSweep(baseConfig ExperimentConfig, etaValues []float64) []ExperimentResult {
	fmt.Printf("\n=== η-sweep: %s | Strategy: %s | Targeting: %s ===\n",
		baseConfig.Name, baseConfig.AdversaryConfig.AnsweringStr, baseConfig.TargetingConfig.Mode)

	results := make([]ExperimentResult, 0, len(etaValues))
	for _, eta := range etaValues {
		cfg := baseConfig
		cfg.VerificationConfig.ErrorTolerance = eta
		cfg.Name = fmt.Sprintf("%s_eta%.3f", baseConfig.Name, eta)
		result := r.RunExperiment(cfg)
		result.EtaValue = eta
		results = append(results, result)
	}
	return results
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
			BatchID:           info.BatchID,
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

	// Schedule packets in batches — all packets in a batch share the same send time.
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
		batchID := b

		for j := 0; j < batchSize; j++ {
			currentPktID := pktID
			pktID++

			sim.Schedule(sendTime, func() {
				pkt := network.NewPacket(currentPktID, batchID, "SourceStation", sim.Now)
				router.Forward(sim, pkt, dest)
			})
		}
	}

	sim.Run(config.SimDuration + 10.0)

	finalRecords := make([]verification.TransmissionRecord, 0)
	for _, pPtr := range prover.Packets {
		finalRecords = append(finalRecords, *pPtr)
	}

	verifier := verification.NewVerifier(prover, config.VerificationConfig)
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
	totalH0 := 0.0
	totalH1 := 0.0
	totalH2 := 0.0
	totalContradictions := 0.0

	for _, trial := range trials {
		detectedDishonest := !trial.Trustworthy

		if wasAdversarial {
			if detectedDishonest {
				truePositives++
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
		totalH0 += trial.PosteriorH0
		totalH1 += trial.PosteriorH1
		totalH2 += trial.PosteriorH2
		totalContradictions += float64(trial.ContradictionsFound)
	}

	n := float64(len(trials))

	result := ExperimentResult{
		Config:              config,
		EtaValue:            config.VerificationConfig.ErrorTolerance,
		Trials:              trials,
		WasAdversarial:      wasAdversarial,
		TargetDelayFraction: config.TargetingConfig.TargetFraction,
		MeanConfidence:      totalConfidence / n,
		MeanQueriesPerTrial: float64(totalQueries) / n,
		MeanPosteriorH0:     totalH0 / n,
		MeanPosteriorH1:     totalH1 / n,
		MeanPosteriorH2:     totalH2 / n,
		MeanContradictions:  totalContradictions / n,
	}

	if wasAdversarial {
		result.TruePositiveRate = float64(truePositives) / n
		result.FalseNegativeRate = float64(falseNegatives) / n
	} else {
		result.TrueNegativeRate = float64(trueNegatives) / n
		result.FalsePositiveRate = float64(falsePositives) / n
	}

	return result
}

func (r *Runner) PrintSummary() {
	fmt.Println("\n================================================================================")
	fmt.Println("                        EXPERIMENT SUMMARY")
	fmt.Println("================================================================================")

	for _, result := range r.Results {
		fmt.Printf("\n%s (η=%.3f):\n", result.Config.Name, result.EtaValue)
		fmt.Printf("  Strategy: %s\n", result.Config.AdversaryConfig.AnsweringStr)
		fmt.Printf("  Mean queries: %.1f, Mean contradictions: %.1f\n",
			result.MeanQueriesPerTrial, result.MeanContradictions)
		fmt.Printf("  Mean posteriors: H0=%.3f H1=%.3f H2=%.3f\n",
			result.MeanPosteriorH0, result.MeanPosteriorH1, result.MeanPosteriorH2)

		if result.WasAdversarial {
			fmt.Printf("  TPR: %.1f%%, FNR: %.1f%%\n",
				result.TruePositiveRate*100,
				result.FalseNegativeRate*100)
		} else {
			fmt.Printf("  TNR: %.1f%%, FPR: %.1f%%\n",
				result.TrueNegativeRate*100,
				result.FalsePositiveRate*100)
		}
	}

	fmt.Println("\n================================================================================")
}
