package experiment

import (
	"fmt"
	"math"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

// =============================================================================
// EXPERIMENT CONFIG
// =============================================================================

type ExperimentConfig struct {
	Name        string
	NumPackets  int
	NumTrials   int
	SimDuration float64

	Paths        []network.SatellitePath
	PathStrategy network.PathSelectionStrategy

	AdversarialConfig network.AdversarialConfig

	FlaggingStrategy  verification.FlaggingStrategy
	AnsweringStrategy verification.AnsweringStrategy
	FlagProbability   float64
	// FlagPercentile removed as it is not used in the new Oracle

	VerificationConfig verification.VerificationConfig
}

func DefaultExperimentConfig() ExperimentConfig {
	return ExperimentConfig{
		Name:        "default",
		NumPackets:  100,
		NumTrials:   10,
		SimDuration: 50.0,

		Paths: []network.SatellitePath{
			{Name: "LEO_FAST", Delay: 0.05, SpikeProb: 0.1, SpikeDelay: 1.0},
			{Name: "GEO_SLOW", Delay: 0.25, SpikeProb: 0.02, SpikeDelay: 0.5},
		},
		PathStrategy: network.StrategyRandom,

		AdversarialConfig: network.DefaultHonestConfig(),

		// Updated to use available strategies from the new verification package
		FlaggingStrategy:  verification.FlagRandom,
		AnsweringStrategy: verification.AnswerRandom,
		FlagProbability:   0.5,

		VerificationConfig: verification.DefaultVerificationConfig(),
	}
}

// =============================================================================
// TRIAL RESULT
// =============================================================================

type TrialResult struct {
	TrialNum    int
	Verdict     string
	Confidence  float64
	Trustworthy bool

	QueriesExecuted     int
	ContradictionsFound int

	TrueDelayedPackets int
	TrueDelayFraction  float64
	DetectedCorrectly  bool
	Duration           time.Duration
}

// =============================================================================
// EXPERIMENT RESULT
// =============================================================================

type ExperimentResult struct {
	Config ExperimentConfig
	Trials []TrialResult

	TruePositiveRate  float64
	FalsePositiveRate float64
	TrueNegativeRate  float64
	FalseNegativeRate float64

	MeanQueriesPerDetection float64
	MeanConfidence          float64

	WasAdversarial      bool
	TargetDelayFraction float64
}

func (er ExperimentResult) String() string {
	result := fmt.Sprintf(`
================================================================================
                        EXPERIMENT RESULT: %s
================================================================================
Configuration:
  Packets:          %d
  Trials:           %d
  Adversarial:      %v (delay fraction: %.2f%%)
  Flagging:         %s
  Answering:        %s

Results:
`, er.Config.Name, er.Config.NumPackets, er.Config.NumTrials,
		er.WasAdversarial, er.TargetDelayFraction*100,
		er.Config.FlaggingStrategy, er.Config.AnsweringStrategy)

	if er.WasAdversarial {
		result += fmt.Sprintf(`  True Positive Rate:   %.2f%% (correctly detected dishonesty)
  False Negative Rate:  %.2f%% (missed dishonesty)
`, er.TruePositiveRate*100, er.FalseNegativeRate*100)
	} else {
		result += fmt.Sprintf(`  True Negative Rate:   %.2f%% (correctly confirmed honest)
  False Positive Rate:  %.2f%% (wrongly accused)
`, er.TrueNegativeRate*100, er.FalsePositiveRate*100)
	}

	result += fmt.Sprintf(`  Mean Confidence:      %.2f%%
  Mean Queries:         %.1f
================================================================================
`, er.MeanConfidence*100, er.MeanQueriesPerDetection)

	return result
}

// =============================================================================
// MOCK GROUND STATION
// =============================================================================

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

// =============================================================================
// RUNNER
// =============================================================================

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
	fmt.Printf("    Flagging: %s, Answering: %s\n", config.FlaggingStrategy, config.AnsweringStrategy)

	trials := make([]TrialResult, config.NumTrials)

	for trial := 0; trial < config.NumTrials; trial++ {
		startTime := time.Now()
		result := r.runSingleTrial(config, trial)
		result.Duration = time.Since(startTime)

		trials[trial] = result

		// Reduced verbosity for large batch runs, uncomment to debug
		// fmt.Printf("  Trial %d: %s (confidence=%.2f%%, queries=%d)\n",
		// 	trial+1, result.Verdict, result.Confidence*100, result.QueriesExecuted)
	}

	aggregated := r.aggregateResults(config, trials)
	r.Results = append(r.Results, aggregated)

	return aggregated
}

func (r *Runner) runSingleTrial(config ExperimentConfig, trialNum int) TrialResult {
	sim := engine.NewSimulation()
	router := network.NewVerifiableRouter(config.Paths, config.AdversarialConfig)

	// Setup Oracle
	oracle := verification.NewStrategicOracle(config.FlaggingStrategy, config.AnsweringStrategy)
	oracle.FlagProbability = config.FlagProbability

	// No longer need SetShortestPath as the new verification strategy is strictly observed-delay based

	dest := &MockGroundStation{Name: "DestStation"}

	// We capture records to ingest into the Verifier later
	transmissions := make([]verification.TransmissionRecord, 0)
	delayedCount := 0

	router.OnTransmission = func(info network.TransmissionInfo) {
		// Map Network Info to Verification Record
		// Note: The PacketRecord/TransmissionRecord struct has been simplified
		// in the refactor. We only populate the fields it supports.
		record := verification.PacketRecord{
			ID:          info.PacketID,
			SentTime:    info.SentTime,
			MinDelay:    info.MinDelay,
			ActualDelay: info.ActualDelay,
			WasDelayed:  info.WasDelayed,
			IsFlagged:   false, // Will be set by Oracle.FlagPackets()
		}

		oracle.RecordTransmission(record)
		transmissions = append(transmissions, record) // NOTE: Local copy won't have flags updated

		if info.WasDelayed {
			delayedCount++
		}
	}

	for i := 0; i < config.NumPackets; i++ {
		pktID := i
		sendTime := float64(i) * (config.SimDuration / float64(config.NumPackets))

		sim.Schedule(sendTime, func() {
			pkt := network.NewPacket(pktID, "SourceStation", sim.Now)
			router.Forward(sim, pkt, dest, config.PathStrategy)
		})
	}

	sim.Run(config.SimDuration + 10.0)

	// Important: The Oracle decides which packets to flag *after* the run (batch)
	oracle.FlagPackets()

	// Update our local records with the flags the Oracle just decided
	// (Since we passed copies or values, we need to refresh them from the Oracle)
	finalRecords := make([]verification.TransmissionRecord, 0)
	for _, pPtr := range oracle.Packets {
		finalRecords = append(finalRecords, *pPtr)
	}

	verifyConfig := config.VerificationConfig
	verifyConfig.SamplingSecret = fmt.Sprintf("secret_trial_%d_%d", trialNum, time.Now().UnixNano())

	verifier := verification.NewVerifier(oracle, verifyConfig)
	verifier.IngestRecords(finalRecords)

	result := verifier.RunVerification(sim.Now)

	wasAdversarial := config.AdversarialConfig.Mode != network.ModeHonest
	detectedDishonest := !result.Trustworthy
	correctDetection := (wasAdversarial && detectedDishonest) || (!wasAdversarial && !detectedDishonest)

	return TrialResult{
		TrialNum:            trialNum,
		Verdict:             result.Verdict,
		Confidence:          result.Confidence,
		Trustworthy:         result.Trustworthy,
		QueriesExecuted:     result.TotalQueries,
		ContradictionsFound: result.ContradictionsFound,
		TrueDelayedPackets:  delayedCount,
		TrueDelayFraction:   float64(delayedCount) / float64(config.NumPackets),
		DetectedCorrectly:   correctDetection,
	}
}

func (r *Runner) aggregateResults(config ExperimentConfig, trials []TrialResult) ExperimentResult {
	wasAdversarial := config.AdversarialConfig.Mode != network.ModeHonest

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
		TargetDelayFraction: config.AdversarialConfig.DelayFraction,
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

// =============================================================================
// SWEEP FUNCTIONS
// =============================================================================

func (r *Runner) RunStrategySweep(name string, baseConfig ExperimentConfig) []ExperimentResult {
	results := make([]ExperimentResult, 0)

	strategies := []struct {
		flag   verification.FlaggingStrategy
		answer verification.AnsweringStrategy
		name   string
	}{
		{verification.FlagRandom, verification.AnswerRandom, "rand_rand"},
		{verification.FlagRandom, verification.AnswerSmart, "rand_smart"},
		{verification.FlagSmart, verification.AnswerRandom, "smart_rand"},
		{verification.FlagSmart, verification.AnswerSmart, "smart_smart"},
	}

	for _, strat := range strategies {
		config := baseConfig
		config.Name = fmt.Sprintf("%s_%s", name, strat.name)
		config.FlaggingStrategy = strat.flag
		config.AnsweringStrategy = strat.answer

		result := r.RunExperiment(config)
		results = append(results, result)
	}

	return results
}

func (r *Runner) RunDelayFractionSweep(name string, baseConfig ExperimentConfig, fractions []float64) []ExperimentResult {
	results := make([]ExperimentResult, 0)

	for _, fraction := range fractions {
		config := baseConfig
		config.Name = fmt.Sprintf("%s_delay_%.0f%%", name, fraction*100)
		config.AdversarialConfig = network.AdversarialConfig{
			Mode:              network.ModeRandomDelay,
			DelayFraction:     fraction,
			MinMaliciousDelay: 0.5,
			MaxMaliciousDelay: 2.0,
		}

		result := r.RunExperiment(config)
		results = append(results, result)
	}

	return results
}

// =============================================================================
// SUMMARY
// =============================================================================

func (r *Runner) PrintSummary() {
	fmt.Println("\n================================================================================")
	fmt.Println("                        EXPERIMENT SUMMARY")
	fmt.Println("================================================================================")

	for _, result := range r.Results {
		fmt.Printf("\n%s:\n", result.Config.Name)
		fmt.Printf("  Strategy: %s + %s\n", result.Config.FlaggingStrategy, result.Config.AnsweringStrategy)

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

func (r *Runner) GenerateCSV() string {
	csv := "experiment,adversarial,delay_fraction,flagging,answering,tpr,fpr,tnr,fnr,mean_queries,mean_confidence\n"

	for _, result := range r.Results {
		csv += fmt.Sprintf("%s,%v,%.3f,%s,%s,%.3f,%.3f,%.3f,%.3f,%.1f,%.3f\n",
			result.Config.Name,
			result.WasAdversarial,
			result.TargetDelayFraction,
			result.Config.FlaggingStrategy,
			result.Config.AnsweringStrategy,
			result.TruePositiveRate,
			result.FalsePositiveRate,
			result.TrueNegativeRate,
			result.FalseNegativeRate,
			result.MeanQueriesPerDetection,
			result.MeanConfidence,
		)
	}

	return csv
}

func ConfidenceInterval(rate float64, n int) (float64, float64) {
	if n == 0 {
		return 0, 1
	}

	z := 1.96
	p := rate

	se := math.Sqrt(p * (1 - p) / float64(n))
	lower := math.Max(0, p-z*se)
	upper := math.Min(1, p+z*se)

	return lower, upper
}
