package experiment

import (
	"fmt"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

type ExperimentConfig struct {
	Name               string
	NumPackets         int
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
		NumTrials:   5,
		SimDuration: 100.0,

		DelayModelConfig: network.DelayModelConfig{
			BaseDelayMin:   0.020,
			BaseDelayMax:   0.080,
			TransitionRate: 0.05,
			LegitMu:        -4.6,
			LegitSigma:     0.8,
			MaliciousMin:   0.100,
			MaliciousMax:   0.200,
		},

		TargetingConfig: network.DefaultHonestTargeting(),

		AdversaryConfig: verification.AdversaryConfig{
			AnsweringStr:  verification.AnswerHonest,
			MaliciousRate: 0.1,
		},

		VerificationConfig: verification.DefaultVerificationConfig(),
	}
}

type TrialResult struct {
	TrialNum              int
	Verdict               string
	Confidence            float64
	Trustworthy           bool
	QueriesExecuted       int
	ContradictionsFound   int
	HistoryContradictions int
	TrueDelayedPackets    int
	TrueDelayFraction     float64
	DetectedCorrectly     bool
	Duration              time.Duration
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

func (er ExperimentResult) String() string {
	strategyName := fmt.Sprintf("%s", er.Config.AdversaryConfig.AnsweringStr)

	result := fmt.Sprintf(`
================================================================================
                        EXPERIMENT RESULT: %s
================================================================================
Configuration:
  Packets:          %d
  Trials:           %d
  Adversarial:      %v (target fraction: %.2f%%)
  Strategy:         %s

Results:
`, er.Config.Name, er.Config.NumPackets, er.Config.NumTrials,
		er.WasAdversarial, er.TargetDelayFraction*100, strategyName)

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

		fmt.Printf("  Trial %d: %s (confidence=%.2f%%, queries=%d, hist_contra=%d)\n",
			trial+1, result.Verdict, result.Confidence*100, result.QueriesExecuted, result.HistoryContradictions)
	}

	aggregated := r.aggregateResults(config, trials)
	r.Results = append(r.Results, aggregated)

	return aggregated
}

func (r *Runner) runSingleTrial(config ExperimentConfig, trialNum int) TrialResult {
	sim := engine.NewSimulation()

	delayModel := network.NewDelayModelConfig(config.DelayModelConfig)
	delayModel.Initialise(config.SimDuration + 10.0)

	router := network.NewRouter(delayModel, config.TargetingConfig)

	// Create Oracle
	oracle := verification.NewOracle(config.AdversaryConfig)

	dest := NewMockGroundStation("DestStation")
	transmissions := make([]verification.TransmissionRecord, 0)
	delayedCount := 0

	router.OnTransmission = func(info network.TransmissionInfo) {
		record := verification.TransmissionRecord{
			ID:             info.PacketID,
			SentTime:       info.SentTime,
			BaseDelay:      info.BaseDelay,
			LegitDelay:     info.LegitDelay,
			MaliciousDelay: info.MaliciousDelay,
			ActualDelay:    info.TotalDelay,
			MinDelay:       info.MinPossibleDelay,
			WasDelayed:     info.WasDelayed,
		}

		oracle.RecordTransmission(record)
		transmissions = append(transmissions, record)

		if info.WasDelayed {
			delayedCount++
		}
	}

	// For ID-based targeting, we need to populate TargetIDs in config if not done
	if config.TargetingConfig.Mode == network.TargetByID && len(config.TargetingConfig.TargetIDs) == 0 {
		// Populate logic handled elsewhere or assume user provided it
	}

	for i := 0; i < config.NumPackets; i++ {
		pktID := i
		sendTime := float64(i) * (config.SimDuration / float64(config.NumPackets))

		sim.Schedule(sendTime, func() {
			pkt := network.NewPacket(pktID, "SourceStation", sim.Now)
			router.Forward(sim, pkt, dest)
		})
	}

	sim.Run(config.SimDuration + 10.0)

	finalRecords := make([]verification.TransmissionRecord, 0)
	for _, pPtr := range oracle.Packets {
		finalRecords = append(finalRecords, *pPtr)
	}

	verifyConfig := config.VerificationConfig
	// Update secret if needed

	verifier := verification.NewVerifier(oracle, verifyConfig)
	verifier.IngestRecords(finalRecords)
	result := verifier.RunVerification()

	wasAdversarial := config.TargetingConfig.Mode != network.TargetNone
	detectedDishonest := !result.Trustworthy
	correctDetection := (wasAdversarial && detectedDishonest) || (!wasAdversarial && !detectedDishonest)

	return TrialResult{
		TrialNum:              trialNum,
		Verdict:               result.Verdict,
		Confidence:            result.Confidence,
		Trustworthy:           result.Trustworthy,
		QueriesExecuted:       result.TotalQueries,
		ContradictionsFound:   result.ContradictionsFound,
		HistoryContradictions: result.HistoryContradictions,
		TrueDelayedPackets:    delayedCount,
		TrueDelayFraction:     float64(delayedCount) / float64(config.NumPackets),
		DetectedCorrectly:     correctDetection,
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

func (r *Runner) RunStrategySweep(name string, baseConfig ExperimentConfig) []ExperimentResult {
	results := make([]ExperimentResult, 0)

	// Sweep Packet Size? Strategy?
	// For now, let's sweep Answering Strategies

	strats := []verification.AnsweringStrategy{
		verification.AnswerHonest,
		verification.AnswerRandom,
		verification.AnswerSmart,
		verification.AnswerBold,
	}

	for _, s := range strats {
		config := baseConfig
		config.Name = fmt.Sprintf("%s_%s", name, s)
		config.AdversaryConfig.AnsweringStr = s
		// Force Targeting to Random if adversarial
		if config.TargetingConfig.Mode == network.TargetNone {
			// This sweep assumes adversarial targeting?
			// If we want to test honesty, use TargetNone.
			// If we sweep strategies, we probably mean Adversarial Strategies.
			config.TargetingConfig = network.DefaultAdversarialTargeting(0.10) // 10% attack
		}

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
		config.TargetingConfig = network.DefaultAdversarialTargeting(fraction)

		result := r.RunExperiment(config)
		results = append(results, result)
	}

	return results
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

func (r *Runner) GenerateCSV() string {
	csv := "experiment,adversarial,target_fraction,lying_strategy,tpr,fpr,tnr,fnr,mean_queries,mean_confidence\n"

	for _, result := range r.Results {
		csv += fmt.Sprintf("%s,%v,%.3f,%s,%.3f,%.3f,%.3f,%.3f,%.1f,%.3f\n",
			result.Config.Name,
			result.WasAdversarial,
			result.TargetDelayFraction,
			result.Config.AdversaryConfig.AnsweringStr,
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
