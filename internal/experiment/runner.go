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

type TrialResult struct {
	TrialNum            int
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	QueriesExecuted     int
	ContradictionsFound int
	FlaggingRate        float64
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

		fmt.Printf("  Trial %d: %s (confidence=%.2f%%, queries=%d, contradictions=%d, flagRate=%.2f%%)\n",
			trial+1, result.Verdict, result.Confidence*100, result.QueriesExecuted, result.ContradictionsFound, result.FlaggingRate*100)
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
	oracle := verification.NewOracle(config.AdversaryConfig)

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
		}

		oracle.RecordTransmission(record)

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
		TrialNum:            trialNum,
		Verdict:             result.Verdict,
		Confidence:          result.Confidence,
		Trustworthy:         result.Trustworthy,
		QueriesExecuted:     result.TotalQueries,
		ContradictionsFound: result.ContradictionsFound,
		FlaggingRate:        result.FlaggingRate,
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
