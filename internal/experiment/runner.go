package experiment

import (
	"fmt"
	"math"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

type ExperimentConfig struct {
	Name        string
	NumPackets  int
	NumTrials   int
	SimDuration float64

	Paths        []network.SatellitePath
	PathStrategy network.PathSelectionStrategy

	AdversarialConfig network.AdversarialConfig
	LyingStrategy     verification.LyingStrategy
	LieProbability    float64

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
		LyingStrategy:     verification.StrategyHonest,
		LieProbability:    0.0,

		VerificationConfig: verification.DefaultVerificationConfig(),
	}
}

type TrialResult struct {
	TrialNum    int
	Verdict     string
	Confidence  float64
	Trustworthy bool

	QueriesExecuted     int
	ContradictionsFound int
	DefinitiveProofs    int

	TrueDelayedPackets int
	TrueDelayFraction  float64
	DetectedCorrectly  bool
	Duration           time.Duration
}

type ExperimentResult struct {
	Config ExperimentConfig
	Trials []TrialResult

	TruePositiveRate  float64 // Detected dishonest when dishonest
	FalsePositiveRate float64 // Detected dishonest when honest
	TrueNegativeRate  float64 // Detected honest when honest
	FalseNegativeRate float64 // Detected honest when dishonest

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
  Lying Strategy:   %s

Results:
`, er.Config.Name, er.Config.NumPackets, er.Config.NumTrials,
		er.WasAdversarial, er.TargetDelayFraction*100,
		er.Config.LyingStrategy)

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

	trials := make([]TrialResult, config.NumTrials)

	for trial := 0; trial < config.NumTrials; trial++ {
		startTime := time.Now()
		result := r.runSingleTrial(config, trial)
		result.Duration = time.Since(startTime)

		trials[trial] = result

		fmt.Printf("  Trial %d: %s (confidence=%.2f%%, queries=%d)\n",
			trial+1, result.Verdict, result.Confidence*100, result.QueriesExecuted)
	}
	aggregated := r.aggregateResults(config, trials)
	r.Results = append(r.Results, aggregated)

	return aggregated
}

func (r *Runner) runSingleTrial(config ExperimentConfig, trialNum int) TrialResult {
	sim := engine.NewSimulation()
	router := network.NewVerifiableRouter(config.Paths, config.AdversarialConfig)
	shortestPath, shortestDelay := router.GetShortestPath()
	oracle := verification.NewNetworkOracle(
		config.LyingStrategy,
		config.LieProbability,
		shortestPath,
		shortestDelay,
	)

	dest := &MockGroundStation{Name: "DestStation"}
	transmissions := make([]verification.TransmissionRecord, 0)
	delayedCount := 0

	router.OnTransmission = func(info network.TransmissionInfo) {
		record := verification.TransmissionRecord{
			PacketID:       info.PacketID,
			SentTime:       info.SentTime,
			ReceivedTime:   info.ReceivedTime,
			PathUsed:       info.PathUsed,
			PathDelay:      info.PathBaseDelay,
			MinDelay:       info.MinDelay,
			ActualDelay:    info.ActualDelay,
			MaliciousDelay: info.MaliciousDelay,
			IsShortestPath: info.IsShortestPath,
			WasDelayed:     info.WasDelayed,
		}

		oracle.RecordTransmission(record)
		transmissions = append(transmissions, record)

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
	verifyConfig := config.VerificationConfig
	verifyConfig.SamplingSecret = fmt.Sprintf("secret_trial_%d_%d", trialNum, time.Now().UnixNano())

	verifier := verification.NewVerifier(oracle, verifyConfig)

	for _, p := range config.Paths {
		isShortest := p.Name == shortestPath
		verifier.AddPathInfo(p.Name, p.Delay, isShortest)
	}

	verifier.IngestRecords(transmissions)
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
		DefinitiveProofs:    result.DefinitiveProofs,
		TrueDelayedPackets:  delayedCount,
		TrueDelayFraction:   float64(delayedCount) / float64(config.NumPackets),
		DetectedCorrectly:   correctDetection,
	}
}

func (r *Runner) aggregateResults(config ExperimentConfig, trials []TrialResult) ExperimentResult {
	wasAdversarial := config.AdversarialConfig.Mode != network.ModeHonest

	truePositives := 0  // Correctly detected dishonesty
	falsePositives := 0 // Wrongly accused honesty
	trueNegatives := 0  // Correctly confirmed honesty
	falseNegatives := 0 // Missed dishonesty

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

// RunSweep runs experiments sweeping a parameter
func (r *Runner) RunSweep(name string, baseConfig ExperimentConfig,
	delayFractions []float64) []ExperimentResult {

	results := make([]ExperimentResult, 0)

	for _, fraction := range delayFractions {
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

// RunStrategySweep runs experiments with different lying strategies
func (r *Runner) RunStrategySweep(name string, baseConfig ExperimentConfig,
	strategies []verification.LyingStrategy) []ExperimentResult {

	results := make([]ExperimentResult, 0)

	for _, strategy := range strategies {
		config := baseConfig
		config.Name = fmt.Sprintf("%s_%s", name, strategy)
		config.LyingStrategy = strategy
		config.LieProbability = 0.5

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
	csv := "experiment,adversarial,delay_fraction,lying_strategy,tpr,fpr,tnr,fnr,mean_queries,mean_confidence\n"

	for _, result := range r.Results {
		csv += fmt.Sprintf("%s,%v,%.3f,%s,%.3f,%.3f,%.3f,%.3f,%.1f,%.3f\n",
			result.Config.Name,
			result.WasAdversarial,
			result.TargetDelayFraction,
			result.Config.LyingStrategy,
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

func CalculateDetectionCurve(trials []TrialResult) map[int]float64 {
	curve := make(map[int]float64)
	maxQueries := 0
	for _, t := range trials {
		if t.QueriesExecuted > maxQueries {
			maxQueries = t.QueriesExecuted
		}
	}

	for q := 10; q <= maxQueries; q += 10 {
		detected := 0
		total := 0

		for _, t := range trials {
			if t.QueriesExecuted <= q && !t.Trustworthy {
				detected++
			}
			total++
		}

		if total > 0 {
			curve[q] = float64(detected) / float64(total)
		}
	}

	return curve
}

func ConfidenceInterval(rate float64, n int) (float64, float64) {
	if n == 0 {
		return 0, 1
	}

	z := 1.96 // 95% CI
	p := rate

	se := math.Sqrt(p * (1 - p) / float64(n))
	lower := math.Max(0, p-z*se)
	upper := math.Min(1, p+z*se)

	return lower, upper
}
