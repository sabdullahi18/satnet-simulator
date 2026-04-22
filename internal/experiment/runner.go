package experiment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

// HonestBaselineConfig pins the network to H0 (honest, no incompetence, no
// targeting) and exposes only the knobs relevant to characterising verifier
// behaviour on a perfectly honest network.
type HonestBaselineConfig struct {
	Name         string
	NumTrials    int
	NumPackets   int
	BatchSize    int
	SimDuration  float64
	DelayModel   network.DelayModelConfig
	Verification verification.VerificationConfig
}

func DefaultHonestBaseline() HonestBaselineConfig {
	return HonestBaselineConfig{
		Name:        "honest_baseline",
		NumTrials:   200,
		NumPackets:  10000,
		BatchSize:   10,
		SimDuration: 1000.0,
		DelayModel: network.DelayModelConfig{
			BaseDelayMin:      0.020,
			BaseDelayMax:      0.080,
			TransitionRate:    0.05,
			IncompetenceRate:  0.0,
			IncompetenceMu:    0.0,
			IncompetenceSigma: 0.0,
			DeliberateMin:     0.0,
			DeliberateMax:     0.0,
		},
		Verification: verification.DefaultVerificationConfig(),
	}
}

type HonestTrialResult struct {
	TrialNum            int
	Verdict             string
	Confidence          float64
	QueriesUsed         int
	ContradictionsFound int
	PosteriorH0         float64
	PosteriorH1         float64
	PosteriorH2         float64
	Duration            time.Duration
}

type HonestAggregate struct {
	Config HonestBaselineConfig
	Trials []HonestTrialResult

	TrustedRate        float64
	InconclusiveRate   float64
	FalseDishonestRate float64

	MeanQueriesToVerdict   float64
	MedianQueriesToVerdict int
	P90QueriesToVerdict    int
	MinQueriesToVerdict    int
	MaxQueriesToVerdict    int

	MeanPosteriorH0 float64
	MeanPosteriorH1 float64
	MeanPosteriorH2 float64

	MeanContradictions float64
	ContradictionRate  float64
}

type Runner struct {
	Verbose bool
	Results []HonestAggregate
}

func NewRunner() *Runner {
	return &Runner{Verbose: true}
}

// RunHonest runs N trials under the honest baseline config and aggregates.
func (r *Runner) RunHonest(cfg HonestBaselineConfig) HonestAggregate {
	if r.Verbose {
		fmt.Printf(">>> %s: N=%d, packets=%d, B=%d, η=%.4f, α=%.4f, ε=%.4f\n",
			cfg.Name, cfg.NumTrials, cfg.NumPackets, cfg.BatchSize,
			cfg.Verification.ErrorTolerance,
			cfg.Verification.ConfidenceThreshold,
			cfg.Verification.Epsilon)
	}

	trials := make([]HonestTrialResult, cfg.NumTrials)
	for i := 0; i < cfg.NumTrials; i++ {
		start := time.Now()
		trials[i] = r.runSingleHonestTrial(cfg, i)
		trials[i].Duration = time.Since(start)
	}

	agg := aggregateHonest(cfg, trials)
	r.Results = append(r.Results, agg)

	if r.Verbose {
		fmt.Printf("    trusted=%.1f%%  inconclusive=%.1f%%  false_dishonest=%.1f%%  median_q=%d  p90_q=%d\n",
			agg.TrustedRate*100, agg.InconclusiveRate*100, agg.FalseDishonestRate*100,
			agg.MedianQueriesToVerdict, agg.P90QueriesToVerdict)
	}
	return agg
}

// SweepHonestEta varies η (ErrorTolerance) under the honest baseline.
func (r *Runner) SweepHonestEta(base HonestBaselineConfig, etas []float64) []HonestAggregate {
	fmt.Printf("\n=== Honest baseline: η sweep (%d values) ===\n", len(etas))
	out := make([]HonestAggregate, 0, len(etas))
	for _, eta := range etas {
		cfg := base
		cfg.Verification.ErrorTolerance = eta
		cfg.Name = fmt.Sprintf("%s_eta%.4f", base.Name, eta)
		out = append(out, r.RunHonest(cfg))
	}
	return out
}

// SweepHonestAlpha varies α (ConfidenceThreshold) under the honest baseline.
func (r *Runner) SweepHonestAlpha(base HonestBaselineConfig, alphas []float64) []HonestAggregate {
	fmt.Printf("\n=== Honest baseline: α sweep (%d values) ===\n", len(alphas))
	out := make([]HonestAggregate, 0, len(alphas))
	for _, a := range alphas {
		cfg := base
		cfg.Verification.ConfidenceThreshold = a
		cfg.Name = fmt.Sprintf("%s_alpha%.4f", base.Name, a)
		out = append(out, r.RunHonest(cfg))
	}
	return out
}

// SweepHonestBatch varies batch size B.
func (r *Runner) SweepHonestBatch(base HonestBaselineConfig, batches []int) []HonestAggregate {
	fmt.Printf("\n=== Honest baseline: batch-size sweep (%d values) ===\n", len(batches))
	out := make([]HonestAggregate, 0, len(batches))
	for _, b := range batches {
		cfg := base
		cfg.BatchSize = b
		cfg.Name = fmt.Sprintf("%s_batch%d", base.Name, b)
		out = append(out, r.RunHonest(cfg))
	}
	return out
}

// SweepHonestNumPackets varies trial length (total packets).
func (r *Runner) SweepHonestNumPackets(base HonestBaselineConfig, ns []int) []HonestAggregate {
	fmt.Printf("\n=== Honest baseline: trial-length sweep (%d values) ===\n", len(ns))
	out := make([]HonestAggregate, 0, len(ns))
	for _, n := range ns {
		cfg := base
		cfg.NumPackets = n
		cfg.Name = fmt.Sprintf("%s_pkts%d", base.Name, n)
		out = append(out, r.RunHonest(cfg))
	}
	return out
}

// SweepHonestTransitionRate varies λ (Poisson rate of base-delay transitions).
// Honest networks should be invariant to λ; this is a sanity check.
func (r *Runner) SweepHonestTransitionRate(base HonestBaselineConfig, rates []float64) []HonestAggregate {
	fmt.Printf("\n=== Honest baseline: λ sweep (%d values) ===\n", len(rates))
	out := make([]HonestAggregate, 0, len(rates))
	for _, rate := range rates {
		cfg := base
		cfg.DelayModel.TransitionRate = rate
		cfg.Name = fmt.Sprintf("%s_lambda%.3f", base.Name, rate)
		out = append(out, r.RunHonest(cfg))
	}
	return out
}

// SweepHonestEpsilon varies ε (implementation-noise floor). Honest results
// should shift only marginally with ε; this checks the numerical floor.
func (r *Runner) SweepHonestEpsilon(base HonestBaselineConfig, epsilons []float64) []HonestAggregate {
	fmt.Printf("\n=== Honest baseline: ε sweep (%d values) ===\n", len(epsilons))
	out := make([]HonestAggregate, 0, len(epsilons))
	for _, e := range epsilons {
		cfg := base
		cfg.Verification.Epsilon = e
		cfg.Name = fmt.Sprintf("%s_eps%.0e", base.Name, e)
		out = append(out, r.RunHonest(cfg))
	}
	return out
}

type honestDest struct{ Received int }

func (h *honestDest) Receive(sim *engine.Simulation, pkt network.Packet, pathUsed string) {
	h.Received++
}

func (r *Runner) runSingleHonestTrial(cfg HonestBaselineConfig, trialNum int) HonestTrialResult {
	sim := engine.NewSimulation()

	dm := network.NewDelayModelConfig(cfg.DelayModel)
	dm.Initialise(cfg.SimDuration + 10.0)

	prover := verification.NewProver(verification.AdversaryConfig{
		AnsweringStr: verification.AnswerHonest,
	})

	router := network.NewRouter(
		dm,
		network.DefaultHonestTargeting(),
		func(hasIncompetence, wasDelayed bool) bool { return false },
	)

	router.OnTransmission = func(info network.TransmissionInfo) {
		prover.RecordTransmission(verification.TransmissionRecord{
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
		})
	}

	dest := &honestDest{}

	batchSize := cfg.BatchSize
	if batchSize < 2 {
		batchSize = 2
	}
	numBatches := cfg.NumPackets / batchSize
	if numBatches < 1 {
		numBatches = 1
	}

	pktID := 0
	for b := 0; b < numBatches; b++ {
		sendTime := float64(b) * (cfg.SimDuration / float64(numBatches))
		batchID := b
		for j := 0; j < batchSize; j++ {
			id := pktID
			pktID++
			sim.Schedule(sendTime, func() {
				pkt := network.NewPacket(id, batchID, "Source", sim.Now)
				router.Forward(sim, pkt, dest)
			})
		}
	}
	sim.Run(cfg.SimDuration + 10.0)

	observations := make([]verification.Observation, 0, len(prover.Packets))
	for _, p := range prover.Packets {
		observations = append(observations, verification.ObservationFrom(*p))
	}

	verifier := verification.NewVerifier(prover, cfg.Verification)
	verifier.IngestObservations(observations)
	res := verifier.RunVerification()

	return HonestTrialResult{
		TrialNum:            trialNum,
		Verdict:             res.Verdict,
		Confidence:          res.Confidence,
		QueriesUsed:         res.TotalQueries,
		ContradictionsFound: res.ContradictionsFound,
		PosteriorH0:         res.PosteriorH0,
		PosteriorH1:         res.PosteriorH1,
		PosteriorH2:         res.PosteriorH2,
	}
}

func aggregateHonest(cfg HonestBaselineConfig, trials []HonestTrialResult) HonestAggregate {
	n := len(trials)
	agg := HonestAggregate{Config: cfg, Trials: trials}
	if n == 0 {
		return agg
	}

	var trusted, inconclusive, dishonest int
	var sumH0, sumH1, sumH2 float64
	var totalContradictions int
	var withContradictions int
	queriesToVerdict := make([]int, 0, n)

	for _, t := range trials {
		switch t.Verdict {
		case "TRUSTED":
			trusted++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		case "INCONCLUSIVE", "INSUFFICIENT_DATA":
			inconclusive++
		default:
			dishonest++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		}
		sumH0 += t.PosteriorH0
		sumH1 += t.PosteriorH1
		sumH2 += t.PosteriorH2
		totalContradictions += t.ContradictionsFound
		if t.ContradictionsFound > 0 {
			withContradictions++
		}
	}

	agg.TrustedRate = float64(trusted) / float64(n)
	agg.InconclusiveRate = float64(inconclusive) / float64(n)
	agg.FalseDishonestRate = float64(dishonest) / float64(n)
	agg.MeanPosteriorH0 = sumH0 / float64(n)
	agg.MeanPosteriorH1 = sumH1 / float64(n)
	agg.MeanPosteriorH2 = sumH2 / float64(n)
	agg.MeanContradictions = float64(totalContradictions) / float64(n)
	agg.ContradictionRate = float64(withContradictions) / float64(n)

	if len(queriesToVerdict) > 0 {
		sort.Ints(queriesToVerdict)
		var sum int
		for _, q := range queriesToVerdict {
			sum += q
		}
		agg.MeanQueriesToVerdict = float64(sum) / float64(len(queriesToVerdict))
		agg.MedianQueriesToVerdict = queriesToVerdict[len(queriesToVerdict)/2]
		p90 := (len(queriesToVerdict) * 90) / 100
		if p90 >= len(queriesToVerdict) {
			p90 = len(queriesToVerdict) - 1
		}
		agg.P90QueriesToVerdict = queriesToVerdict[p90]
		agg.MinQueriesToVerdict = queriesToVerdict[0]
		agg.MaxQueriesToVerdict = queriesToVerdict[len(queriesToVerdict)-1]
	}
	return agg
}

func (r *Runner) SaveAggregates(path string, results []HonestAggregate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
	if r.Verbose {
		fmt.Printf("    wrote %s\n", path)
	}
	return nil
}

func (r *Runner) PrintSummary() {
	fmt.Println("\n================================================================================")
	fmt.Println("                         HONEST BASELINE SUMMARY")
	fmt.Println("================================================================================")
	for _, agg := range r.Results {
		fmt.Printf("\n%s\n", agg.Config.Name)
		fmt.Printf("  η=%.4f  α=%.4f  ε=%.4f  B=%d  N=%d  trials=%d\n",
			agg.Config.Verification.ErrorTolerance,
			agg.Config.Verification.ConfidenceThreshold,
			agg.Config.Verification.Epsilon,
			agg.Config.BatchSize, agg.Config.NumPackets, agg.Config.NumTrials)
		fmt.Printf("  trusted=%.1f%%  inconclusive=%.1f%%  false_dishonest=%.1f%%\n",
			agg.TrustedRate*100, agg.InconclusiveRate*100, agg.FalseDishonestRate*100)
		fmt.Printf("  queries to verdict: mean=%.1f median=%d P90=%d min=%d max=%d\n",
			agg.MeanQueriesToVerdict, agg.MedianQueriesToVerdict, agg.P90QueriesToVerdict,
			agg.MinQueriesToVerdict, agg.MaxQueriesToVerdict)
		fmt.Printf("  mean posterior: H0=%.4f H1=%.4f H2=%.4f\n",
			agg.MeanPosteriorH0, agg.MeanPosteriorH1, agg.MeanPosteriorH2)
	}
	fmt.Println("\n================================================================================")
}
