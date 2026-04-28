package experiment

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

	TrustedRate          float64
	InconclusiveRate     float64
	FalseDishonestRate   float64
	TrustedRateCI        RateCI
	InconclusiveRateCI   RateCI
	FalseDishonestRateCI RateCI

	MeanQueriesToVerdict   float64
	MedianQueriesToVerdict int
	P90QueriesToVerdict    int
	MinQueriesToVerdict    int
	MaxQueriesToVerdict    int

	MeanPosteriorH0 float64
	MeanPosteriorH1 float64
	MeanPosteriorH2 float64

	MeanContradictions  float64
	ContradictionRate   float64
	ContradictionRateCI RateCI
}

// RateCI stores a two-sided 95% confidence interval for a Bernoulli rate.
type RateCI struct {
	Lower float64
	Upper float64
}

type Runner struct {
	Verbose              bool
	Results              []HonestAggregate
	baseSeed             int64
	deterministicSeeding bool
}

func NewRunner() *Runner {
	return &Runner{Verbose: true}
}

const rateCI95Z = 1.959963984540054

func wilsonRateCI(successes, total int) RateCI {
	if total <= 0 {
		return RateCI{}
	}
	n := float64(total)
	p := float64(successes) / n
	z2 := rateCI95Z * rateCI95Z
	denom := 1.0 + z2/n
	center := (p + z2/(2.0*n)) / denom
	margin := (rateCI95Z / denom) * math.Sqrt((p*(1.0-p)+z2/(4.0*n))/n)

	ci := RateCI{Lower: center - margin, Upper: center + margin}
	if ci.Lower < 0 {
		ci.Lower = 0
	}
	if ci.Upper > 1 {
		ci.Upper = 1
	}
	return ci
}

func formatRateWithCI(rate float64, ci RateCI) string {
	return fmt.Sprintf("%.1f%% [%.1f, %.1f]", rate*100, ci.Lower*100, ci.Upper*100)
}

// SetBaseSeed enables deterministic per-trial seeding.
// With a fixed base seed, each (scenario, config, trial) maps to a stable
// random stream, so rerunning a single sweep is independent of what other
// sweeps were enabled.
func (r *Runner) SetBaseSeed(seed int64) {
	r.baseSeed = seed
	r.deterministicSeeding = true
}

func (r *Runner) maybeSeedTrial(scope, cfgName string, trialNum int) {
	if !r.deterministicSeeding {
		return
	}
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "%s|%s|%d", scope, cfgName, trialNum)
	rand.Seed(int64(h.Sum64() ^ uint64(r.baseSeed)))
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
		r.maybeSeedTrial("honest", cfg.Name, i)
		start := time.Now()
		trials[i] = r.runSingleHonestTrial(cfg, i)
		trials[i].Duration = time.Since(start)
	}

	agg := aggregateHonest(cfg, trials)
	r.Results = append(r.Results, agg)

	if r.Verbose {
		fmt.Printf("    trusted=%s  inconclusive=%s  false_dishonest=%s  median_q=%d  p90_q=%d\n",
			formatRateWithCI(agg.TrustedRate, agg.TrustedRateCI),
			formatRateWithCI(agg.InconclusiveRate, agg.InconclusiveRateCI),
			formatRateWithCI(agg.FalseDishonestRate, agg.FalseDishonestRateCI),
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
	agg.TrustedRateCI = wilsonRateCI(trusted, n)
	agg.InconclusiveRateCI = wilsonRateCI(inconclusive, n)
	agg.FalseDishonestRateCI = wilsonRateCI(dishonest, n)
	agg.MeanPosteriorH0 = sumH0 / float64(n)
	agg.MeanPosteriorH1 = sumH1 / float64(n)
	agg.MeanPosteriorH2 = sumH2 / float64(n)
	agg.MeanContradictions = float64(totalContradictions) / float64(n)
	agg.ContradictionRate = float64(withContradictions) / float64(n)
	agg.ContradictionRateCI = wilsonRateCI(withContradictions, n)

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
		fmt.Printf("  trusted=%s  inconclusive=%s  false_dishonest=%s\n",
			formatRateWithCI(agg.TrustedRate, agg.TrustedRateCI),
			formatRateWithCI(agg.InconclusiveRate, agg.InconclusiveRateCI),
			formatRateWithCI(agg.FalseDishonestRate, agg.FalseDishonestRateCI))
		fmt.Printf("  contradiction_rate=%s\n", formatRateWithCI(agg.ContradictionRate, agg.ContradictionRateCI))
		fmt.Printf("  queries to verdict: mean=%.1f median=%d P90=%d min=%d max=%d\n",
			agg.MeanQueriesToVerdict, agg.MedianQueriesToVerdict, agg.P90QueriesToVerdict,
			agg.MinQueriesToVerdict, agg.MaxQueriesToVerdict)
		fmt.Printf("  mean posterior: H0=%.4f H1=%.4f H2=%.4f\n",
			agg.MeanPosteriorH0, agg.MeanPosteriorH1, agg.MeanPosteriorH2)
	}
	fmt.Println("\n================================================================================")
}

// ============================================================================
// Incompetent network evaluation
// ============================================================================

// IncompetentBaselineConfig pins the network to H1 behaviour: genuine
// congestion events occur at rate IncompetenceRate, each is independently
// flagged with probability FlagReliability, and the prover answers queries
// according to AnsweringStrategy (usually AnswerHonest; AnswerUnreliable
// models drifting bookkeeping via AnswerErrorRate).
type IncompetentBaselineConfig struct {
	Name              string
	NumTrials         int
	NumPackets        int
	BatchSize         int
	SimDuration       float64
	DelayModel        network.DelayModelConfig
	FlagReliability   float64 // P(flag is set | packet experienced congestion)
	AnsweringStrategy verification.AnsweringStrategy
	AnswerErrorRate   float64 // only used when AnsweringStrategy == AnswerUnreliable
	Verification      verification.VerificationConfig
}

func DefaultIncompetentBaseline() IncompetentBaselineConfig {
	return IncompetentBaselineConfig{
		Name:        "incompetent_baseline",
		NumTrials:   50,
		NumPackets:  2000,
		BatchSize:   10,
		SimDuration: 1000.0,
		DelayModel: network.DelayModelConfig{
			BaseDelayMin:      0.020,
			BaseDelayMax:      0.080,
			TransitionRate:    0.05,
			IncompetenceRate:  0.05,
			IncompetenceMu:    -3.9, // e^{-3.9} ≈ 20 ms geometric-mean congestion delay
			IncompetenceSigma: 0.5,
			DeliberateMin:     0.0,
			DeliberateMax:     0.0,
		},
		FlagReliability:   0.0, // worst-case classical incompetence: never flags
		AnsweringStrategy: verification.AnswerHonest,
		AnswerErrorRate:   0.0,
		Verification:      verification.DefaultVerificationConfig(),
	}
}

type IncompetentTrialResult struct {
	TrialNum            int
	Verdict             string
	VerdictClass        string // TRUSTED, CAUGHT_INCOMPETENT, CAUGHT_MALICIOUS, SLA_BREACHED, INCONCLUSIVE
	Confidence          float64
	QueriesUsed         int
	ContradictionsFound int
	PosteriorH0         float64
	PosteriorH1         float64
	PosteriorH2         float64
	Duration            time.Duration
}

type IncompetentAggregate struct {
	Config IncompetentBaselineConfig
	Trials []IncompetentTrialResult

	TrustedRate             float64 // false negative: incompetence not caught
	CaughtIncompetentRate   float64 // H1 posterior wins
	CaughtMaliciousRate     float64 // H2 posterior wins (misclassification)
	SLABreachedRate         float64 // flagging-rate threshold crossed
	InconclusiveRate        float64
	CorrectDetectionRate    float64 // CaughtIncompetent + CaughtMalicious + SLABreached
	TrustedRateCI           RateCI
	CaughtIncompetentRateCI RateCI
	CaughtMaliciousRateCI   RateCI
	SLABreachedRateCI       RateCI
	InconclusiveRateCI      RateCI
	CorrectDetectionRateCI  RateCI

	MeanQueriesToVerdict   float64
	MedianQueriesToVerdict int
	P90QueriesToVerdict    int
	MinQueriesToVerdict    int
	MaxQueriesToVerdict    int

	MeanPosteriorH0 float64
	MeanPosteriorH1 float64
	MeanPosteriorH2 float64

	MeanContradictions float64
}

// ResultsIncompetent is kept separate from r.Results so the honest PrintSummary
// does not have to discriminate on type; callers retrieve via the returned
// slice of aggregates.
func (r *Runner) RunIncompetent(cfg IncompetentBaselineConfig) IncompetentAggregate {
	if r.Verbose {
		fmt.Printf(">>> %s: N=%d, pkts=%d, B=%d, p_incomp=%.4f, flag_rel=%.3f, ans=%s, ans_err=%.3f, η=%.4f, α=%.4f\n",
			cfg.Name, cfg.NumTrials, cfg.NumPackets, cfg.BatchSize,
			cfg.DelayModel.IncompetenceRate, cfg.FlagReliability,
			cfg.AnsweringStrategy, cfg.AnswerErrorRate,
			cfg.Verification.ErrorTolerance,
			cfg.Verification.ConfidenceThreshold)
	}

	trials := make([]IncompetentTrialResult, cfg.NumTrials)
	for i := 0; i < cfg.NumTrials; i++ {
		r.maybeSeedTrial("incompetent", cfg.Name, i)
		start := time.Now()
		trials[i] = r.runSingleIncompetentTrial(cfg, i)
		trials[i].Duration = time.Since(start)
	}
	agg := aggregateIncompetent(cfg, trials)

	if r.Verbose {
		fmt.Printf("    trusted=%s  H1=%s  H2=%s  SLA=%s  inconclusive=%s  median_q=%d\n",
			formatRateWithCI(agg.TrustedRate, agg.TrustedRateCI),
			formatRateWithCI(agg.CaughtIncompetentRate, agg.CaughtIncompetentRateCI),
			formatRateWithCI(agg.CaughtMaliciousRate, agg.CaughtMaliciousRateCI),
			formatRateWithCI(agg.SLABreachedRate, agg.SLABreachedRateCI),
			formatRateWithCI(agg.InconclusiveRate, agg.InconclusiveRateCI),
			agg.MedianQueriesToVerdict)
	}
	return agg
}

// incompetentFlagging returns a flagging function that sets the flag on a
// congested packet with probability `reliability`. A value of 1.0 is a
// perfectly-flagging network; 0.0 is the classical incompetent SNP that
// never flags its own congestion events.
func incompetentFlagging(reliability float64) network.FlaggingFn {
	return func(hasIncompetence, wasDelayed bool) bool {
		if hasIncompetence {
			return rand.Float64() < reliability
		}
		return false
	}
}

// adversarialFlagging flags a deliberately-delayed packet with probability pFlag.
// Untargeted packets are never flagged.
func adversarialFlagging(pFlag float64) network.FlaggingFn {
	return func(hasIncompetence, wasDelayed bool) bool {
		if !wasDelayed {
			return false
		}
		return rand.Float64() < pFlag
	}
}

func (r *Runner) runSingleIncompetentTrial(cfg IncompetentBaselineConfig, trialNum int) IncompetentTrialResult {
	sim := engine.NewSimulation()

	dm := network.NewDelayModelConfig(cfg.DelayModel)
	dm.Initialise(cfg.SimDuration + 10.0)

	prover := verification.NewProver(verification.AdversaryConfig{
		AnsweringStr:    cfg.AnsweringStrategy,
		AnswerErrorRate: cfg.AnswerErrorRate,
	})

	router := network.NewRouter(
		dm,
		network.DefaultHonestTargeting(), // TargetNone; incompetence fires via DelayModel.IncompetenceRate
		incompetentFlagging(cfg.FlagReliability),
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

	return IncompetentTrialResult{
		TrialNum:            trialNum,
		Verdict:             res.Verdict,
		VerdictClass:        classifyIncompetentVerdict(res),
		Confidence:          res.Confidence,
		QueriesUsed:         res.TotalQueries,
		ContradictionsFound: res.ContradictionsFound,
		PosteriorH0:         res.PosteriorH0,
		PosteriorH1:         res.PosteriorH1,
		PosteriorH2:         res.PosteriorH2,
	}
}

func classifyIncompetentVerdict(res verification.VerificationResult) string {
	if strings.Contains(res.Verdict, "SLA_BREACHED") {
		return "SLA_BREACHED"
	}
	switch res.Verdict {
	case "TRUSTED":
		return "TRUSTED"
	case "INCONCLUSIVE", "INSUFFICIENT_DATA":
		return "INCONCLUSIVE"
	case "DISHONEST":
		if res.PosteriorH1 >= res.PosteriorH2 {
			return "CAUGHT_INCOMPETENT"
		}
		return "CAUGHT_MALICIOUS"
	}
	return "UNKNOWN"
}

func aggregateIncompetent(cfg IncompetentBaselineConfig, trials []IncompetentTrialResult) IncompetentAggregate {
	n := len(trials)
	agg := IncompetentAggregate{Config: cfg, Trials: trials}
	if n == 0 {
		return agg
	}

	var trusted, caughtIncomp, caughtMal, slaBreach, inconclusive int
	var sumH0, sumH1, sumH2 float64
	var totalContradictions int
	queriesToVerdict := make([]int, 0, n)

	for _, t := range trials {
		switch t.VerdictClass {
		case "TRUSTED":
			trusted++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		case "CAUGHT_INCOMPETENT":
			caughtIncomp++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		case "CAUGHT_MALICIOUS":
			caughtMal++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		case "SLA_BREACHED":
			slaBreach++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		case "INCONCLUSIVE":
			inconclusive++
		}
		sumH0 += t.PosteriorH0
		sumH1 += t.PosteriorH1
		sumH2 += t.PosteriorH2
		totalContradictions += t.ContradictionsFound
	}
	correctDetections := caughtIncomp + caughtMal + slaBreach

	fn := float64(n)
	agg.TrustedRate = float64(trusted) / fn
	agg.CaughtIncompetentRate = float64(caughtIncomp) / fn
	agg.CaughtMaliciousRate = float64(caughtMal) / fn
	agg.SLABreachedRate = float64(slaBreach) / fn
	agg.InconclusiveRate = float64(inconclusive) / fn
	agg.CorrectDetectionRate = float64(correctDetections) / fn
	agg.TrustedRateCI = wilsonRateCI(trusted, n)
	agg.CaughtIncompetentRateCI = wilsonRateCI(caughtIncomp, n)
	agg.CaughtMaliciousRateCI = wilsonRateCI(caughtMal, n)
	agg.SLABreachedRateCI = wilsonRateCI(slaBreach, n)
	agg.InconclusiveRateCI = wilsonRateCI(inconclusive, n)
	agg.CorrectDetectionRateCI = wilsonRateCI(correctDetections, n)
	agg.MeanPosteriorH0 = sumH0 / fn
	agg.MeanPosteriorH1 = sumH1 / fn
	agg.MeanPosteriorH2 = sumH2 / fn
	agg.MeanContradictions = float64(totalContradictions) / fn

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

// --- Sweeps ---

// SweepIncompetenceRate varies p_incomp (DelayModel.IncompetenceRate).
// Low rates test whether tiny amounts of incompetence stay hidden; high
// rates test how fast genuine unreliability is caught.
func (r *Runner) SweepIncompetenceRate(base IncompetentBaselineConfig, rates []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: p_incomp sweep (%d values) ===\n", len(rates))
	out := make([]IncompetentAggregate, 0, len(rates))
	for _, p := range rates {
		cfg := base
		cfg.DelayModel.IncompetenceRate = p
		cfg.Name = fmt.Sprintf("%s_pincomp%.4f", base.Name, p)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepFlagReliability varies P(flag | congestion). At 1.0 the SNP is
// indistinguishable from honest; at 0.0 every congestion event leaks out
// as a hidden-delay admission when queried.
func (r *Runner) SweepFlagReliability(base IncompetentBaselineConfig, reliabilities []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: flag-reliability sweep (%d values) ===\n", len(reliabilities))
	out := make([]IncompetentAggregate, 0, len(reliabilities))
	for _, rel := range reliabilities {
		cfg := base
		cfg.FlagReliability = rel
		cfg.Name = fmt.Sprintf("%s_flagrel%.3f", base.Name, rel)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetentPhaseMap performs a 2D sweep over p_incomp and flag
// reliability. The output is flattened row-major by p_incomp, then
// flag-reliability, and each aggregate retains both axis values in Config.
func (r *Runner) SweepIncompetentPhaseMap(base IncompetentBaselineConfig, rates, reliabilities []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: phase map p_incomp x flag-reliability (%d x %d) ===\n", len(rates), len(reliabilities))
	out := make([]IncompetentAggregate, 0, len(rates)*len(reliabilities))
	for _, p := range rates {
		for _, rel := range reliabilities {
			cfg := base
			cfg.DelayModel.IncompetenceRate = p
			cfg.FlagReliability = rel
			cfg.Name = fmt.Sprintf("%s_pincomp%.4f_flagrel%.3f", base.Name, p, rel)
			out = append(out, r.RunIncompetent(cfg))
		}
	}
	return out
}

// SweepAnswerErrorRate varies how often the incompetent prover (using
// AnswerUnreliable) claims a congested packet was minimal. Each such
// answer is a contradiction, which is the signature of H2, so this
// sweep shows where the verdict flips from CAUGHT_INCOMPETENT to
// CAUGHT_MALICIOUS.
func (r *Runner) SweepAnswerErrorRate(base IncompetentBaselineConfig, rates []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: answer-error-rate sweep (%d values) ===\n", len(rates))
	out := make([]IncompetentAggregate, 0, len(rates))
	for _, ae := range rates {
		cfg := base
		cfg.AnsweringStrategy = verification.AnswerUnreliable
		cfg.AnswerErrorRate = ae
		cfg.Name = fmt.Sprintf("%s_anserr%.3f", base.Name, ae)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetentEta varies the verifier's error-tolerance parameter while
// the network is incompetent. Small η makes the verifier strict and risks
// mislabelling H1 noise as H2; large η is lenient and risks missing the
// incompetence entirely.
func (r *Runner) SweepIncompetentEta(base IncompetentBaselineConfig, etas []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: η sweep (%d values) ===\n", len(etas))
	out := make([]IncompetentAggregate, 0, len(etas))
	for _, e := range etas {
		cfg := base
		cfg.Verification.ErrorTolerance = e
		cfg.Name = fmt.Sprintf("%s_eta%.4f", base.Name, e)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetentAlpha varies the confidence threshold α against a fixed
// incompetent network.
func (r *Runner) SweepIncompetentAlpha(base IncompetentBaselineConfig, alphas []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: α sweep (%d values) ===\n", len(alphas))
	out := make([]IncompetentAggregate, 0, len(alphas))
	for _, a := range alphas {
		cfg := base
		cfg.Verification.ConfidenceThreshold = a
		cfg.Name = fmt.Sprintf("%s_alpha%.6f", base.Name, a)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetentNumPackets varies the number of packets per trial (batch
// budget). At small p_incomp the verifier may need many batches before it
// happens to query a congested packet.
func (r *Runner) SweepIncompetentNumPackets(base IncompetentBaselineConfig, ns []int) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: NumPackets sweep (%d values) ===\n", len(ns))
	out := make([]IncompetentAggregate, 0, len(ns))
	for _, n := range ns {
		cfg := base
		cfg.NumPackets = n
		cfg.Name = fmt.Sprintf("%s_pkts%d", base.Name, n)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetentBatchSize varies B while keeping total NumPackets fixed.
// Larger B means fewer batches (and fewer queries under the one-query-
// per-batch rule), but each query still has the same per-packet chance of
// hitting a congested packet.
func (r *Runner) SweepIncompetentBatchSize(base IncompetentBaselineConfig, batches []int) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: batch-size sweep (%d values) ===\n", len(batches))
	out := make([]IncompetentAggregate, 0, len(batches))
	for _, b := range batches {
		cfg := base
		cfg.BatchSize = b
		cfg.Name = fmt.Sprintf("%s_batch%d", base.Name, b)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetentQueriesPerBatch varies verifier audit aggressiveness via
// QueriesPerBatch. Larger values query more packets from each batch and can
// accelerate detection when incompetence signals are sparse.
func (r *Runner) SweepIncompetentQueriesPerBatch(base IncompetentBaselineConfig, qpbs []int) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: queries-per-batch sweep (%d values) ===\n", len(qpbs))
	out := make([]IncompetentAggregate, 0, len(qpbs))
	for _, qpb := range qpbs {
		cfg := base
		cfg.Verification.QueriesPerBatch = qpb
		cfg.Name = fmt.Sprintf("%s_qpb%d", base.Name, qpb)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetenceMagnitude varies µ (the log-normal mean of the
// congestion-delay distribution). The verifier uses batch ordering, not
// absolute magnitude, so this sweep is expected to be flat; running it
// makes that design property empirical rather than asserted.
func (r *Runner) SweepIncompetenceMagnitude(base IncompetentBaselineConfig, mus []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: incompetence-magnitude µ sweep (%d values) ===\n", len(mus))
	out := make([]IncompetentAggregate, 0, len(mus))
	for _, mu := range mus {
		cfg := base
		cfg.DelayModel.IncompetenceMu = mu
		cfg.Name = fmt.Sprintf("%s_mu%.3f", base.Name, mu)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

// SweepIncompetentFlagThreshold varies τ_flag, the verifier's SLA flagging
// rate threshold, to see when the corrected flag rate catches incompetence
// before the Bayesian posterior does.
func (r *Runner) SweepIncompetentFlagThreshold(base IncompetentBaselineConfig, taus []float64) []IncompetentAggregate {
	fmt.Printf("\n=== Incompetent: τ_flag sweep (%d values) ===\n", len(taus))
	out := make([]IncompetentAggregate, 0, len(taus))
	for _, tau := range taus {
		cfg := base
		cfg.Verification.FlaggingRateThreshold = tau
		cfg.Name = fmt.Sprintf("%s_tauflag%.4f", base.Name, tau)
		out = append(out, r.RunIncompetent(cfg))
	}
	return out
}

func (r *Runner) SaveIncompetentAggregates(path string, results []IncompetentAggregate) error {
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
