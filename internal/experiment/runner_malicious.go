package experiment

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"satnet-simulator/internal/engine"
	"satnet-simulator/internal/network"
	"satnet-simulator/internal/verification"
)

// MaliciousBaselineConfig models a network that deliberately injects delay
// into a subset of packets while trying to evade the verifier.  The three
// core adversarial parameters map directly onto the generalised parametric
// adversary from §5.5:
//
//	p_target — fraction of packets deliberately delayed  (Targeting.TargetFraction)
//	p_flag   — probability a targeted packet is proactively flagged (PFlag)
//	p_lie    — probability the SNP claims a delayed, unflagged packet is minimal (PLie)
//
// Every named strategy in §5.3–5.4 is a corner of this cube:
//
//	Naive Liar:     p_flag=0, p_lie=1
//	Silent Dropper: p_flag=0, p_lie=0
//	Smart Strategy: p_flag=1, p_lie=0, p_target ≤ τ_flag
type MaliciousBaselineConfig struct {
	Name        string
	NumTrials   int
	NumPackets  int
	BatchSize   int
	SimDuration float64

	DelayModel network.DelayModelConfig // DeliberateMin/Max carry d_mal

	Targeting network.TargetingConfig

	PFlag float64 // p_flag
	PLie  float64 // p_lie

	AnsweringStrategy verification.AnsweringStrategy
	Verification      verification.VerificationConfig
}

func DefaultMaliciousBaseline() MaliciousBaselineConfig {
	return MaliciousBaselineConfig{
		Name:        "malicious_baseline",
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
			DeliberateMin:     0.050,
			DeliberateMax:     0.050,
		},
		Targeting:         network.DefaultAdversarialTargeting(0.10),
		PFlag:             0.0,
		PLie:              1.0,
		AnsweringStrategy: verification.AnswerParametric,
		Verification:      verification.DefaultVerificationConfig(),
	}
}

// AggressivePFlag computes the p_flag that exactly consumes the SLA flagging
// budget when the adversary targets pTarget fraction of packets (§5.5
// "Aggressive Optimisation").
func AggressivePFlag(pTarget, tauFlag float64) float64 {
	if pTarget <= 0 {
		return 0
	}
	return math.Min(1.0, tauFlag/pTarget)
}

// ============================================================================
// Trial result types
// ============================================================================

type MaliciousTrialResult struct {
	TrialNum            int
	Verdict             string
	VerdictClass        string
	Confidence          float64
	QueriesUsed         int
	ContradictionsFound int
	PosteriorH0         float64
	PosteriorH1         float64
	PosteriorH2         float64
	Duration            time.Duration
}

type MaliciousAggregate struct {
	Config MaliciousBaselineConfig
	Trials []MaliciousTrialResult

	// Detection-rate breakdown
	MissedRate                float64 // false negative: malicious slipped through as TRUSTED
	CaughtMaliciousRate       float64 // H2 posterior wins — correct classification
	MisclassifiedIncompRate   float64 // H1 posterior wins — wrong sub-class
	SLABreachedRate           float64 // caught via flagging-rate axis
	InconclusiveRate          float64
	CorrectDetectionRate      float64 // caught by any mechanism
	MissedRateCI              RateCI
	CaughtMaliciousRateCI     RateCI
	MisclassifiedIncompRateCI RateCI
	SLABreachedRateCI         RateCI
	InconclusiveRateCI        RateCI
	CorrectDetectionRateCI    RateCI

	MeanQueriesToVerdict   float64
	MedianQueriesToVerdict int
	P90QueriesToVerdict    int
	MinQueriesToVerdict    int
	MaxQueriesToVerdict    int

	MeanPosteriorH0    float64
	MeanPosteriorH1    float64
	MeanPosteriorH2    float64
	MeanContradictions float64
}

// ============================================================================
// Core trial runner
// ============================================================================

func (r *Runner) RunMalicious(cfg MaliciousBaselineConfig) MaliciousAggregate {
	if r.Verbose {
		fmt.Printf(">>> %s: N=%d, pkts=%d, B=%d, p_target=%.4f, p_flag=%.3f, p_lie=%.3f, d_mal=[%.3f,%.3f], η=%.4f, α=%.4f\n",
			cfg.Name, cfg.NumTrials, cfg.NumPackets, cfg.BatchSize,
			cfg.Targeting.TargetFraction, cfg.PFlag, cfg.PLie,
			cfg.DelayModel.DeliberateMin, cfg.DelayModel.DeliberateMax,
			cfg.Verification.ErrorTolerance,
			cfg.Verification.ConfidenceThreshold)
	}

	trials := make([]MaliciousTrialResult, cfg.NumTrials)
	for i := 0; i < cfg.NumTrials; i++ {
		r.maybeSeedTrial("malicious", cfg.Name, i)
		start := time.Now()
		trials[i] = r.runSingleMaliciousTrial(cfg, i)
		trials[i].Duration = time.Since(start)
	}

	agg := aggregateMalicious(cfg, trials)
	if r.Verbose {
		fmt.Printf("    missed=%s  caught_H2=%s  caught_H1=%s  SLA=%s  inconclusive=%s  median_q=%d\n",
			formatRateWithCI(agg.MissedRate, agg.MissedRateCI),
			formatRateWithCI(agg.CaughtMaliciousRate, agg.CaughtMaliciousRateCI),
			formatRateWithCI(agg.MisclassifiedIncompRate, agg.MisclassifiedIncompRateCI),
			formatRateWithCI(agg.SLABreachedRate, agg.SLABreachedRateCI),
			formatRateWithCI(agg.InconclusiveRate, agg.InconclusiveRateCI),
			agg.MedianQueriesToVerdict)
	}
	return agg
}

func (r *Runner) runSingleMaliciousTrial(cfg MaliciousBaselineConfig, trialNum int) MaliciousTrialResult {
	sim := engine.NewSimulation()

	dm := network.NewDelayModelConfig(cfg.DelayModel)
	dm.Initialise(cfg.SimDuration + 10.0)

	prover := verification.NewProver(verification.AdversaryConfig{
		AnsweringStr: cfg.AnsweringStrategy,
		LieRate:      cfg.PLie,
	})

	router := network.NewRouter(dm, cfg.Targeting, adversarialFlagging(cfg.PFlag))
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

	return MaliciousTrialResult{
		TrialNum:            trialNum,
		Verdict:             res.Verdict,
		VerdictClass:        classifyMaliciousVerdict(res),
		Confidence:          res.Confidence,
		QueriesUsed:         res.TotalQueries,
		ContradictionsFound: res.ContradictionsFound,
		PosteriorH0:         res.PosteriorH0,
		PosteriorH1:         res.PosteriorH1,
		PosteriorH2:         res.PosteriorH2,
	}
}

func classifyMaliciousVerdict(res verification.VerificationResult) string {
	if strings.Contains(res.Verdict, "SLA_BREACHED") {
		return "SLA_BREACHED"
	}
	switch res.Verdict {
	case "TRUSTED":
		return "MISSED"
	case "INCONCLUSIVE", "INSUFFICIENT_DATA":
		return "INCONCLUSIVE"
	case "DISHONEST":
		if res.PosteriorH2 >= res.PosteriorH1 {
			return "CAUGHT_MALICIOUS"
		}
		return "MISCLASSIFIED_INCOMPETENT"
	}
	return "UNKNOWN"
}

func aggregateMalicious(cfg MaliciousBaselineConfig, trials []MaliciousTrialResult) MaliciousAggregate {
	n := len(trials)
	agg := MaliciousAggregate{Config: cfg, Trials: trials}
	if n == 0 {
		return agg
	}

	var missed, caughtMal, misclassIncomp, slaBreach, inconclusive int
	var sumH0, sumH1, sumH2 float64
	var totalContradictions int
	queriesToVerdict := make([]int, 0, n)

	for _, t := range trials {
		switch t.VerdictClass {
		case "MISSED":
			missed++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		case "CAUGHT_MALICIOUS":
			caughtMal++
			queriesToVerdict = append(queriesToVerdict, t.QueriesUsed)
		case "MISCLASSIFIED_INCOMPETENT":
			misclassIncomp++
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
	correctDetections := caughtMal + misclassIncomp + slaBreach

	fn := float64(n)
	agg.MissedRate = float64(missed) / fn
	agg.CaughtMaliciousRate = float64(caughtMal) / fn
	agg.MisclassifiedIncompRate = float64(misclassIncomp) / fn
	agg.SLABreachedRate = float64(slaBreach) / fn
	agg.InconclusiveRate = float64(inconclusive) / fn
	agg.CorrectDetectionRate = float64(correctDetections) / fn
	agg.MissedRateCI = wilsonRateCI(missed, n)
	agg.CaughtMaliciousRateCI = wilsonRateCI(caughtMal, n)
	agg.MisclassifiedIncompRateCI = wilsonRateCI(misclassIncomp, n)
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

func (r *Runner) SaveMaliciousAggregates(path string, results []MaliciousAggregate) error {
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

// ============================================================================
// Named-strategy constructors (§5.3 – §5.4)
// ============================================================================

// NaiveLiarConfig returns the baseline config for §5.3.1: p_flag=0, p_lie=1.
// The SNP randomly targets packets and lies about every queried delay.
func NaiveLiarConfig(base MaliciousBaselineConfig, pTarget float64) MaliciousBaselineConfig {
	cfg := base
	cfg.Targeting = network.DefaultAdversarialTargeting(pTarget)
	cfg.PFlag = 0.0
	cfg.PLie = 1.0
	cfg.AnsweringStrategy = verification.AnswerParametric
	return cfg
}

// SilentDropperConfig returns the config for §5.3.2: p_flag=0, p_lie=0.
// The SNP admits every delay honestly but never pre-flags; caught by the
// corrected flagging-rate threshold rather than contradictions.
func SilentDropperConfig(base MaliciousBaselineConfig, pTarget float64) MaliciousBaselineConfig {
	cfg := base
	cfg.Targeting = network.DefaultAdversarialTargeting(pTarget)
	cfg.PFlag = 0.0
	cfg.PLie = 0.0
	cfg.AnsweringStrategy = verification.AnswerParametric
	return cfg
}

// SmartStrategyConfig returns the config for §5.4: p_flag=1, p_lie=0,
// pTarget ≤ τ_flag.  Flags every targeted packet truthfully; should receive
// TRUSTED because it never exceeds the SLA contract.
func SmartStrategyConfig(base MaliciousBaselineConfig, pTarget float64) MaliciousBaselineConfig {
	cfg := base
	cfg.Targeting = network.DefaultAdversarialTargeting(pTarget)
	cfg.PFlag = 1.0
	cfg.PLie = 0.0
	cfg.AnsweringStrategy = verification.AnswerParametric
	return cfg
}

// ParametricConfig returns a fully configurable adversary (§5.5).
func ParametricConfig(base MaliciousBaselineConfig, pTarget, pFlag, pLie float64) MaliciousBaselineConfig {
	cfg := base
	cfg.Targeting = network.DefaultAdversarialTargeting(pTarget)
	cfg.PFlag = pFlag
	cfg.PLie = pLie
	cfg.AnsweringStrategy = verification.AnswerParametric
	return cfg
}

// ============================================================================
// Sweeps
// ============================================================================

// SweepMaliciousPTarget varies p_target (targeting rate) across all modes that
// take a fraction (Random). Other targeting modes use SweepMaliciousTargetingModes.
func (r *Runner) SweepMaliciousPTarget(base MaliciousBaselineConfig, pTargets []float64) []MaliciousAggregate {
	fmt.Printf("\n=== Malicious: p_target sweep (%d values) [%s] ===\n", len(pTargets), base.Name)
	out := make([]MaliciousAggregate, 0, len(pTargets))
	for _, p := range pTargets {
		cfg := base
		cfg.Targeting = network.DefaultAdversarialTargeting(p)
		cfg.Name = fmt.Sprintf("%s_ptarget%.4f", base.Name, p)
		out = append(out, r.RunMalicious(cfg))
	}
	return out
}

// SweepMaliciousPFlag varies p_flag at a fixed p_target.
func (r *Runner) SweepMaliciousPFlag(base MaliciousBaselineConfig, pFlags []float64) []MaliciousAggregate {
	fmt.Printf("\n=== Malicious: p_flag sweep (%d values) [%s] ===\n", len(pFlags), base.Name)
	out := make([]MaliciousAggregate, 0, len(pFlags))
	for _, pf := range pFlags {
		cfg := base
		cfg.PFlag = pf
		cfg.Name = fmt.Sprintf("%s_pflag%.4f", base.Name, pf)
		out = append(out, r.RunMalicious(cfg))
	}
	return out
}

// SweepMaliciousPLie varies p_lie at fixed p_target and p_flag.
func (r *Runner) SweepMaliciousPLie(base MaliciousBaselineConfig, pLies []float64) []MaliciousAggregate {
	fmt.Printf("\n=== Malicious: p_lie sweep (%d values) [%s] ===\n", len(pLies), base.Name)
	out := make([]MaliciousAggregate, 0, len(pLies))
	for _, pl := range pLies {
		cfg := base
		cfg.PLie = pl
		cfg.Name = fmt.Sprintf("%s_plie%.4f", base.Name, pl)
		out = append(out, r.RunMalicious(cfg))
	}
	return out
}

// SweepMaliciousPhaseMap runs a 2D sweep over p_target and p_lie with p_flag
// set to the aggressive optimum (τ_flag / p_target) at each point.
func (r *Runner) SweepMaliciousPhaseMap(base MaliciousBaselineConfig, pTargets, pLies []float64) []MaliciousAggregate {
	tauFlag := base.Verification.FlaggingRateThreshold
	fmt.Printf("\n=== Malicious: phase map p_target x p_lie (%d x %d, aggressive p_flag) [%s] ===\n",
		len(pTargets), len(pLies), base.Name)
	out := make([]MaliciousAggregate, 0, len(pTargets)*len(pLies))
	for _, pt := range pTargets {
		for _, pl := range pLies {
			cfg := base
			cfg.Targeting = network.DefaultAdversarialTargeting(pt)
			cfg.PFlag = AggressivePFlag(pt, tauFlag)
			cfg.PLie = pl
			cfg.Name = fmt.Sprintf("%s_ptarget%.4f_plie%.4f", base.Name, pt, pl)
			out = append(out, r.RunMalicious(cfg))
		}
	}
	return out
}

// SweepMaliciousTargetingModes compares all four non-trivial targeting modes
// (Random, Periodic, Quota, All) at a single p_target-equivalent rate using
// the Naive Liar strategy (p_flag=0, p_lie=1) so targeting selection is the
// only variable.
func (r *Runner) SweepMaliciousTargetingModes(base MaliciousBaselineConfig) []MaliciousAggregate {
	fmt.Printf("\n=== Malicious: targeting mode comparison [%s] ===\n", base.Name)

	batchSize := base.BatchSize
	if batchSize < 2 {
		batchSize = 2
	}

	// Approximately 10% targeting equivalent across modes
	const approxRate = 0.10
	period := int(math.Round(1.0 / approxRate))
	quota := int(math.Round(float64(batchSize) * approxRate))
	if quota < 1 {
		quota = 1
	}

	modes := []struct {
		name      string
		targeting network.TargetingConfig
	}{
		{"random", network.DefaultAdversarialTargeting(approxRate)},
		{"periodic", network.DefaultPeriodicTargeting(period)},
		{"quota", network.DefaultQuotaTargeting(quota, batchSize)},
		{"all", network.DefaultAllTargeting()},
	}

	out := make([]MaliciousAggregate, 0, len(modes))
	for _, m := range modes {
		cfg := base
		cfg.Targeting = m.targeting
		cfg.PFlag = 0.0
		cfg.PLie = 1.0
		cfg.AnsweringStrategy = verification.AnswerParametric
		cfg.Name = fmt.Sprintf("%s_mode_%s", base.Name, m.name)
		out = append(out, r.RunMalicious(cfg))
	}
	return out
}
