package verification

import (
	"math"
	"math/rand"
	"sort"
)

type VerificationConfig struct {
	MaxQueries          int
	WindowSize          int     // Size of sliding window for baseline estimation
	QuantileAlpha       float64 // Quantile for baseline estimation (e.g. 0.05)
	CongestionThreshold float64 // Probability threshold to flag as suspicious
	HistoryCheckEnabled bool
	Distributions       AdversaryDistributions
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		MaxQueries:          500,
		WindowSize:          50,
		QuantileAlpha:       0.05,
		CongestionThreshold: 0.95,
		HistoryCheckEnabled: true,
		Distributions: AdversaryDistributions{
			LegitCongestion: DistributionConfig{Name: "LogNormal", Params: map[string]float64{"Mu": -4.6, "Sigma": 0.8}},
			MaliciousDelay:  DistributionConfig{Name: "Uniform", Params: map[string]float64{"Min": 0.1, "Max": 0.2}},
			BaseNoise:       DistributionConfig{Name: "Exponential", Params: map[string]float64{"Rate": 100.0}},
		},
	}
}

type VerificationResult struct {
	Verdict               string
	Confidence            float64
	Trustworthy           bool
	TotalQueries          int
	ContradictionsFound   int
	HistoryContradictions int
	ProbHonest            float64
	ProbIncompetent       float64
	ProbMalicious         float64
}

type Verifier struct {
	Oracle          *Oracle
	Records         []TransmissionRecord
	Config          VerificationConfig
	ProbHonest      float64
	ProbIncompetent float64
	ProbMalicious   float64

	// History of queries to the oracle
	QueryHistory map[int]Answer
}

func NewVerifier(oracle *Oracle, config VerificationConfig) *Verifier {
	return &Verifier{
		Oracle:          oracle,
		Config:          config,
		ProbHonest:      0.333,
		ProbIncompetent: 0.333,
		ProbMalicious:   0.333,
		QueryHistory:    make(map[int]Answer),
	}
}

func (v *Verifier) IngestRecords(records []TransmissionRecord) {
	v.Records = records
}

func (v *Verifier) RunVerification() VerificationResult {
	if len(v.Records) < v.Config.WindowSize {
		return VerificationResult{Verdict: "INSUFFICIENT_DATA", Trustworthy: true}
	}

	contradictions := 0
	historyContradictions := 0
	queries := 0

	// Indices to query - could be random or targeted
	indices := rand.Perm(len(v.Records))

	// Pre-calculate baseline delays using sliding window
	baseDelays := v.estimateBaseDelays()

	for _, idx := range indices {
		if queries >= v.Config.MaxQueries {
			break
		}

		p := v.Records[idx]

		// Skip if we can't estimate base delay for this packet (e.g. edges)
		estimatedBase, ok := baseDelays[p.ID]
		if !ok {
			continue
		}

		// Simulate query time - simplified here as sequential post-hoc
		// If verification happened during simulation, this would be sim.Now
		// For now, let's assume verification starts at end of sim and takes time
		queryTime := v.Records[len(v.Records)-1].SentTime + 1.0 + float64(queries)*0.001

		q := Query{PktID: p.ID, Time: queryTime}
		ans := v.Oracle.AnswerQuery(q)
		queries++

		// Consistency Check
		if v.Config.HistoryCheckEnabled {
			if prevAns, exists := v.QueryHistory[p.ID]; exists {
				if prevAns != ans {
					historyContradictions++
					// History contradiction is strong evidence against honesty
					v.updateBeliefsHistoryContradiction()
				}
			}
			v.QueryHistory[p.ID] = ans
		}

		// Analysis
		obsDelay := p.ActualDelay
		excessDelay := obsDelay - estimatedBase
		if excessDelay < 0 {
			excessDelay = 0
		}

		v.updateBeliefs(ans, excessDelay)

		// Check for specific contradictions for reporting
		// Logical Contradiction: Oracle says Minimal, but delay is clearly high
		if ans == AnswerMinimal {
			// Threshold for "clearly high"?
			// Check if likelihood of Minimal is tiny compared to Flagged/Malicious
			if excessDelay > 0.05 { // 50ms excess is likely not minimal noise
				contradictions++
			}
		}

		// If strongly converged, break early?
		if v.ProbMalicious > 0.999 && contradictions > 5 {
			break
		}
	}

	verdict := "TRUSTED"
	trustworthy := true
	confidence := v.ProbHonest

	if v.ProbMalicious > v.ProbHonest && v.ProbMalicious > v.ProbIncompetent {
		verdict = "MALICIOUS"
		trustworthy = false
		confidence = v.ProbMalicious
	} else if v.ProbIncompetent > v.ProbHonest {
		verdict = "INCOMPETENT"
		trustworthy = false
		confidence = v.ProbIncompetent
	}

	if historyContradictions > 0 {
		verdict = "HISTORY_CONTRADICTION"
		trustworthy = false
		confidence = 1.0
	}

	return VerificationResult{
		Verdict:               verdict,
		Confidence:            confidence,
		Trustworthy:           trustworthy,
		TotalQueries:          queries,
		ContradictionsFound:   contradictions,
		HistoryContradictions: historyContradictions,
		ProbHonest:            v.ProbHonest,
		ProbIncompetent:       v.ProbIncompetent,
		ProbMalicious:         v.ProbMalicious,
	}
}

// estimateBaseDelays uses a sliding window to find the alpha-quantile of delays
// This approximates the base delay path.
func (v *Verifier) estimateBaseDelays() map[int]float64 {
	estimates := make(map[int]float64)

	// Sort records by time to process in sliding window
	// (Assuming v.Records are somewhat ordered, but let's be safe if we need strict time order)
	// For simplicity, assuming v.Records index correlates with time or we sort them.
	// But ID might not be time-ordered. Let's create a timed list.
	type TimedRecord struct {
		ID    int
		Time  float64
		Delay float64
	}
	timed := make([]TimedRecord, len(v.Records))
	for i, r := range v.Records {
		timed[i] = TimedRecord{r.ID, r.SentTime, r.ActualDelay}
	}
	sort.Slice(timed, func(i, j int) bool {
		return timed[i].Time < timed[j].Time
	})

	halfWindow := v.Config.WindowSize / 2

	for i := 0; i < len(timed); i++ {
		start := i - halfWindow
		if start < 0 {
			start = 0
		}
		end := i + halfWindow
		if end > len(timed) {
			end = len(timed)
		}

		windowDelays := make([]float64, 0, end-start)
		for k := start; k < end; k++ {
			windowDelays = append(windowDelays, timed[k].Delay)
		}
		sort.Float64s(windowDelays)

		// Quantile
		idx := int(float64(len(windowDelays)) * v.Config.QuantileAlpha)
		if idx >= len(windowDelays) {
			idx = len(windowDelays) - 1
		}

		estimates[timed[i].ID] = windowDelays[idx]
	}
	return estimates
}

func (v *Verifier) updateBeliefsHistoryContradiction() {
	// Strong penalty for honesty
	// P(HistoryConflict | Honest) ~ 0 (unless bitflip error)
	// P(HistoryConflict | Malicious) > 0 (poor state management by attacker)

	lHonest := 0.0001
	lIncompetent := 0.1
	lMalicious := 0.9

	v.ProbHonest *= lHonest
	v.ProbIncompetent *= lIncompetent
	v.ProbMalicious *= lMalicious
	v.normalize()
}

func (v *Verifier) updateBeliefs(ans Answer, excessDelay float64) {
	// Calculate likelihoods P(Data | Hypothesis)

	// 1. Honest Hypothesis
	// If Minimal: Expected excess delay ~ 0 (or small noise)
	// If Flagged: Expected excess delay ~ LogNormal(LegitMu, LegitSigma) - but we don't know params?
	// The prompt implies we know distribution of legit delays.
	// Let's assume we know approximate Legit/Congestion params.

	lhHonest := v.likelihoodHonest(ans, excessDelay)
	lhIncompetent := v.likelihoodIncompetent(ans, excessDelay)
	lhMalicious := v.likelihoodMalicious(ans, excessDelay)

	v.ProbHonest *= lhHonest
	v.ProbIncompetent *= lhIncompetent
	v.ProbMalicious *= lhMalicious

	v.normalize()
}

func (v *Verifier) normalize() {
	total := v.ProbHonest + v.ProbIncompetent + v.ProbMalicious
	if total > 0 {
		v.ProbHonest /= total
		v.ProbIncompetent /= total
		v.ProbMalicious /= total
	}
}

func (v *Verifier) likelihoodHonest(ans Answer, delay float64) float64 {
	if ans == AnswerMinimal {
		// P(delay | Minimal, Honest)
		// Expected Base Noise
		rate := v.Config.Distributions.BaseNoise.Params["Rate"]
		return pdfExponential(delay, rate)
	} else {
		// P(delay | Flagged, Honest)
		// Expected Legit Congestion
		mu := v.Config.Distributions.LegitCongestion.Params["Mu"]
		sigma := v.Config.Distributions.LegitCongestion.Params["Sigma"]
		return pdfLogNormal(delay, mu, sigma)
	}
}

func (v *Verifier) likelihoodIncompetent(ans Answer, delay float64) float64 {
	// Incompetent: Random answer, but delay is honest (mixed)
	rate := v.Config.Distributions.BaseNoise.Params["Rate"]
	mu := v.Config.Distributions.LegitCongestion.Params["Mu"]
	sigma := v.Config.Distributions.LegitCongestion.Params["Sigma"]

	// Assume 90% minimal, 10% congested traffic overall (prior)
	probDelay := 0.9*pdfExponential(delay, rate) + 0.1*pdfLogNormal(delay, mu, sigma)

	return 0.5 * probDelay
}

func (v *Verifier) likelihoodMalicious(ans Answer, delay float64) float64 {
	// Malicious: Mixed Legit and Malicious

	if ans == AnswerFlagged {
		// P(delay | Flagged, MaliciousNode)
		// Mix of Legit LogNormal and Malicious Uniform
		mu := v.Config.Distributions.LegitCongestion.Params["Mu"]
		sigma := v.Config.Distributions.LegitCongestion.Params["Sigma"]
		min := v.Config.Distributions.MaliciousDelay.Params["Min"]
		max := v.Config.Distributions.MaliciousDelay.Params["Max"]

		lp := pdfLogNormal(delay, mu, sigma)
		mp := pdfUniform(delay, min, max)

		return 0.5*lp + 0.5*mp
	} else {
		// Answer Minimal but High Delay -> Gaslighting
		// If delay is high (> 50ms), very indicative of Gaslighting
		rate := v.Config.Distributions.BaseNoise.Params["Rate"]

		if delay > 0.05 {
			return 1.0
		}
		return pdfExponential(delay, rate)
	}
}

func pdfExponential(x, rate float64) float64 {
	if x < 0 {
		return 0
	}
	return rate * math.Exp(-rate*x)
}

func pdfLogNormal(x, mu, sigma float64) float64 {
	if x <= 0 {
		return 0
	}
	return (1 / (x * sigma * math.Sqrt(2*math.Pi))) * math.Exp(-math.Pow(math.Log(x)-mu, 2)/(2*sigma*sigma))
}

func pdfUniform(x, min, max float64) float64 {
	if x >= min && x <= max {
		return 1.0 / (max - min)
	}
	return 0.0001 // Small prob for robustness
}
