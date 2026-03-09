package verification

import (
	"math"
	"math/rand"
	"sort"
)

// Likelihood constants for each hypothesis under observed evidence types.
//
// H0 = honest network, H1 = incompetent network, H2 = malicious network.
const (
	// P(contradiction | H_j): honest networks never produce false minimal claims.
	pContraH0 = 1e-9 // essentially impossible
	pContraH1 = 0.05 // incompetent networks occasionally make wrong minimal claims
	pContraH2 = 0.50 // malicious networks risk contradiction through deliberate deception

	// P(flagging inconsistency | H_j): unflagged packet with delay exceeding a flagged
	// packet, prover admits non-minimal — indicates failure to flag (incompetence signal).
	pFlagInconsistH0 = 0.01
	pFlagInconsistH1 = 0.20
	pFlagInconsistH2 = 0.10

	// Baseline likelihoods for a clean query with no anomalies detected.
	pCleanH0 = 0.90
	pCleanH1 = 0.60
	pCleanH2 = 0.40
)

type VerificationConfig struct {
	MaxQueries          int
	FlagRateThreshold   float64
	ConfidenceThreshold float64 // Sequential stopping: halt when any P(H_j | evidence) exceeds this
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		MaxQueries:          500,
		FlagRateThreshold:   0.30,
		ConfidenceThreshold: 0.95,
	}
}

type VerificationResult struct {
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	TotalQueries        int
	ContradictionsFound int
	FlaggingRate        float64
	PosteriorH0         float64 // P(Honest | evidence)
	PosteriorH1         float64 // P(Incompetent | evidence)
	PosteriorH2         float64 // P(Malicious | evidence)
}

// empiricalDist incrementally accumulates delay samples and estimates probability
// density via Gaussian KDE using Silverman's bandwidth rule.
type empiricalDist struct {
	samples []float64
	sum     float64
	sumSq   float64
}

func (e *empiricalDist) add(x float64) {
	e.samples = append(e.samples, x)
	e.sum += x
	e.sumSq += x * x
}

// pdf estimates the probability density at x. Returns 1.0 (uninformative) when
// fewer than 2 samples have been observed.
func (e *empiricalDist) pdf(x float64) float64 {
	n := len(e.samples)
	if n < 2 {
		return 1.0
	}
	mean := e.sum / float64(n)
	variance := e.sumSq/float64(n) - mean*mean
	if variance < 1e-20 {
		if math.Abs(x-mean) < 1e-9 {
			return 1.0
		}
		return 1e-10
	}
	sigma := math.Sqrt(variance)
	// Silverman's bandwidth rule: h = 1.06 * sigma * n^(-1/5)
	h := 1.06 * sigma * math.Pow(float64(n), -0.2)
	density := 0.0
	for _, s := range e.samples {
		u := (x - s) / h
		density += math.Exp(-0.5 * u * u)
	}
	return density / (float64(n) * h * math.Sqrt(2*math.Pi))
}

type Verifier struct {
	Prover  *Prover
	Records []TransmissionRecord
	Config  VerificationConfig
}

func NewVerifier(prover *Prover, config VerificationConfig) *Verifier {
	return &Verifier{
		Prover: prover,
		Config: config,
	}
}

func (v *Verifier) IngestRecords(records []TransmissionRecord) {
	v.Records = records
}

func (v *Verifier) RunVerification() VerificationResult {
	if len(v.Records) < 2 {
		return VerificationResult{
			Verdict: "INSUFFICIENT_DATA", Trustworthy: true,
			PosteriorH0: 1.0 / 3, PosteriorH1: 1.0 / 3, PosteriorH2: 1.0 / 3,
		}
	}

	// Count initially flagged packets for the overall flag rate denominator.
	initialFlaggedCount := 0
	for _, r := range v.Records {
		if r.IsFlagged {
			initialFlaggedCount++
		}
	}

	batches := v.groupByTime()

	// Bayesian posterior over [H0, H1, H2] — equal priors.
	post := [3]float64{1.0 / 3, 1.0 / 3, 1.0 / 3}

	// Empirical delay distributions built incrementally from query responses.
	// fMinimal: delays for packets the prover claims achieved minimal (base-only) delay.
	// fFlagged: delays for packets the prover flagged as having experienced congestion.
	fMinimal := &empiricalDist{}
	fFlagged := &empiricalDist{}

	// Pre-populate fFlagged from the network's pre-query flagging phase.
	for _, r := range v.Records {
		if r.IsFlagged {
			fFlagged.add(r.ActualDelay)
		}
	}

	contradictions := 0
	queries := 0
	// artificialFlagCount tracks unflagged packets caught via flagging inconsistency;
	// they inflate the flag rate to penalise incompetent provers.
	artificialFlagCount := 0

	times := make([]int, 0, len(batches))
	for bid := range batches {
		times = append(times, bid)
	}
	rand.Shuffle(len(times), func(i, j int) {
		times[i], times[j] = times[j], times[i]
	})

	alpha := v.Config.ConfidenceThreshold

	for _, bid := range times {
		// Sequential stopping: halt as soon as any posterior exceeds the confidence threshold.
		if maxf(post[0], post[1], post[2]) > alpha {
			break
		}
		if queries >= v.Config.MaxQueries {
			break
		}

		batch := batches[bid]
		if len(batch) < 2 {
			continue
		}

		// Minimum observed delay in this batch (same base delay for all packets in batch,
		// so any spread reflects congestion or malicious delay).
		minDelay := batch[0].ActualDelay
		for _, p := range batch[1:] {
			if p.ActualDelay < minDelay {
				minDelay = p.ActualDelay
			}
		}

		// Minimum delay among flagged packets within this batch.
		// All packets share the same base delay, so flagging a packet with delay d1 but
		// not flagging a packet with delay d2 > d1 in the same batch is inconsistent.
		minFlaggedInBatch := math.MaxFloat64
		for _, p := range batch {
			if p.IsFlagged && p.ActualDelay < minFlaggedInBatch {
				minFlaggedInBatch = p.ActualDelay
			}
		}

		// Query one randomly selected packet from the batch.
		idx := rand.Intn(len(batch))
		p := batch[idx]

		q := Query{ObservedDelay: p.ActualDelay, SentTime: p.SentTime}
		ans := v.Prover.AnswerQuery(q)
		queries++

		// Update empirical distributions from this response.
		if ans.IsMinimal {
			fMinimal.add(p.ActualDelay)
		}

		// Main contradiction check: prover claims minimal, but another packet in the same
		// batch (same base delay) arrived sooner — logically impossible for an honest prover.
		if ans.IsMinimal && p.ActualDelay > minDelay {
			contradictions++
			post = bayesUpdate(post, pContraH0, pContraH1, pContraH2)
		} else if ans.IsMinimal {
			// Soft evidence: use empirical distributions F_minimal and F_flagged to assess
			// how consistent this minimal claim is under each hypothesis.
			lH0, lH1, lH2 := softMinimalLikelihoods(p.ActualDelay, fMinimal, fFlagged)
			post = bayesUpdate(post, lH0, lH1, lH2)
		} else {
			// Prover admits the packet was not minimal — consistent with honest reporting.
			post = bayesUpdate(post, pCleanH0, pCleanH1, pCleanH2)
		}

		// Flagging inconsistency check (within-batch only — different batches have different
		// base delays so cross-batch absolute delay comparison is not meaningful):
		//
		// If the prover flagged some packet with delay d1 in this batch but did NOT flag
		// the queried packet p with delay d2 > d1:
		//   IsMinimal=true  → contradiction: d1 was flagged as congested, yet the larger
		//                     delay d2 is claimed minimal — impossible.
		//   IsMinimal=false → prover admits d2 was not minimal but never flagged it.
		//                     This is incompetence; treat p as if it should have been
		//                     flagged (artificial flag) and update posteriors accordingly.
		if !p.IsFlagged && minFlaggedInBatch < math.MaxFloat64 && p.ActualDelay > minFlaggedInBatch {
			if ans.IsMinimal {
				// Only count as a new contradiction if the main check did not already catch it.
				if !(p.ActualDelay > minDelay) {
					contradictions++
					post = bayesUpdate(post, pContraH0, pContraH1, pContraH2)
				}
			} else {
				artificialFlagCount++
				post = bayesUpdate(post, pFlagInconsistH0, pFlagInconsistH1, pFlagInconsistH2)
			}
		}
	}

	// Flagging rate measured over all delivered packets, not just queried ones.
	flaggingRate := 0.0
	if len(v.Records) > 0 {
		flaggingRate = float64(initialFlaggedCount+artificialFlagCount) / float64(len(v.Records))
	}

	// Flag rate anomaly: if the observed flag rate significantly exceeds the threshold,
	// this heavily penalises H0 and shifts probability mass toward H2 (malicious cover-up).
	// Each 5% excess beyond the threshold contributes one Bayesian update step.
	if flaggingRate > v.Config.FlagRateThreshold {
		excess := flaggingRate - v.Config.FlagRateThreshold
		steps := int(excess/0.05) + 1
		for i := 0; i < steps; i++ {
			post = bayesUpdate(post, 0.05, 0.40, 0.60)
		}
	}

	// Verdict derivation:
	//   1. Contradictions found       → DISHONEST (deductive proof, confidence=1.0)
	//   2. P(H2) > α                  → DISHONEST (statistically confident malicious)
	//   3. P(H1) > α                  → SUSPICIOUS_FLAG_RATE (statistically confident incompetent)
	//   4. P(H0) > α                  → TRUSTED
	//   5. Inconclusive (no posterior > α):
	//        flag rate > threshold    → SUSPICIOUS_FLAG_RATE (confidence=flaggingRate)
	//        otherwise               → TRUSTED (confidence=1.0-flaggingRate)
	verdict := "TRUSTED"
	trustworthy := true
	confidence := post[0] // P(H0 | evidence) — refined below

	if contradictions > 0 {
		// A contradiction is a deductive proof of dishonesty — confidence is certain.
		verdict = "DISHONEST"
		trustworthy = false
		confidence = 1.0
	} else if post[2] > alpha {
		// Bayesian posterior confidently identifies malicious behaviour.
		verdict = "DISHONEST"
		trustworthy = false
		confidence = post[2]
	} else if post[1] > alpha {
		// Bayesian posterior confidently identifies incompetent behaviour.
		verdict = "SUSPICIOUS_FLAG_RATE"
		trustworthy = false
		confidence = post[1]
	} else if post[0] > alpha {
		// Bayesian posterior confidently identifies honest behaviour.
		verdict = "TRUSTED"
		trustworthy = true
		confidence = post[0]
	} else if flaggingRate > v.Config.FlagRateThreshold {
		// Inconclusive posteriors but flag rate anomaly detected.
		verdict = "SUSPICIOUS_FLAG_RATE"
		trustworthy = false
		confidence = flaggingRate
	} else {
		// Inconclusive posteriors, no flag rate anomaly.
		confidence = 1.0 - flaggingRate
	}

	return VerificationResult{
		Verdict:             verdict,
		Confidence:          confidence,
		Trustworthy:         trustworthy,
		TotalQueries:        queries,
		ContradictionsFound: contradictions,
		FlaggingRate:        flaggingRate,
		PosteriorH0:         post[0],
		PosteriorH1:         post[1],
		PosteriorH2:         post[2],
	}
}

// bayesUpdate applies one Bayes step and re-normalises the posterior.
// If numerical underflow occurs, resets to a uniform prior.
func bayesUpdate(prior [3]float64, lH0, lH1, lH2 float64) [3]float64 {
	p0 := prior[0] * lH0
	p1 := prior[1] * lH1
	p2 := prior[2] * lH2
	sum := p0 + p1 + p2
	if sum < 1e-300 {
		return [3]float64{1.0 / 3, 1.0 / 3, 1.0 / 3}
	}
	return [3]float64{p0 / sum, p1 / sum, p2 / sum}
}

// softMinimalLikelihoods returns likelihoods for H0/H1/H2 given a minimal claim for delay d.
//
// Uses the empirical distributions F_minimal and F_flagged to assess consistency:
//   - Under H0: the delay should track the minimal distribution (honest minimal claims)
//   - Under H1: incompetent mixing means both distributions contribute to the likelihood
//   - Under H2: malicious actors try to pass deliberately-delayed packets as minimal,
//     so flagged-distribution delays are more likely to appear in "minimal" claims
func softMinimalLikelihoods(delay float64, fMinimal, fFlagged *empiricalDist) (lH0, lH1, lH2 float64) {
	pMin := math.Max(fMinimal.pdf(delay), 1e-9)
	pFlag := math.Max(fFlagged.pdf(delay), 1e-9)

	// fracMin in (0,1): how "minimal-like" is this delay relative to "flagged-like"
	fracMin := pMin / (pMin + pFlag)

	// H0: honest — minimal claims should closely match the minimal distribution
	lH0 = 0.05 + fracMin*0.85 // [0.05, 0.90]

	// H1: incompetent — noisier separation; both distributions contribute
	lH1 = 0.15 + fracMin*0.45 // [0.15, 0.60]

	// H2: malicious — more likely to mislabel flagged-distribution delays as minimal
	lH2 = 0.20 + (1-fracMin)*0.40 // [0.20, 0.60], inversely correlated with fracMin

	return
}

func maxf(a, b, c float64) float64 {
	if a >= b && a >= c {
		return a
	}
	if b >= c {
		return b
	}
	return c
}

func (v *Verifier) groupByTime() map[int][]TransmissionRecord {
	batches := make(map[int][]TransmissionRecord)

	sorted := make([]TransmissionRecord, len(v.Records))
	copy(sorted, v.Records)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].SentTime < sorted[j].SentTime
	})

	for _, r := range sorted {
		batches[int(r.SentTime)] = append(batches[int(r.SentTime)], r)
	}

	return batches
}
