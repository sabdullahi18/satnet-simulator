package verification

import (
	"math"
	"math/rand"
	"sort"
)

const epsilon = 1e-9

// VerificationConfig holds the parameters for the Bayesian verifier.
type VerificationConfig struct {
	ErrorTolerance      float64 // η — maximum tolerable error rate; governs all Bayesian likelihoods
	ConfidenceThreshold float64 // α — posterior threshold for sequential stopping (e.g. 0.95)
	MaxQueries          int     // safety cap on total prover queries
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		ErrorTolerance:      0.05,
		ConfidenceThreshold: 0.95,
		MaxQueries:          500,
	}
}

type VerificationResult struct {
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	TotalQueries        int
	ContradictionsFound int
	PosteriorH0         float64 // P(Honest | evidence)
	PosteriorH1         float64 // P(Incompetent | evidence)
	PosteriorH2         float64 // P(Malicious | evidence)
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

	eta := v.Config.ErrorTolerance

	// All likelihoods are derived from η (error tolerance).
	//
	// Contradiction evidence — prover claims minimal, another packet arrived sooner:
	//   P(C|H0) = ε        honest networks cannot produce contradictions (system error only)
	//   P(C|H1) = η        incompetent prover's error rate
	//   P(C|H2) = 1-η      malicious prover, high contradiction risk
	//
	// Clean query — no contradiction detected:
	//   P(K|H0) = 1-ε      complement of H0 contradiction rate
	//   P(K|H1) = 1-η      complement of H1 contradiction rate
	//   P(K|H2) = η        malicious prover occasionally avoids contradiction
	//
	// Flagging inconsistency — unflagged packet with delay > flagged packet, prover admits non-minimal:
	//   P(F|H0) = η        honest networks rarely fail to flag delayed packets
	//   P(F|H1) = 1-η      incompetent networks commonly miss flags (strongly favours H1)
	//   P(F|H2) = η        malicious networks have a similar low miss-flag rate as honest
	pContraH0 := epsilon
	pContraH1 := eta
	pContraH2 := 1 - eta

	pCleanH0 := 1 - epsilon
	pCleanH1 := 1 - eta
	pCleanH2 := eta

	pFlagH0 := eta
	pFlagH1 := 1 - eta
	pFlagH2 := eta

	batches := v.groupByTime()

	// Bayesian posterior over [H0, H1, H2] — uniform (uninformative) prior.
	post := [3]float64{1.0 / 3, 1.0 / 3, 1.0 / 3}

	contradictions := 0
	queries := 0

	times := make([]int, 0, len(batches))
	for bid := range batches {
		times = append(times, bid)
	}
	rand.Shuffle(len(times), func(i, j int) {
		times[i], times[j] = times[j], times[i]
	})

	alpha := v.Config.ConfidenceThreshold

	for _, bid := range times {
		// Sequential stopping: halt when any posterior exceeds α.
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

		// Minimum observed delay in this batch. All packets share the same base delay,
		// so any spread reflects congestion or deliberate delay.
		minDelay := batch[0].ActualDelay
		for _, p := range batch[1:] {
			if p.ActualDelay < minDelay {
				minDelay = p.ActualDelay
			}
		}

		// Minimum delay among flagged packets in this batch. An unflagged packet
		// with delay > minFlaggedInBatch means the network failed to flag a congested packet.
		minFlaggedInBatch := math.MaxFloat64
		for _, p := range batch {
			if p.IsFlagged && p.ActualDelay < minFlaggedInBatch {
				minFlaggedInBatch = p.ActualDelay
			}
		}

		// Randomly select one packet from the batch to query.
		idx := rand.Intn(len(batch))
		p := batch[idx]

		q := Query{ObservedDelay: p.ActualDelay, SentTime: p.SentTime}
		ans := v.Prover.AnswerQuery(q)
		queries++

		// Contradiction check: prover claims minimal, but another packet in the same
		// batch (same base delay) arrived sooner — logically impossible for an honest prover.
		if ans.IsMinimal && p.ActualDelay > minDelay {
			contradictions++
			post = bayesUpdate(post, pContraH0, pContraH1, pContraH2)
		} else {
			post = bayesUpdate(post, pCleanH0, pCleanH1, pCleanH2)
		}

		// Flagging inconsistency check: if a flagged packet with delay d1 exists in the
		// batch, the queried packet (delay d2 > d1) was not flagged, and the prover admits
		// d2 was not minimal — the network failed to flag a congested packet (incompetence).
		// When ans.IsMinimal, d2 > d1 >= minDelay so the main contradiction check already fired.
		if !p.IsFlagged && minFlaggedInBatch < math.MaxFloat64 && p.ActualDelay > minFlaggedInBatch && !ans.IsMinimal {
			post = bayesUpdate(post, pFlagH0, pFlagH1, pFlagH2)
		}
	}

	// Verdict derivation per README verdict table:
	//   P(H2|E) > α  → DISHONEST
	//   P(H1|E) > α  → DISHONEST
	//   P(H0|E) > α  → TRUSTED
	//   otherwise    → INCONCLUSIVE (Trustworthy depends on P(H0))
	//
	// A logical contradiction is a deductive proof of dishonesty — confidence is certain.
	if contradictions > 0 {
		return VerificationResult{
			Verdict: "DISHONEST", Confidence: 1.0, Trustworthy: false,
			TotalQueries: queries, ContradictionsFound: contradictions,
			PosteriorH0: post[0], PosteriorH1: post[1], PosteriorH2: post[2],
		}
	}

	verdict := "INCONCLUSIVE"
	trustworthy := post[0] >= post[1] && post[0] >= post[2]
	confidence := maxf(post[0], post[1], post[2])

	if post[2] > alpha {
		verdict = "DISHONEST"
		trustworthy = false
		confidence = post[2]
	} else if post[1] > alpha {
		verdict = "DISHONEST"
		trustworthy = false
		confidence = post[1]
	} else if post[0] > alpha {
		verdict = "TRUSTED"
		trustworthy = true
		confidence = post[0]
	}

	return VerificationResult{
		Verdict:             verdict,
		Confidence:          confidence,
		Trustworthy:         trustworthy,
		TotalQueries:        queries,
		ContradictionsFound: contradictions,
		PosteriorH0:         post[0],
		PosteriorH1:         post[1],
		PosteriorH2:         post[2],
	}
}

// bayesUpdate applies one Bayes step and re-normalises the posterior.
// Resets to uniform prior on numerical underflow.
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
