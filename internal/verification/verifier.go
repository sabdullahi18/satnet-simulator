package verification

import (
	"math"
	"math/rand"
)

type VerificationConfig struct {
	ErrorTolerance        float64
	ConfidenceThreshold   float64
	FlaggingRateThreshold float64
	Epsilon               float64
	QueriesPerBatch       int
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		ErrorTolerance:        0.05,
		ConfidenceThreshold:   0.95,
		FlaggingRateThreshold: 0.30,
		Epsilon:               1e-4,
		QueriesPerBatch:       1,
	}
}

type VerificationResult struct {
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	TotalQueries        int
	ContradictionsFound int
	PosteriorH0         float64
	PosteriorH1         float64
	PosteriorH2         float64
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

	lt := LikelihoodTable{
		Epsilon: v.Config.Epsilon,
		Eta:     v.Config.ErrorTolerance,
	}

	batches := v.groupByBatch()

	totalPackets := len(v.Records)
	flaggedCount := 0
	for _, r := range v.Records {
		if r.IsFlagged {
			flaggedCount++
		}
	}

	logPost := [3]float64{math.Log(1.0 / 3), math.Log(1.0 / 3), math.Log(1.0 / 3)}
	contradictions := 0
	queries := 0
	hiddenDelaysFound := 0

	if v.Config.FlaggingRateThreshold > 0 {
		flagRate := float64(flaggedCount) / float64(totalPackets)
		if flagRate > v.Config.FlaggingRateThreshold {
			post := normaliseLogPosterior(logPost)
			return VerificationResult{
				Verdict:     "DISHONEST (SLA_BREACHED)",
				Confidence:  1.0,
				Trustworthy: false,
				PosteriorH0: post[0],
				PosteriorH1: post[1],
				PosteriorH2: post[2],
			}
		}
	}

	times := make([]int, 0, len(batches))
	for bid := range batches {
		times = append(times, bid)
	}
	rand.Shuffle(len(times), func(i, j int) {
		times[i], times[j] = times[j], times[i]
	})

	alpha := v.Config.ConfidenceThreshold
	logAlpha := math.Log(alpha)
	slaBreached := false

	for _, bid := range times {
		if maxLogExceeds(logPost, logAlpha) || slaBreached {
			break
		}

		batch := batches[bid]
		if len(batch) < 2 {
			continue
		}

		minDelay := batch[0].ActualDelay
		for _, p := range batch[1:] {
			if p.ActualDelay < minDelay {
				minDelay = p.ActualDelay
			}
		}

		queriesThisBatch := v.Config.QueriesPerBatch
		if queriesThisBatch <= 0 {
			queriesThisBatch = 1
		}
		if queriesThisBatch > len(batch) {
			queriesThisBatch = len(batch)
		}

		indices := make([]int, len(batch))
		for i := range indices {
			indices[i] = i
		}
		rand.Shuffle(len(indices), func(i, j int) {
			indices[i], indices[j] = indices[j], indices[i]
		})

		for qi := 0; qi < queriesThisBatch; qi++ {
			if maxLogExceeds(logPost, logAlpha) {
				break
			}
			p := batch[indices[qi]]
			q := Query{BatchID: p.BatchID, ObservedDelay: p.ActualDelay, SentTime: p.SentTime}
			ans := v.Prover.AnswerQuery(q)
			queries++

			contradiction := ans.IsMinimal && p.ActualDelay > minDelay
			flagInc := !ans.IsMinimal && !p.IsFlagged

			if contradiction {
				contradictions++
			}
			if flagInc {
				hiddenDelaysFound++
			}

			ll := lt.JointLogLikelihoods(contradiction, flagInc)
			for i := 0; i < 3; i++ {
				logPost[i] += ll[i]
			}

			if flagInc && v.Config.FlaggingRateThreshold > 0 {
				estimatedTrueRate := float64(hiddenDelaysFound+flaggedCount) / float64(totalPackets)
				if estimatedTrueRate > v.Config.ConfidenceThreshold {
					slaBreached = true
					break
				}
			}
		}
	}

	post := normaliseLogPosterior(logPost)
	verdict := "INCONCLUSIVE"
	trustworthy := post[0] >= post[1] && post[0] >= post[2]
	confidence := maxf(post[0], post[1], post[2])

	if slaBreached {
		return VerificationResult{
			Verdict:             "DISHONEST (SLA_BREACHED)",
			Confidence:          1.0,
			Trustworthy:         false,
			TotalQueries:        queries,
			ContradictionsFound: contradictions,
			PosteriorH0:         post[0],
			PosteriorH1:         post[1],
			PosteriorH2:         post[2],
		}
	}

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

func normaliseLogPosterior(logPost [3]float64) [3]float64 {
	m := logPost[0]
	if logPost[1] > m {
		m = logPost[1]
	}
	if logPost[2] > m {
		m = logPost[2]
	}
	sumExp := math.Exp(logPost[0]-m) + math.Exp(logPost[1]-m) + math.Exp(logPost[2]-m)
	logZ := m + math.Log(sumExp)
	return [3]float64{
		math.Exp(logPost[0] - logZ),
		math.Exp(logPost[1] - logZ),
		math.Exp(logPost[2] - logZ),
	}
}

func maxLogExceeds(logPost [3]float64, logAlpha float64) bool {
	post := normaliseLogPosterior(logPost)
	return maxf(post[0], post[1], post[2]) > math.Exp(logAlpha)
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

func (v *Verifier) groupByBatch() map[int][]TransmissionRecord {
	batches := make(map[int][]TransmissionRecord)
	for _, r := range v.Records {
		batches[r.BatchID] = append(batches[r.BatchID], r)
	}
	return batches
}
