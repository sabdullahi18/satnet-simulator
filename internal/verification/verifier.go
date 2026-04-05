package verification

import (
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

	eta := v.Config.ErrorTolerance
	epsilon := v.Config.Epsilon

	batches := v.groupByBatch()

	totalPackets := len(v.Records)
	flaggedCount := 0
	for _, r := range v.Records {
		if r.IsFlagged {
			flaggedCount++
		}
	}

	pContraH0 := epsilon
	pContraH1 := eta
	pContraH2 := 1 - eta
	pCleanH0 := 1 - epsilon
	pCleanH1 := 1 - eta
	pCleanH2 := eta
	pFlagH0 := epsilon
	pFlagH1 := 1 - eta
	pFlagH2 := eta

	post := [3]float64{1.0 / 3, 1.0 / 3, 1.0 / 3}
	contradictions := 0
	queries := 0
	hiddenDelaysFound := 0

	if v.Config.FlaggingRateThreshold > 0 {
		flagRate := float64(flaggedCount) / float64(totalPackets)
		if flagRate > v.Config.FlaggingRateThreshold {
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
	slaBreached := false

	for _, bid := range times {
		if maxf(post[0], post[1], post[2]) > alpha || slaBreached {
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
			if maxf(post[0], post[1], post[2]) > alpha {
				break
			}
			p := batch[indices[qi]]
			q := Query{BatchID: p.BatchID, ObservedDelay: p.ActualDelay, SentTime: p.SentTime}
			ans := v.Prover.AnswerQuery(q)
			queries++

			if ans.IsMinimal && p.ActualDelay > minDelay {
				contradictions++
				post = bayesUpdate(post, pContraH0, pContraH1, pContraH2)
			} else if !p.IsFlagged && !ans.IsMinimal {
				hiddenDelaysFound++
				post = bayesUpdate(post, pFlagH0, pFlagH1, pFlagH2)
				if v.Config.FlaggingRateThreshold > 0 {
					estimatedTrueRate := float64(hiddenDelaysFound+flaggedCount) / float64(totalPackets)
					if estimatedTrueRate > v.Config.FlaggingRateThreshold {
						slaBreached = true
						break
					}
				}

			} else if p.IsFlagged && !ans.IsMinimal {
				post = bayesUpdate(post, 1-pFlagH0, 1-pFlagH1, 1-pFlagH2)
			} else {
				post = bayesUpdate(post, pCleanH0, pCleanH1, pCleanH2)
			}
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

func (v *Verifier) groupByBatch() map[int][]TransmissionRecord {
	batches := make(map[int][]TransmissionRecord)
	for _, r := range v.Records {
		batches[r.BatchID] = append(batches[r.BatchID], r)
	}
	return batches
}
