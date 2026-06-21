package verification

import (
	"math"
	"math/rand"
	"slices"

	"satnet-simulator/internal/network"
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
		ConfidenceThreshold:   0.99,
		FlaggingRateThreshold: 0.30,
		Epsilon:               1e-3,
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
	Packets []*network.Packet
	Config  VerificationConfig
}

func NewVerifier(prover *Prover, config VerificationConfig) *Verifier {
	return &Verifier{
		Prover: prover,
		Config: config,
	}
}

func (v *Verifier) IngestPackets(packets []*network.Packet) {
	v.Packets = packets
}

func (v *Verifier) countFlaggedPackets() int {
	count := 0
	for _, p := range v.Packets {
		if p.IsFlagged {
			count++
		}
	}
	return count
}

func (v *Verifier) getShuffledBatchIDs(batches map[int][]*network.Packet) []int {
	times := make([]int, 0, len(batches))
	for bid := range batches {
		times = append(times, bid)
	}
	// rand.Shuffle runs in O(N) and ensures an unbiased random sampling
	// of batches if the verification terminates early.
	rand.Shuffle(len(times), func(i, j int) {
		times[i], times[j] = times[j], times[i]
	})
	return times
}

func (v *Verifier) formatResult(logPost []float64, queries, contradictions int, slaBreached bool) VerificationResult {
	post := normaliseLogPosterior(logPost)

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

	verdict := "INCONCLUSIVE"
	trustworthy := post[0] >= post[1] && post[0] >= post[2]
	confidence := max(post[0], post[1], post[2])

	alpha := v.Config.ConfidenceThreshold
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

func (v *Verifier) RunVerification() VerificationResult {
	if len(v.Packets) < 2 {
		return VerificationResult{
			Verdict: "INSUFFICIENT_DATA", Trustworthy: true,
			PosteriorH0: 1.0 / 3, PosteriorH1: 1.0 / 3, PosteriorH2: 1.0 / 3,
		}
	}

	logPost := []float64{math.Log(1.0 / 3), math.Log(1.0 / 3), math.Log(1.0 / 3)}
	flaggedCount := v.countFlaggedPackets()
	totalPackets := len(v.Packets)

	if v.Config.FlaggingRateThreshold > 0 && float64(flaggedCount)/float64(totalPackets) > v.Config.FlaggingRateThreshold {
		return v.formatResult(logPost, 0, 0, true)
	}

	lt := newLikelihoodTable(v.Config.Epsilon, v.Config.ErrorTolerance)
	batches := v.groupByBatch()
	batchIDs := v.getShuffledBatchIDs(batches)

	logAlpha := math.Log(v.Config.ConfidenceThreshold)
	queries, contradictions, hiddenDelaysFound := 0, 0, 0
	slaBreached := false

	for _, bid := range batchIDs {
		if maxLogExceeds(logPost, logAlpha) || slaBreached {
			break
		}

		batch := batches[bid]
		if len(batch) < 2 {
			continue
		}

		minDelay := batch[0].TotalDelay
		for _, p := range batch[1:] {
			if p.TotalDelay < minDelay {
				minDelay = p.TotalDelay
			}
		}

		queriesThisBatch := max(1, min(v.Config.QueriesPerBatch, len(batch)))

		indices := make([]int, len(batch))
		for i := range indices {
			indices[i] = i
		}
		// O(N) shuffle ensures we randomly sample packets within the batch to query.
		rand.Shuffle(len(indices), func(i, j int) {
			indices[i], indices[j] = indices[j], indices[i]
		})

		for qi := range queriesThisBatch {
			if maxLogExceeds(logPost, logAlpha) {
				break
			}
			p := batch[indices[qi]]
			q := query{batchID: p.BatchID, observedDelay: p.TotalDelay, sentTime: p.SentTime}
			ans := v.Prover.AnswerQuery(q)
			queries++

			contradiction := ans.isMinimal && p.TotalDelay > minDelay
			flagInconsistent := !ans.isMinimal && !p.IsFlagged

			if contradiction {
				contradictions++
			}
			if flagInconsistent {
				hiddenDelaysFound++
			}

			ll := lt.jointLogLikelihoods(contradiction, flagInconsistent)
			for i := range 3 {
				logPost[i] += ll[i]
			}

			// The corrected flag rate accounts for both packets explicitly flagged by the
			// router and unflagged packets the verifier proved were delayed due to incompetence.
			if flagInconsistent && v.Config.FlaggingRateThreshold > 0 {
				correctedFlagRate := float64(hiddenDelaysFound+flaggedCount) / float64(totalPackets)
				if correctedFlagRate > v.Config.FlaggingRateThreshold {
					slaBreached = true
					break
				}
			}
		}
	}

	return v.formatResult(logPost, queries, contradictions, slaBreached)
}

// log-sum-exp trick to avoid numerical underflow
func normaliseLogPosterior(logPost []float64) [3]float64 {
	m := slices.Max(logPost)
	sumExp := math.Exp(logPost[0]-m) + math.Exp(logPost[1]-m) + math.Exp(logPost[2]-m)
	logZ := m + math.Log(sumExp)
	return [3]float64{
		math.Exp(logPost[0] - logZ),
		math.Exp(logPost[1] - logZ),
		math.Exp(logPost[2] - logZ),
	}
}

func maxLogExceeds(logPost []float64, logAlpha float64) bool {
	post := normaliseLogPosterior(logPost)
	return max(post[0], post[1], post[2]) > math.Exp(logAlpha)
}

func (v *Verifier) groupByBatch() map[int][]*network.Packet {
	batches := make(map[int][]*network.Packet)
	for _, p := range v.Packets {
		batches[p.BatchID] = append(batches[p.BatchID], p)
	}
	return batches
}