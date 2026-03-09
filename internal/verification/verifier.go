package verification

import (
	"math"
	"math/rand"
	"sort"
)

type VerificationConfig struct {
	MaxQueries        int
	FlagRateThreshold float64
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		MaxQueries:        500,
		FlagRateThreshold: 0.30,
	}
}

type VerificationResult struct {
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	TotalQueries        int
	ContradictionsFound int
	FlaggingRate        float64
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
		return VerificationResult{Verdict: "INSUFFICIENT_DATA", Trustworthy: true}
	}

	// Count initially flagged packets for the overall flag rate denominator.
	initialFlaggedCount := 0
	for _, r := range v.Records {
		if r.IsFlagged {
			initialFlaggedCount++
		}
	}

	batches := v.groupByTime()
	contradictions := 0
	queries := 0
	// artificialFlagCount tracks unflagged-but-delayed packets caught via the flagging
	// inconsistency check. They inflate the flag rate to penalise incompetent provers.
	artificialFlagCount := 0

	times := make([]int, 0, len(batches))
	for bid := range batches {
		times = append(times, bid)
	}
	rand.Shuffle(len(times), func(i, j int) {
		times[i], times[j] = times[j], times[i]
	})

	for _, bid := range times {
		if queries >= v.Config.MaxQueries {
			break
		}

		batch := batches[bid]
		if len(batch) < 2 {
			continue
		}

		// Minimum observed delay in this batch (shared base delay means any spread is extra).
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

		// Main contradiction check: prover claims minimal, but another packet in the same
		// batch (same base delay) arrived sooner — logically impossible for an honest prover.
		if ans.IsMinimal && p.ActualDelay > minDelay {
			contradictions++
		}

		// Flagging inconsistency check (within-batch only — different batches have different
		// base delays so cross-batch absolute delay comparison is not meaningful):
		//
		// If the prover flagged some packet with delay d1 in this batch but did NOT flag
		// the queried packet p with delay d2 > d1:
		//   - IsMinimal=true  → contradiction: d1 was flagged as congested, yet the larger
		//                       delay d2 is claimed minimal — impossible.
		//   - IsMinimal=false → prover admits d2 was not minimal but never flagged it.
		//                       This is incompetence; we penalise by treating p as if it
		//                       should have been flagged (artificial flag).
		if !p.IsFlagged && minFlaggedInBatch < math.MaxFloat64 && p.ActualDelay > minFlaggedInBatch {
			if ans.IsMinimal {
				// Only count as a new contradiction if the main check did not already catch it.
				if !(p.ActualDelay > minDelay) {
					contradictions++
				}
			} else {
				artificialFlagCount++
			}
		}
	}

	// Flagging rate is measured over all delivered packets, not just queried ones.
	flaggingRate := 0.0
	if len(v.Records) > 0 {
		flaggingRate = float64(initialFlaggedCount+artificialFlagCount) / float64(len(v.Records))
	}

	verdict := "TRUSTED"
	trustworthy := true
	confidence := 1.0 - flaggingRate

	if contradictions > 0 {
		// A contradiction is a deductive proof of dishonesty — confidence is 1.0.
		verdict = "DISHONEST"
		trustworthy = false
		confidence = 1.0
	} else if flaggingRate > v.Config.FlagRateThreshold {
		verdict = "SUSPICIOUS_FLAG_RATE"
		trustworthy = false
		confidence = flaggingRate
	}

	return VerificationResult{
		Verdict:             verdict,
		Confidence:          confidence,
		Trustworthy:         trustworthy,
		TotalQueries:        queries,
		ContradictionsFound: contradictions,
		FlaggingRate:        flaggingRate,
	}
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
