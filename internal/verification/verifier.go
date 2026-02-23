package verification

import (
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
	Oracle  *Oracle
	Records []TransmissionRecord
	Config  VerificationConfig
}

func NewVerifier(oracle *Oracle, config VerificationConfig) *Verifier {
	return &Verifier{
		Oracle: oracle,
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

	batches := v.groupByTime()
	contradictions := 0
	queries := 0
	flaggedCount := 0

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

		minDelay := batch[0].ActualDelay
		for _, p := range batch[1:] {
			if p.ActualDelay < minDelay {
				minDelay = p.ActualDelay
			}
		}

		for _, p := range batch {
			if queries >= v.Config.MaxQueries {
				break
			}

			queryTime := float64(queries) * 0.001
			q := Query{PktID: p.ID, Time: queryTime}
			ans := v.Oracle.AnswerQuery(q)
			queries++

			// If oracle claims minimal but we observed a lower delay in the same batch,
			// that's a direct contradiction — absolute proof of dishonesty.
			if ans.IsMinimal && p.ActualDelay > minDelay {
				contradictions++
			}

			if ans.IsFlagged {
				flaggedCount++
			}
		}
	}

	flaggingRate := 0.0
	if queries > 0 {
		flaggingRate = float64(flaggedCount) / float64(queries)
	}

	verdict := "TRUSTED"
	trustworthy := true
	confidence := 1.0 - flaggingRate

	if contradictions > 0 {
		verdict = "MALICIOUS"
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
