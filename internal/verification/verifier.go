package verification

import (
	"math/rand"
)

type VerificationConfig struct {
	MaxQueries             int
	SamplingSecret         string
	SamplingRate           float64
	TargetConfidence       float64
	ExpectedCongestionRate float64
	RateTolerancePO        float64
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		MaxQueries:             500,
		SamplingRate:           0.20,
		TargetConfidence:       0.95,
		ExpectedCongestionRate: 0.05,
		RateTolerancePO:        0.05,
	}
}

type VerificationResult struct {
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	TotalQueries        int
	ContradictionsFound int
	DefinitiveProofs    int
	FlagRate            float64
}

type Verifier struct {
	Oracle          *Oracle
	Records         []TransmissionRecord
	Config          VerificationConfig
	ProbHonest      float64
	ProbIncompetent float64
	ProbMalicious   float64
}

func NewVerifier(oracle *Oracle, config VerificationConfig) *Verifier {
	return &Verifier{
		Oracle:          oracle,
		Config:          config,
		ProbHonest:      0.33,
		ProbIncompetent: 0.33,
		ProbMalicious:   0.33,
	}
}

func (v *Verifier) IngestRecords(records []TransmissionRecord) {
	v.Records = records
}

func (v *Verifier) RunVerification(currentTime float64) VerificationResult {
	if len(v.Records) < 2 {
		return VerificationResult{Verdict: "INSUFFICIENT_DATA", Trustworthy: true}
	}

	contradictions := 0
	definitiveProofs := 0
	queries := 0
	indices := rand.Perm(len(v.Records))

	flaggedCount := 0
	for _, p := range v.Records {
		if p.IsFlagged {
			flaggedCount++
		}
	}
	flagRate := float64(flaggedCount) / float64(len(v.Records))

	suspiciousFlags := false
	if flagRate > (v.Config.ExpectedCongestionRate + v.Config.RateTolerancePO) {
		suspiciousFlags = true
		v.ProbHonest = 0.20
		v.ProbMalicious = 0.60
		v.ProbIncompetent = 0.20
	}

	for i := 0; i < len(indices)-1; i += 2 {
		if queries >= v.Config.MaxQueries {
			break
		}

		idx1, idx2 := indices[i], indices[i+1]
		p1 := v.Records[idx1]
		p2 := v.Records[idx2]

		if p1.ActualDelay == p2.ActualDelay {
			continue
		}

		q := Query{ID: queries, Pkt1: p1.ID, Pkt2: p2.ID}
		ans := v.Oracle.Answer(q)
		queries++

		evidence := v.analyseResponse(p1, p2, ans)
		v.updateBeliefs(evidence)

		if evidence == EvStrongContradiction {
			contradictions++
		}
		if evidence == EvDefinitiveProof {
			definitiveProofs++
		}

		if v.ProbMalicious > 0.999 && contradictions > 3 {
			break
		}
		if v.ProbHonest > 0.99 && queries > 50 {
			break
		}
	}

	verdict := "TRUSTED"
	trustworthy := true
	confidence := v.ProbHonest

	if suspiciousFlags && v.ProbHonest > 0.5 {
		verdict = "SUSPICIOUS_FLAG_RATE"
		trustworthy = false
		confidence = 0.90
	} else if definitiveProofs > 0 {
		verdict = "MALICIOUS_PROVEN"
		trustworthy = false
		confidence = 0.999
	} else if v.ProbMalicious > 0.90 {
		verdict = "MALICIOUS"
		trustworthy = false
		confidence = v.ProbMalicious
	} else if v.ProbIncompetent > 0.90 {
		verdict = "INCOMPETENT"
		trustworthy = false
		confidence = v.ProbIncompetent
	}

	return VerificationResult{
		Verdict:             verdict,
		Confidence:          confidence,
		Trustworthy:         trustworthy,
		TotalQueries:        queries,
		ContradictionsFound: contradictions,
		DefinitiveProofs:    definitiveProofs,
		FlagRate:            flagRate,
	}
}

type EvidenceType int

const (
	EvConsistent EvidenceType = iota
	EvWeakInconsistency
	EvStrongContradiction
	EvDefinitiveProof
)

func (v *Verifier) analyseResponse(p1, p2 TransmissionRecord, ans Answer) EvidenceType {
	d1 := p1.ActualDelay
	d2 := p2.ActualDelay

	obs1Lower := d1 < d2
	obs2Lower := d2 < d1

	if ans == Pkt1Lower {
		if obs1Lower {
			if !p2.IsFlagged {
				return EvWeakInconsistency
			}
			return EvConsistent
		} else if obs2Lower {
			if !p2.IsFlagged {
				return EvStrongContradiction
			}
			return EvConsistent
		}
	}

	if ans == Pkt2Lower {
		if obs2Lower {
			if !p1.IsFlagged {
				return EvWeakInconsistency
			}
			return EvConsistent
		} else if obs1Lower {
			if !p1.IsFlagged {
				return EvStrongContradiction
			}
			return EvConsistent
		}
	}

	return EvConsistent
}

func (v *Verifier) updateBeliefs(ev EvidenceType) {
	var lHonest, lIncompetent, lMalicious float64

	switch ev {
	case EvConsistent:
		lHonest = 0.80
		lIncompetent = 0.50
		lMalicious = 0.50

	case EvWeakInconsistency:
		lHonest = 0.10
		lIncompetent = 0.80
		lMalicious = 0.40

	case EvStrongContradiction:
		lHonest = 0.0001
		lIncompetent = 0.20
		lMalicious = 0.80

	case EvDefinitiveProof:
		lHonest = 0.00001
		lIncompetent = 0.05
		lMalicious = 0.95
	}

	pH := v.ProbHonest * lHonest
	pI := v.ProbIncompetent * lIncompetent
	pM := v.ProbMalicious * lMalicious

	total := pH + pI + pM
	if total > 0 {
		v.ProbHonest = pH / total
		v.ProbIncompetent = pI / total
		v.ProbMalicious = pM / total
	}
}
