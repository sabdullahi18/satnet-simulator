package verification

import (
	"fmt"
	"math/rand"
)

type VerificationConfig struct {
	MaxQueries             int
	SamplingSecret         string
	ExpectedCongestionRate float64
	RateTolerancePO        float64
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		MaxQueries:             500,
		ExpectedCongestionRate: 0.05,
		RateTolerancePO:        0.05,
	}
}

type Verifier struct {
	Oracle  *Oracle
	Records []TransmissionRecord
	Config  VerificationConfig

	ProbHonest      float64
	ProbIncompetent float64
	ProbMalicious   float64
}

type VerificationResult struct {
	Verdict             string
	Confidence          float64
	Trustworthy         bool
	TotalQueries        int
	ContradictionsFound int
	FlagRate            float64
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
		v.ProbMalicious = 0.6
		v.ProbIncompetent = 0.2
		fmt.Printf(">>> SUSPICIOUS ACTIVITY: flag rate %.1f%% exceeds expected %.1f%%\n", flagRate*100, v.Config.ExpectedCongestionRate*100)
	}

	fmt.Printf("\n--- Starting Verification (Max %d Queries) ---\n", v.Config.MaxQueries)
	fmt.Printf("    Initial Beliefs: Honest=%.2f, Incompetent=%.2f, Malicious=%.2f\n\n",
		v.ProbHonest, v.ProbIncompetent, v.ProbMalicious)

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

		status := "CONSISTENT"
		switch evidence {
		case EvStrongContradiction:
			status = "!!! CONTRADICTION !!!"
			contradictions++
		case EvWeakInconsistency:
			status = "! Inconsistent (Flag)"
		}

		fmt.Printf("Q%d: Pkt %d (Obs: %.2fs) vs Pkt %d (Obs: %.2fs)\n",
			q.ID, p1.ID, p1.ActualDelay, p2.ID, p2.ActualDelay)
		fmt.Printf("      Oracle Claims: %s was minimal.\n", ans)
		fmt.Printf("      Analysis:      %s\n", status)

		fmt.Printf("      [STATS]:       P(Honest)=%.4f  P(Incomp)=%.4f  P(Malicious)=%.4f\n",
			v.ProbHonest, v.ProbIncompetent, v.ProbMalicious)

		truthStr := ""
		if p1.WasDelayed {
			truthStr += fmt.Sprintf("Pkt %d MALICIOUSLY DELAYED. ", p1.ID)
		}
		if p2.WasDelayed {
			truthStr += fmt.Sprintf("Pkt %d MALICIOUSLY DELAYED. ", p2.ID)
		}
		if truthStr == "" {
			truthStr = "Clean traffic."
		}

		fmt.Printf("      [DEBUG TRUTH]: %s\n\n", truthStr)

		if v.ProbMalicious > 0.999 && contradictions > 5 {
			fmt.Println(">>> Early Stopping: Malicious intent confirmed with >99.9% confidence.")
			break
		}
		if v.ProbIncompetent > 0.999 {
			fmt.Println(">>> Early Stopping: High confidence of Incompetence.")
			break
		}
	}

	verdict := "TRUSTED"
	trustworthy := true
	confidence := v.ProbHonest

	if suspiciousFlags && v.ProbHonest > 0.5 {
		verdict = "MALICIOUS_FLOODING"
		trustworthy = false
		confidence = 0.95
		v.ProbMalicious = 0.95
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
	}
}

type EvidenceType int

const (
	EvConsistent EvidenceType = iota
	EvWeakInconsistency
	EvStrongContradiction
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
			return EvStrongContradiction
		}
	}

	if ans == Pkt2Lower {
		if obs2Lower {
			if !p1.IsFlagged {
				return EvWeakInconsistency
			}
			return EvConsistent
		} else if obs1Lower {
			return EvStrongContradiction
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
		lMalicious = 0.50 // Smart malicious acts consistent often
	case EvWeakInconsistency:
		lHonest = 0.10
		lIncompetent = 0.80
		lMalicious = 0.40
	case EvStrongContradiction:
		// A strong contradiction (physical impossibility) is damning
		lHonest = 0.0001
		lIncompetent = 0.20
		lMalicious = 0.80
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
