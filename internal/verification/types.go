package verification

import "fmt"

type Query struct {
	PktID int
	Time  float64
}

func (q Query) String() string {
	return fmt.Sprintf("Q(t=%.2f): is_minimal(%d)?", q.Time, q.PktID)
}

type Answer int

const (
	AnswerMinimal Answer = iota
	AnswerFlagged
)

func (a Answer) String() string {
	switch a {
	case AnswerMinimal:
		return "MINIMAL"
	case AnswerFlagged:
		return "FLAGGED"
	default:
		return "UNKNOWN"
	}
}

type PacketRecord struct {
	ID             int
	SentTime       float64
	BaseDelay      float64
	LegitDelay     float64
	MaliciousDelay float64
	ActualDelay    float64
	// MinDelay - This concept is now covered by BaseDelay, since MinPossible = BaseDelay
	MinDelay   float64
	WasDelayed bool // True if MaliciousDelay > 0
	IsFlagged  bool // This was for old logic; now we use the Oracle's answer for this.
	// But we might want to store the "Answer" we got for this packet if we queried it.
}

func (pr PacketRecord) String() string {
	delayed := ""
	if pr.WasDelayed {
		delayed = fmt.Sprintf(", MALICIOUS=%.4f", pr.MaliciousDelay)
	}
	return fmt.Sprintf("Pkt%d: sent=%.2f, base=%.4f, legit=%.4f, actual=%.4f%s",
		pr.ID, pr.SentTime, pr.BaseDelay, pr.LegitDelay, pr.ActualDelay, delayed)
}

type TransmissionRecord = PacketRecord

type DistributionConfig struct {
	Name   string
	Params map[string]float64
}

type AdversaryDistributions struct {
	LegitCongestion DistributionConfig // Expected LogNormal
	MaliciousDelay  DistributionConfig // Expected Uniform (or assumed)
	BaseNoise       DistributionConfig // Expected Exponential for "Minimal"
}
