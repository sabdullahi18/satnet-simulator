package verification

import "fmt"

type Query struct {
	PktID int
	Time  float64
}

func (q Query) String() string {
	return fmt.Sprintf("Q(t=%.2f): is_minimal(%d)?", q.Time, q.PktID)
}

type Answer struct {
	IsMinimal bool
	IsFlagged bool
}

func (a Answer) String() string {
	if a.IsMinimal {
		return "MINIMAL"
	}
	if a.IsFlagged {
		return "FLAGGED"
	}
	return "NOT_MINIMAL"
}

type PacketRecord struct {
	ID             int
	SentTime       float64
	BaseDelay      float64
	LegitDelay     float64
	MaliciousDelay float64
	ActualDelay    float64
	MinDelay       float64
	WasDelayed     bool // True if MaliciousDelay > 0
	HasCongestion  bool // True if packet experienced legitimate congestion
}

func (pr PacketRecord) String() string {
	extra := ""
	if pr.HasCongestion {
		extra += fmt.Sprintf(", CONGESTION=%.4f", pr.LegitDelay)
	}
	if pr.WasDelayed {
		extra += fmt.Sprintf(", MALICIOUS=%.4f", pr.MaliciousDelay)
	}
	return fmt.Sprintf("Pkt%d: sent=%.2f, base=%.4f, actual=%.4f%s",
		pr.ID, pr.SentTime, pr.BaseDelay, pr.ActualDelay, extra)
}

type TransmissionRecord = PacketRecord
