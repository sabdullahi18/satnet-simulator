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
	ID                int
	SentTime          float64
	BaseDelay         float64
	IncompetenceDelay float64
	DeliberateDelay   float64
	ActualDelay       float64
	WasDelayed        bool // True if DeliberateDelay > 0
	HasIncompetence   bool // True if packet experienced incompetence delay
}

func (pr PacketRecord) String() string {
	extra := ""
	if pr.HasIncompetence {
		extra += fmt.Sprintf(", INCOMPETENCE=%.4f", pr.IncompetenceDelay)
	}
	if pr.WasDelayed {
		extra += fmt.Sprintf(", DELIBERATE=%.4f", pr.DeliberateDelay)
	}
	return fmt.Sprintf("Pkt%d: sent=%.2f, base=%.4f, actual=%.4f%s",
		pr.ID, pr.SentTime, pr.BaseDelay, pr.ActualDelay, extra)
}

type TransmissionRecord = PacketRecord
