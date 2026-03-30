package verification

import (
	"fmt"
)

// Query represents the verifier's question: "Was delay X minimal for packets sent at time t?"
type Query struct {
	BatchID       int
	ObservedDelay float64
	SentTime      float64
}

func (q Query) String() string {
	return fmt.Sprintf("Q(t=%.2f): is_minimal(delay=%.4f)?", q.SentTime, q.ObservedDelay)
}

// Answer is the prover's response. IsMinimal=true claims the packet experienced only
// base propagation delay — no congestion, no deliberate delay.
type Answer struct {
	IsMinimal bool
}

func (a Answer) String() string {
	if a.IsMinimal {
		return "MINIMAL"
	}
	return "NOT_MINIMAL"
}

type PacketRecord struct {
	ID                int
	BatchID           int
	SentTime          float64
	BaseDelay         float64
	IncompetenceDelay float64
	DeliberateDelay   float64
	ActualDelay       float64
	WasDelayed        bool // True if DeliberateDelay > 0 (deliberately targeted)
	HasIncompetence   bool // True if packet experienced incompetence delay
	IsFlagged         bool // Set by the prover pre-query to admit "honest errors"
}

func (pr PacketRecord) String() string {
	extra := ""
	if pr.IsFlagged {
		extra += fmt.Sprintf(", FLAGGED")
	}
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
