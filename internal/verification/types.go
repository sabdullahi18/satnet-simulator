package verification

import "fmt"

type Query struct {
	ID   int
	Pkt1 int
	Pkt2 int
}

func (q Query) String() string {
	return fmt.Sprintf("Q%d: min_delay(%d) vs min_delay(%d)?", q.ID, q.Pkt1, q.Pkt2)
}

type Answer int

const (
	Pkt1Lower Answer = iota
	Pkt2Lower
)

func (a Answer) String() string {
	switch a {
	case Pkt1Lower:
		return "PKT1"
	case Pkt2Lower:
		return "PKT2"
	default:
		return "UNKNOWN"
	}
}

type PacketRecord struct {
	ID          int
	SentTime    float64
	MinDelay    float64
	ActualDelay float64
	WasDelayed  bool
	IsFlagged   bool
}

type TransmissionRecord = PacketRecord
