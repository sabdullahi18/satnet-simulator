package verification

import "fmt"

type QueryType int

const (
	// QueryShortestPath asks if the network used the shortest path for a packet
	QueryShortestPath QueryType = iota
	// QueryDelay asks what the delay was for a packet
	QueryDelay
	// QueryPathUsed asks which specific path was used
	QueryPathUsed
	// QueryPacketCount asks how many packets used a specific path in an interval
	QueryPacketCount
)

func (q QueryType) String() string {
	switch q {
	case QueryShortestPath:
		return "SHORTEST_PATH"
	case QueryDelay:
		return "DELAY"
	case QueryPathUsed:
		return "PATH_USED"
	case QueryPacketCount:
		return "PACKET_COUNT"
	default:
		return "UNKNOWN"
	}
}

type TimeInterval struct {
	Start float64
	End   float64
}

func (ti TimeInterval) String() string {
	return fmt.Sprintf("[%.2f, %.2f]", ti.Start, ti.End)
}

func (ti TimeInterval) Contains(t float64) bool {
	return t >= ti.Start && t <= ti.End
}

type Query struct {
	ID       int
	Type     QueryType
	Interval TimeInterval
	PacketID int    // For packet-specific queries
	PathName string // For path-specific queries (e.g., QueryPacketCount)
}

func (q Query) String() string {
	if q.ID == -1 {
		return fmt.Sprintf("Hash commitment for packet %d at routing time", q.PacketID)
	}

	switch q.Type {
	case QueryShortestPath:
		return fmt.Sprintf("Q%d: Did packet %d use shortest path in %s?", q.ID, q.PacketID, q.Interval)
	case QueryDelay:
		return fmt.Sprintf("Q%d: What was the delay for packet %d in %s?", q.ID, q.PacketID, q.Interval)
	case QueryPathUsed:
		return fmt.Sprintf("Q%d: Which path did packet %d use in %s?", q.ID, q.PacketID, q.Interval)
	case QueryPacketCount:
		return fmt.Sprintf("Q%d: How many packets used path '%s' in %s?", q.ID, q.PathName, q.Interval)
	default:
		return fmt.Sprintf("Q%d: Unknown query type", q.ID)
	}
}

type Response struct {
	QueryID      int
	Query        Query
	BoolAnswer   bool
	FloatAnswer  float64
	StringAnswer string
	AnswerTime   float64
}

func (r Response) String() string {
	if r.QueryID == -1 {
		return r.StringAnswer
	}

	switch r.Query.Type {
	case QueryShortestPath:
		return fmt.Sprintf("R%d: %v", r.QueryID, r.BoolAnswer)
	case QueryDelay:
		return fmt.Sprintf("R%d: %.4fs", r.QueryID, r.FloatAnswer)
	case QueryPathUsed:
		return fmt.Sprintf("R%d: %s", r.QueryID, r.StringAnswer)
	case QueryPacketCount:
		return fmt.Sprintf("R%d: %d packets", r.QueryID, int(r.FloatAnswer))
	default:
		return fmt.Sprintf("R%d: unknown", r.QueryID)
	}
}

// TransmissionRecord is the ground truth of what actually happened
type TransmissionRecord struct {
	PacketID       int
	SentTime       float64
	ReceivedTime   float64
	PathUsed       string
	PathDelay      float64
	ActualDelay    float64
	IsShortestPath bool
}

func (tr TransmissionRecord) String() string {
	return fmt.Sprintf("Pkt%d: sent=%.2f, recv=%.2f, path=%s, delay=%.4f, shortest=%v",
		tr.PacketID, tr.SentTime, tr.ReceivedTime, tr.PathUsed, tr.ActualDelay, tr.IsShortestPath)
}
