package verification

import (
	"crypto/sha256"
	"fmt"
)

type QueryType int

const (
	// which of two packets had better optimal delay
	QueryComparison QueryType = iota
	// rank k packets by optimal delay
	QueryOrdering
	// hash of the path used
	QueryPathHash
	// optimal delay was above/below threshold
	QueryDelayBound
	// congestion during interval
	QueryCongestionFlag
	// shortest path was used (legacy)
	QueryShortestPath
	// actual delay (legacy)
	QueryDelay
	// which path was used (legacy)
	QueryPathUsed
	// how many packets used a path (legacy)
	QueryPacketCount
)

func (q QueryType) String() string {
	switch q {
	case QueryComparison:
		return "COMPARISON"
	case QueryOrdering:
		return "ORDERING"
	case QueryPathHash:
		return "PATH_HASH"
	case QueryDelayBound:
		return "DELAY_BOUND"
	case QueryCongestionFlag:
		return "CONGESTION_FLAG"
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

func (ti TimeInterval) Overlaps(other TimeInterval) bool {
	return ti.Start <= other.End && other.Start <= ti.End
}

func (ti TimeInterval) Duration() float64 {
	return ti.End - ti.Start
}

type Query struct {
	ID       int
	Type     QueryType
	Interval TimeInterval

	PacketID  int
	PacketID2 int
	PacketIDs []int

	PathName string
	PathHash string

	DelayThreshold float64
}

func (q Query) String() string {
	switch q.Type {
	case QueryComparison:
		return fmt.Sprintf("Q%d: Compare optimal delay of packets %d vs %d in %s",
			q.ID, q.PacketID, q.PacketID2, q.Interval)
	case QueryOrdering:
		return fmt.Sprintf("Q%d: Rank packets %v by optimal delay in %s",
			q.ID, q.PacketIDs, q.Interval)
	case QueryPathHash:
		return fmt.Sprintf("Q%d: Path hash for packet %d in %s",
			q.ID, q.PacketID, q.Interval)
	case QueryDelayBound:
		return fmt.Sprintf("Q%d: Was optimal delay for packet %d above/below %.4fs?",
			q.ID, q.PacketID, q.DelayThreshold)
	case QueryCongestionFlag:
		return fmt.Sprintf("Q%d: Congestion on path %s during %s?",
			q.ID, q.PathHash, q.Interval)
	case QueryShortestPath:
		return fmt.Sprintf("Q%d: Did packet %d use shortest path in %s?",
			q.ID, q.PacketID, q.Interval)
	case QueryDelay:
		return fmt.Sprintf("Q%d: What was the delay for packet %d in %s?",
			q.ID, q.PacketID, q.Interval)
	case QueryPathUsed:
		return fmt.Sprintf("Q%d: Which path did packet %d use in %s?",
			q.ID, q.PacketID, q.Interval)
	case QueryPacketCount:
		return fmt.Sprintf("Q%d: How many packets used path '%s' in %s?",
			q.ID, q.PathName, q.Interval)
	default:
		return fmt.Sprintf("Q%d: Unknown query type", q.ID)
	}
}

type ComparisonResult int

const (
	Packet1Faster ComparisonResult = iota
	Packet2Faster
	PacketsEqual
)

func (c ComparisonResult) String() string {
	switch c {
	case Packet1Faster:
		return "PACKET_1_FASTER"
	case Packet2Faster:
		return "PACKET_2_FASTER"
	case PacketsEqual:
		return "EQUAL"
	default:
		return "UNKNOWN"
	}
}

type Response struct {
	QueryID    int
	Query      Query
	AnswerTime float64

	BoolAnswer       bool
	FloatAnswer      float64
	StringAnswer     string
	ComparisonAnswer ComparisonResult
	OrderingAnswer   []int
}

func (r Response) String() string {
	switch r.Query.Type {
	case QueryComparison:
		return fmt.Sprintf("R%d: %s", r.QueryID, r.ComparisonAnswer)
	case QueryOrdering:
		return fmt.Sprintf("R%d: %v", r.QueryID, r.OrderingAnswer)
	case QueryPathHash:
		return fmt.Sprintf("R%d: %s", r.QueryID, r.StringAnswer)
	case QueryDelayBound:
		if r.BoolAnswer {
			return fmt.Sprintf("R%d: ABOVE threshold", r.QueryID)
		}
		return fmt.Sprintf("R%d: BELOW threshold", r.QueryID)
	case QueryCongestionFlag:
		if r.BoolAnswer {
			return fmt.Sprintf("R%d: CONGESTION (level %.2f)", r.QueryID, r.FloatAnswer)
		}
		return fmt.Sprintf("R%d: NO CONGESTION", r.QueryID)
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

type TransmissionRecord struct {
	PacketID       int
	SentTime       float64
	ReceivedTime   float64
	PathUsed       string
	PathDelay      float64
	ActualDelay    float64
	MinDelay       float64
	MaliciousDelay float64
	IsShortestPath bool
	WasDelayed     bool
}

func (tr TransmissionRecord) String() string {
	delayed := ""
	if tr.WasDelayed {
		delayed = fmt.Sprintf(", MALICIOUS_DELAY=%.4f", tr.MaliciousDelay)
	}
	return fmt.Sprintf("Pkt%d: sent=%.2f, recv=%.2f, path=%s, min_delay=%.4f, actual=%.4f, shortest=%v%s",
		tr.PacketID, tr.SentTime, tr.ReceivedTime, tr.PathUsed, tr.MinDelay, tr.ActualDelay, tr.IsShortestPath, delayed)
}

type Commitment struct {
	Timestamp    float64
	Hash         string
	NetworkState string
	Nonce        string
}

func NewCommitment(timestamp float64, networkState string, nonce string) Commitment {
	data := fmt.Sprintf("%f|%s|%s", timestamp, networkState, nonce)
	h := sha256.Sum256([]byte(data))
	return Commitment{
		Timestamp:    timestamp,
		Hash:         fmt.Sprintf("%x", h[:16]),
		NetworkState: networkState,
		Nonce:        nonce,
	}
}

func HashPath(pathName string) string {
	h := sha256.Sum256([]byte(pathName))
	return fmt.Sprintf("%x", h[:8])
}
