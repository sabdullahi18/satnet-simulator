package verification

import (
	"fmt"
	"math/rand"
)

// LyingStrategy defines how the oracle lies
type LyingStrategy int

const (
	// StrategyHonest always tells the truth
	StrategyHonest LyingStrategy = iota
	// StrategyAlwaysClaimShortest always claims it used the shortest path
	StrategyAlwaysClaimShortest
	// StrategyRandomLies randomly lies with a certain probability
	StrategyRandomLies
	// StrategyMinimizeDelay lies about delays to appear faster
	StrategyMinimizeDelay
	// StrategySmart tries to maintain consistency but still lies
	StrategySmart
)

func (s LyingStrategy) String() string {
	switch s {
	case StrategyHonest:
		return "HONEST"
	case StrategyAlwaysClaimShortest:
		return "ALWAYS_CLAIM_SHORTEST"
	case StrategyRandomLies:
		return "RANDOM_LIES"
	case StrategyMinimizeDelay:
		return "MINIMIZE_DELAY"
	case StrategySmart:
		return "SMART"
	default:
		return "UNKNOWN"
	}
}

// NetworkOracle represents the network's interface for answering queries
// It has access to the ground truth but may choose to lie
type NetworkOracle struct {
	Strategy        LyingStrategy
	LieProbability  float64 // For StrategyRandomLies
	GroundTruth     []TransmissionRecord
	ShortestPath    string  // Name of the shortest path
	ShortestDelay   float64 // Delay of the shortest path

	// For smart lying - track what we've claimed before
	claimedPaths   map[int]string  // packetID -> claimed path
	claimedDelays  map[int]float64 // packetID -> claimed delay
	claimedShortest map[int]bool   // packetID -> claimed shortest

	// Statistics
	QueriesAnswered int
	LiesTold        int
}

// NewNetworkOracle creates a new oracle with the given strategy
func NewNetworkOracle(strategy LyingStrategy, lieProbability float64, shortestPath string, shortestDelay float64) *NetworkOracle {
	return &NetworkOracle{
		Strategy:        strategy,
		LieProbability:  lieProbability,
		ShortestPath:    shortestPath,
		ShortestDelay:   shortestDelay,
		GroundTruth:     make([]TransmissionRecord, 0),
		claimedPaths:    make(map[int]string),
		claimedDelays:   make(map[int]float64),
		claimedShortest: make(map[int]bool),
	}
}

// RecordTransmission records the ground truth of a packet transmission
func (o *NetworkOracle) RecordTransmission(record TransmissionRecord) {
	o.GroundTruth = append(o.GroundTruth, record)
}

// FindRecord finds the transmission record for a packet in a given interval
func (o *NetworkOracle) FindRecord(packetID int, interval TimeInterval) *TransmissionRecord {
	for i := range o.GroundTruth {
		rec := &o.GroundTruth[i]
		if rec.PacketID == packetID && interval.Contains(rec.SentTime) {
			return rec
		}
	}
	return nil
}

// Answer responds to a query, potentially lying based on the strategy
func (o *NetworkOracle) Answer(q Query, simTime float64) Response {
	o.QueriesAnswered++

	resp := Response{
		QueryID:    q.ID,
		Query:      q,
		AnswerTime: simTime,
	}

	switch q.Type {
	case QueryShortestPath:
		resp.BoolAnswer = o.answerShortestPath(q)
	case QueryDelay:
		resp.FloatAnswer = o.answerDelay(q)
	case QueryPathUsed:
		resp.StringAnswer = o.answerPathUsed(q)
	case QueryPacketCount:
		resp.FloatAnswer = o.answerPacketCount(q)
	}

	return resp
}

func (o *NetworkOracle) answerShortestPath(q Query) bool {
	record := o.FindRecord(q.PacketID, q.Interval)
	if record == nil {
		return false // No such packet
	}

	truth := record.IsShortestPath

	switch o.Strategy {
	case StrategyHonest:
		return truth

	case StrategyAlwaysClaimShortest:
		if !truth {
			o.LiesTold++
		}
		o.claimedShortest[q.PacketID] = true
		return true

	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
			o.LiesTold++
			o.claimedShortest[q.PacketID] = !truth
			return !truth
		}
		o.claimedShortest[q.PacketID] = truth
		return truth

	case StrategyMinimizeDelay:
		// Claim shortest path to appear efficient
		if !truth {
			o.LiesTold++
		}
		o.claimedShortest[q.PacketID] = true
		return true

	case StrategySmart:
		// Check if we've already made a claim about this packet's path
		if claimedPath, exists := o.claimedPaths[q.PacketID]; exists {
			// Stay consistent with previous path claim
			return claimedPath == o.ShortestPath
		}
		// Otherwise, randomly decide but remember our choice
		lie := rand.Float64() < o.LieProbability
		if lie {
			o.LiesTold++
			o.claimedShortest[q.PacketID] = !truth
			return !truth
		}
		o.claimedShortest[q.PacketID] = truth
		return truth
	}

	return truth
}

func (o *NetworkOracle) answerDelay(q Query) float64 {
	record := o.FindRecord(q.PacketID, q.Interval)
	if record == nil {
		return -1 // No such packet
	}

	truth := record.ActualDelay

	switch o.Strategy {
	case StrategyHonest:
		return truth

	case StrategyAlwaysClaimShortest:
		// If we claim shortest path, we might need to lie about delay too
		if !record.IsShortestPath {
			// Lie: report a delay consistent with shortest path
			liedDelay := o.ShortestDelay + rand.Float64()*1.5 // base + jitter
			if liedDelay != truth {
				o.LiesTold++
			}
			o.claimedDelays[q.PacketID] = liedDelay
			return liedDelay
		}
		o.claimedDelays[q.PacketID] = truth
		return truth

	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
			// Lie: add or subtract random amount
			liedDelay := truth + (rand.Float64()-0.5)*2.0
			if liedDelay < 0.1 {
				liedDelay = 0.1 // Don't go below minimum possible
			}
			o.LiesTold++
			o.claimedDelays[q.PacketID] = liedDelay
			return liedDelay
		}
		o.claimedDelays[q.PacketID] = truth
		return truth

	case StrategyMinimizeDelay:
		// Claim a smaller delay
		liedDelay := truth * 0.5 // Cut delay in half
		if liedDelay < o.ShortestDelay {
			liedDelay = o.ShortestDelay // But not less than physically possible
		}
		if liedDelay != truth {
			o.LiesTold++
		}
		o.claimedDelays[q.PacketID] = liedDelay
		return liedDelay

	case StrategySmart:
		// Check if we've already claimed a path for this packet
		if claimedPath, exists := o.claimedPaths[q.PacketID]; exists {
			// Return a delay consistent with the claimed path
			if claimedPath == o.ShortestPath && !record.IsShortestPath {
				// We claimed shortest but used longer - need to fake a consistent delay
				liedDelay := o.ShortestDelay + rand.Float64()*1.5
				o.LiesTold++
				o.claimedDelays[q.PacketID] = liedDelay
				return liedDelay
			}
		}
		// Return truth
		o.claimedDelays[q.PacketID] = truth
		return truth
	}

	return truth
}

func (o *NetworkOracle) answerPathUsed(q Query) string {
	record := o.FindRecord(q.PacketID, q.Interval)
	if record == nil {
		return "UNKNOWN"
	}

	truth := record.PathUsed

	switch o.Strategy {
	case StrategyHonest:
		return truth

	case StrategyAlwaysClaimShortest:
		if truth != o.ShortestPath {
			o.LiesTold++
		}
		o.claimedPaths[q.PacketID] = o.ShortestPath
		return o.ShortestPath

	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
			// Lie: claim the other path
			liedPath := o.ShortestPath
			if truth == o.ShortestPath {
				liedPath = "OTHER_PATH" // This is a simplification
			}
			o.LiesTold++
			o.claimedPaths[q.PacketID] = liedPath
			return liedPath
		}
		o.claimedPaths[q.PacketID] = truth
		return truth

	case StrategyMinimizeDelay:
		if truth != o.ShortestPath {
			o.LiesTold++
		}
		o.claimedPaths[q.PacketID] = o.ShortestPath
		return o.ShortestPath

	case StrategySmart:
		// Check consistency with previous claims about shortest path
		if claimedShortest, exists := o.claimedShortest[q.PacketID]; exists {
			if claimedShortest {
				o.claimedPaths[q.PacketID] = o.ShortestPath
				if truth != o.ShortestPath {
					o.LiesTold++
				}
				return o.ShortestPath
			}
		}
		o.claimedPaths[q.PacketID] = truth
		return truth
	}

	return truth
}

func (o *NetworkOracle) answerPacketCount(q Query) float64 {
	// Count packets that used the specified path in the interval
	count := 0
	for _, rec := range o.GroundTruth {
		if rec.PathUsed == q.PathName && q.Interval.Contains(rec.SentTime) {
			count++
		}
	}

	truth := float64(count)

	switch o.Strategy {
	case StrategyHonest:
		return truth

	case StrategyAlwaysClaimShortest:
		if q.PathName == o.ShortestPath {
			// Claim all packets used shortest path
			total := 0
			for _, rec := range o.GroundTruth {
				if q.Interval.Contains(rec.SentTime) {
					total++
				}
			}
			if float64(total) != truth {
				o.LiesTold++
			}
			return float64(total)
		}
		// Claim no packets used non-shortest path
		if truth > 0 {
			o.LiesTold++
		}
		return 0

	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
			// Lie: add or subtract random amount
			liedCount := truth + float64(rand.Intn(5)-2)
			if liedCount < 0 {
				liedCount = 0
			}
			if liedCount != truth {
				o.LiesTold++
			}
			return liedCount
		}
		return truth

	case StrategyMinimizeDelay, StrategySmart:
		// For count queries, these strategies behave like honest
		return truth
	}

	return truth
}

// GetStats returns statistics about the oracle's behavior
func (o *NetworkOracle) GetStats() string {
	lieRate := 0.0
	if o.QueriesAnswered > 0 {
		lieRate = float64(o.LiesTold) / float64(o.QueriesAnswered) * 100
	}
	return fmt.Sprintf("Strategy: %s, Queries: %d, Lies: %d (%.1f%%)",
		o.Strategy, o.QueriesAnswered, o.LiesTold, lieRate)
}
