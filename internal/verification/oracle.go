package verification

import (
	"fmt"
	"math/rand"
)

type LyingStrategy int

const (
	// StrategyHonest always tells the truth
	StrategyHonest LyingStrategy = iota
	// StrategyAlwaysClaimShortest always claims it used the shortest path
	StrategyAlwaysClaimShortest
	// StrategyRandomLies randomly lies with a certain probability
	StrategyRandomLies
	// StrategyMinimiseDelay lies about delays to appear faster
	StrategyMinimiseDelay
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
	case StrategyMinimiseDelay:
		return "MINIMISE_DELAY"
	case StrategySmart:
		return "SMART"
	default:
		return "UNKNOWN"
	}
}

// It has access to the ground truth but may choose to lie
type NetworkOracle struct {
	Strategy       LyingStrategy
	LieProbability float64
	GroundTruth    []TransmissionRecord
	ShortestPath   string
	ShortestDelay  float64

	claimedPaths    map[int]string  // packetID -> claimed path
	claimedDelays   map[int]float64 // packetID -> claimed delay
	claimedShortest map[int]bool    // packetID -> claimed shortest

	QueriesAnswered int
	LiesTold        int
}

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

func (o *NetworkOracle) RecordTransmission(record TransmissionRecord) {
	o.GroundTruth = append(o.GroundTruth, record)
}

func (o *NetworkOracle) FindRecord(packetID int, interval TimeInterval) *TransmissionRecord {
	for i := range o.GroundTruth {
		rec := &o.GroundTruth[i]
		if rec.PacketID == packetID && interval.Contains(rec.SentTime) {
			return rec
		}
	}
	return nil
}

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
		return false
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

	case StrategyMinimiseDelay:
		if !truth {
			o.LiesTold++
		}
		o.claimedShortest[q.PacketID] = true
		return true

	case StrategySmart:
		if claimedPath, exists := o.claimedPaths[q.PacketID]; exists {
			// Stay consistent with previous path claim
			return claimedPath == o.ShortestPath
		}
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
		return -1
	}

	truth := record.ActualDelay

	switch o.Strategy {
	case StrategyHonest:
		return truth

	case StrategyAlwaysClaimShortest:
		if !record.IsShortestPath {
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
			liedDelay := truth + (rand.Float64()-0.5)*2.0
			if liedDelay < 0.1 {
				liedDelay = 0.1
			}
			o.LiesTold++
			o.claimedDelays[q.PacketID] = liedDelay
			return liedDelay
		}
		o.claimedDelays[q.PacketID] = truth
		return truth

	case StrategyMinimiseDelay:
		liedDelay := truth * 0.5
		if liedDelay < o.ShortestDelay {
			liedDelay = o.ShortestDelay
		}
		if liedDelay != truth {
			o.LiesTold++
		}
		o.claimedDelays[q.PacketID] = liedDelay
		return liedDelay

	case StrategySmart:
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
			liedPath := o.ShortestPath
			if truth == o.ShortestPath {
				liedPath = "OTHER_PATH"
			}
			o.LiesTold++
			o.claimedPaths[q.PacketID] = liedPath
			return liedPath
		}
		o.claimedPaths[q.PacketID] = truth
		return truth

	case StrategyMinimiseDelay:
		if truth != o.ShortestPath {
			o.LiesTold++
		}
		o.claimedPaths[q.PacketID] = o.ShortestPath
		return o.ShortestPath

	case StrategySmart:
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
		if truth > 0 {
			o.LiesTold++
		}
		return 0

	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
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

	case StrategyMinimiseDelay, StrategySmart:
		return truth
	}

	return truth
}

func (o *NetworkOracle) GetStats() string {
	lieRate := 0.0
	if o.QueriesAnswered > 0 {
		lieRate = float64(o.LiesTold) / float64(o.QueriesAnswered) * 100
	}
	return fmt.Sprintf("Strategy: %s, Queries: %d, Lies: %d (%.1f%%)",
		o.Strategy, o.QueriesAnswered, o.LiesTold, lieRate)
}
