package verification

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
)

type LyingStrategy int

const (
	// always tells the truth
	StrategyHonest LyingStrategy = iota
	// always claims shortest path
	StrategyAlwaysClaimShortest
	// randomly lies with probability
	StrategyRandomLies
	// lies to minimise apparent delay
	StrategyMinimiseDelay
	// maintains consistent lies
	StrategySophisticated
	// lies about specific packets
	StrategyTargeted
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
	case StrategySophisticated:
		return "SOPHISTICATED"
	case StrategyTargeted:
		return "TARGETED"
	default:
		return "UNKNOWN"
	}
}

// It has access to ground truth but may choose to lie
type NetworkOracle struct {
	Strategy       LyingStrategy
	LieProbability float64
	GroundTruth    []TransmissionRecord
	ShortestPath   string
	ShortestDelay  float64

	claimedPaths      map[int]string
	claimedDelays     map[int]float64
	claimedShortest   map[int]bool
	claimedMinDelays  map[int]float64
	comparisonHistory map[string]ComparisonResult

	QueriesAnswered int
	LiesTold        int
	Commitments     []Commitment
}

func NewNetworkOracle(strategy LyingStrategy, lieProbability float64, shortestPath string, shortestDelay float64) *NetworkOracle {
	return &NetworkOracle{
		Strategy:          strategy,
		LieProbability:    lieProbability,
		ShortestPath:      shortestPath,
		ShortestDelay:     shortestDelay,
		GroundTruth:       make([]TransmissionRecord, 0),
		claimedPaths:      make(map[int]string),
		claimedDelays:     make(map[int]float64),
		claimedShortest:   make(map[int]bool),
		claimedMinDelays:  make(map[int]float64),
		comparisonHistory: make(map[string]ComparisonResult),
		Commitments:       make([]Commitment, 0),
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

func (o *NetworkOracle) FindRecordByID(packetID int) *TransmissionRecord {
	for i := range o.GroundTruth {
		if o.GroundTruth[i].PacketID == packetID {
			return &o.GroundTruth[i]
		}
	}
	return nil
}

func (o *NetworkOracle) AddCommitment(timestamp float64, state string) {
	nonce := fmt.Sprintf("%d", rand.Int63())
	c := NewCommitment(timestamp, state, nonce)
	o.Commitments = append(o.Commitments, c)
}

func (o *NetworkOracle) Answer(q Query, simTime float64) Response {
	o.QueriesAnswered++

	resp := Response{
		QueryID:    q.ID,
		Query:      q,
		AnswerTime: simTime,
	}

	switch q.Type {
	case QueryComparison:
		resp.ComparisonAnswer = o.answerComparison(q)
	case QueryOrdering:
		resp.OrderingAnswer = o.answerOrdering(q)
	case QueryPathHash:
		resp.StringAnswer = o.answerPathHash(q)
	case QueryDelayBound:
		resp.BoolAnswer = o.answerDelayBound(q)
	case QueryCongestionFlag:
		resp.BoolAnswer, resp.FloatAnswer = o.answerCongestionFlag(q)
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

func (o *NetworkOracle) answerComparison(q Query) ComparisonResult {
	rec1 := o.FindRecordByID(q.PacketID)
	rec2 := o.FindRecordByID(q.PacketID2)

	if rec1 == nil || rec2 == nil {
		return PacketsEqual
	}

	key := fmt.Sprintf("%d-%d", q.PacketID, q.PacketID2)
	reverseKey := fmt.Sprintf("%d-%d", q.PacketID2, q.PacketID)

	if prev, exists := o.comparisonHistory[key]; exists {
		return prev
	}
	if prev, exists := o.comparisonHistory[reverseKey]; exists {
		switch prev {
		case Packet1Faster:
			return Packet2Faster
		case Packet2Faster:
			return Packet1Faster
		default:
			return PacketsEqual
		}
	}

	truth := PacketsEqual
	if rec1.MinDelay < rec2.MinDelay-0.001 {
		truth = Packet1Faster
	} else if rec2.MinDelay < rec1.MinDelay-0.001 {
		truth = Packet2Faster
	}

	var answer ComparisonResult

	switch o.Strategy {
	case StrategyHonest:
		answer = truth

	case StrategySophisticated:
		answer = o.sophisticatedComparisonAnswer(q, rec1, rec2, truth)

	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
			o.LiesTold++
			options := []ComparisonResult{Packet1Faster, Packet2Faster, PacketsEqual}
			answer = options[rand.Intn(len(options))]
			if answer == truth {
				answer = options[(int(truth)+1)%3]
			}
		} else {
			answer = truth
		}

	case StrategyMinimiseDelay, StrategyAlwaysClaimShortest:
		// Claim the packet with lower observed delay had better min delay
		// This hides malicious delays by attributing them to "worse paths"
		if rec1.ActualDelay < rec2.ActualDelay {
			answer = Packet1Faster
		} else if rec2.ActualDelay < rec1.ActualDelay {
			answer = Packet2Faster
		} else {
			answer = PacketsEqual
		}
		if answer != truth {
			o.LiesTold++
		}

	case StrategyTargeted:
		if rec1.WasDelayed || rec2.WasDelayed {
			if rec1.WasDelayed && !rec2.WasDelayed {
				answer = Packet2Faster
			} else if rec2.WasDelayed && !rec1.WasDelayed {
				answer = Packet1Faster
			} else {
				answer = truth
			}
			if answer != truth {
				o.LiesTold++
			}
		} else {
			answer = truth
		}

	default:
		answer = truth
	}

	o.comparisonHistory[key] = answer
	return answer
}

func (o *NetworkOracle) sophisticatedComparisonAnswer(q Query, rec1, rec2 *TransmissionRecord, truth ComparisonResult) ComparisonResult {
	claimed1, has1 := o.claimedMinDelays[q.PacketID]
	claimed2, has2 := o.claimedMinDelays[q.PacketID2]

	if has1 && has2 {
		if claimed1 < claimed2-0.001 {
			return Packet1Faster
		} else if claimed2 < claimed1-0.001 {
			return Packet2Faster
		}
		return PacketsEqual
	}

	shouldLie := rand.Float64() < o.LieProbability
	if shouldLie && (rec1.WasDelayed || rec2.WasDelayed) {
		o.LiesTold++

		// Create plausible lie: attribute high delay to "bad path"
		// The packet with higher observed delay "had worse min delay"
		if rec1.ActualDelay > rec2.ActualDelay {
			if !has1 {
				o.claimedMinDelays[q.PacketID] = rec1.ActualDelay * 0.8
			}
			if !has2 {
				o.claimedMinDelays[q.PacketID2] = rec2.MinDelay
			}
			return Packet2Faster
		} else if rec2.ActualDelay > rec1.ActualDelay {
			if !has1 {
				o.claimedMinDelays[q.PacketID] = rec1.MinDelay
			}
			if !has2 {
				o.claimedMinDelays[q.PacketID2] = rec2.ActualDelay * 0.8
			}
			return Packet1Faster
		}
	}

	if !has1 {
		o.claimedMinDelays[q.PacketID] = rec1.MinDelay
	}
	if !has2 {
		o.claimedMinDelays[q.PacketID2] = rec2.MinDelay
	}
	return truth
}

func (o *NetworkOracle) answerOrdering(q Query) []int {
	type packetDelay struct {
		id       int
		minDelay float64
		claimed  float64
	}

	packets := make([]packetDelay, 0, len(q.PacketIDs))
	for _, pid := range q.PacketIDs {
		rec := o.FindRecordByID(pid)
		if rec == nil {
			continue
		}

		pd := packetDelay{id: pid, minDelay: rec.MinDelay}

		switch o.Strategy {
		case StrategyHonest:
			pd.claimed = rec.MinDelay

		case StrategySophisticated:
			if claimed, exists := o.claimedMinDelays[pid]; exists {
				pd.claimed = claimed
			} else if rec.WasDelayed && rand.Float64() < o.LieProbability {
				pd.claimed = rec.ActualDelay * 0.8
				o.claimedMinDelays[pid] = pd.claimed
				o.LiesTold++
			} else {
				pd.claimed = rec.MinDelay
				o.claimedMinDelays[pid] = pd.claimed
			}

		case StrategyMinimiseDelay, StrategyTargeted:
			pd.claimed = rec.ActualDelay * 0.9
			if math.Abs(pd.claimed-rec.MinDelay) > 0.001 {
				o.LiesTold++
			}

		default:
			pd.claimed = rec.MinDelay
		}

		packets = append(packets, pd)
	}

	sort.Slice(packets, func(i, j int) bool {
		return packets[i].claimed < packets[j].claimed
	})

	result := make([]int, len(packets))
	for i, p := range packets {
		result[i] = p.id
	}
	return result
}

func (o *NetworkOracle) answerPathHash(q Query) string {
	rec := o.FindRecord(q.PacketID, q.Interval)
	if rec == nil {
		return "UNKNOWN"
	}

	truth := HashPath(rec.PathUsed)

	switch o.Strategy {
	case StrategyHonest:
		return truth

	case StrategySophisticated:
		if claimed, exists := o.claimedPaths[q.PacketID]; exists {
			return HashPath(claimed)
		}
		return truth

	case StrategyAlwaysClaimShortest:
		o.claimedPaths[q.PacketID] = o.ShortestPath
		hash := HashPath(o.ShortestPath)
		if hash != truth {
			o.LiesTold++
		}
		return hash

	default:
		return truth
	}
}

func (o *NetworkOracle) answerDelayBound(q Query) bool {
	rec := o.FindRecordByID(q.PacketID)
	if rec == nil {
		return false
	}

	truth := rec.MinDelay > q.DelayThreshold

	switch o.Strategy {
	case StrategyHonest:
		return truth

	case StrategySophisticated:
		if claimed, exists := o.claimedMinDelays[q.PacketID]; exists {
			return claimed > q.DelayThreshold
		}
		return truth

	case StrategyMinimiseDelay:
		if rec.WasDelayed && q.DelayThreshold > rec.MinDelay {
			o.LiesTold++
			return false
		}
		return truth

	default:
		return truth
	}
}

func (o *NetworkOracle) answerCongestionFlag(q Query) (bool, float64) {
	packetsInInterval := 0
	highDelayCount := 0

	for _, rec := range o.GroundTruth {
		if q.Interval.Contains(rec.SentTime) && HashPath(rec.PathUsed) == q.PathHash {
			packetsInInterval++
			if rec.ActualDelay > rec.MinDelay*1.5 {
				highDelayCount++
			}
		}
	}

	if packetsInInterval == 0 {
		return false, 0
	}

	congestionLevel := float64(highDelayCount) / float64(packetsInInterval)
	hasCongestion := congestionLevel > 0.3

	switch o.Strategy {
	case StrategyHonest:
		return hasCongestion, congestionLevel

	case StrategySophisticated, StrategyTargeted:
		delayedInInterval := 0
		for _, rec := range o.GroundTruth {
			if q.Interval.Contains(rec.SentTime) && rec.WasDelayed {
				delayedInInterval++
			}
		}
		if delayedInInterval > 0 && !hasCongestion {
			o.LiesTold++
			return true, 0.5
		}
		return hasCongestion, congestionLevel

	default:
		return hasCongestion, congestionLevel
	}
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
	case StrategyAlwaysClaimShortest, StrategyMinimiseDelay:
		if !truth {
			o.LiesTold++
		}
		o.claimedShortest[q.PacketID] = true
		return true
	case StrategyRandomLies:
		if rand.Float64() < o.LieProbability {
			o.LiesTold++
			return !truth
		}
		return truth
	case StrategySophisticated:
		if claimed, exists := o.claimedPaths[q.PacketID]; exists {
			return claimed == o.ShortestPath
		}
		if rand.Float64() < o.LieProbability && !truth {
			o.LiesTold++
			o.claimedShortest[q.PacketID] = true
			return true
		}
		return truth
	default:
		return truth
	}
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
	case StrategyMinimiseDelay:
		lied := record.MinDelay + rand.Float64()*0.5
		if lied < truth {
			o.LiesTold++
		}
		return lied
	case StrategySophisticated:
		if claimed, exists := o.claimedDelays[q.PacketID]; exists {
			return claimed
		}
		return truth
	default:
		return truth
	}
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
	case StrategySophisticated:
		if claimed, exists := o.claimedPaths[q.PacketID]; exists {
			return claimed
		}
		return truth
	default:
		return truth
	}
}

func (o *NetworkOracle) answerPacketCount(q Query) float64 {
	count := 0
	for _, rec := range o.GroundTruth {
		if rec.PathUsed == q.PathName && q.Interval.Contains(rec.SentTime) {
			count++
		}
	}
	return float64(count)
}

func (o *NetworkOracle) GetStats() string {
	lieRate := 0.0
	if o.QueriesAnswered > 0 {
		lieRate = float64(o.LiesTold) / float64(o.QueriesAnswered) * 100
	}
	return fmt.Sprintf("Strategy: %s, Queries: %d, Lies: %d (%.1f%%)",
		o.Strategy, o.QueriesAnswered, o.LiesTold, lieRate)
}

func (o *NetworkOracle) Reset() {
	o.claimedPaths = make(map[int]string)
	o.claimedDelays = make(map[int]float64)
	o.claimedShortest = make(map[int]bool)
	o.claimedMinDelays = make(map[int]float64)
	o.comparisonHistory = make(map[string]ComparisonResult)
	o.QueriesAnswered = 0
	o.LiesTold = 0
}
