package verification

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
)

type QueryStrategy int

const (
	StrategyRandom QueryStrategy = iota
	StrategyTargetedQuery
	StrategyAdaptive
	StrategyExhaustive
)

func (s QueryStrategy) String() string {
	switch s {
	case StrategyRandom:
		return "RANDOM"
	case StrategyTargetedQuery:
		return "TARGETED"
	case StrategyAdaptive:
		return "ADAPTIVE"
	case StrategyExhaustive:
		return "EXHAUSTIVE"
	default:
		return "UNKNOWN"
	}
}

type VerificationConfig struct {
	SamplingRate     float64
	SamplingSecret   string
	MaxQueries       int
	TargetConfidence float64
	QueryStrategy    QueryStrategy

	MinPhysicalDelay  float64
	MaxJitter         float64
	TemporalTolerance float64

	PriorHonest float64
	MinQueries  int
}

func DefaultVerificationConfig() VerificationConfig {
	return VerificationConfig{
		SamplingRate:      0.20,
		SamplingSecret:    fmt.Sprintf("secret_%d", rand.Int63()),
		MaxQueries:        500,
		TargetConfidence:  0.95,
		QueryStrategy:     StrategyAdaptive,
		MinPhysicalDelay:  0.01,
		MaxJitter:         2.0,
		TemporalTolerance: 0.5,
		PriorHonest:       0.5,
		MinQueries:        100,
	}
}

type PathCommitment struct {
	PacketID  int
	PathHash  string
	Timestamp float64
}

type Verifier struct {
	Oracle *NetworkOracle
	Config VerificationConfig

	Detector   *ContradictionDetector
	Confidence *ConfidenceTracker

	AllRecords []TransmissionRecord
	SampledIDs map[int]bool
	PathInfos  map[string]PathInfo

	nextQueryID    int
	QueryLog       []QueryLogEntry
	ResponseCache  map[int]Response
	Contradictions []Contradiction
}

type PathInfo struct {
	Name       string
	BaseDelay  float64
	IsShortest bool
}

type QueryLogEntry struct {
	Query     Query
	Response  Response
	Suspicion float64
	Timestamp float64
}

func (v *Verifier) AddPathInfo(name string, baseDelay float64, isShortest bool) {
	v.PathInfos[name] = PathInfo{
		Name:       name,
		BaseDelay:  baseDelay,
		IsShortest: isShortest,
	}
	v.Detector.Physical.AddPath(name, baseDelay)
}

func (v *Verifier) IngestRecords(records []TransmissionRecord) {
	v.AllRecords = append(v.AllRecords, records...)

	for _, rec := range records {
		data := fmt.Sprintf("%d|%f|%s", rec.PacketID, rec.SentTime, v.Config.SamplingSecret)
		hash := HashPath(data)
		hashVal := 0
		for i := 0; i < 4 && i < len(hash); i++ {
			hashVal = hashVal*16 + int(hash[i])%16
		}
		normalised := float64(hashVal) / float64(0xFFFF)

		if normalised < v.Config.SamplingRate {
			v.SampledIDs[rec.PacketID] = true
		}
	}

	delayedCount := 0
	for _, rec := range records {
		if rec.WasDelayed {
			delayedCount++
		}
	}

	v.Confidence = NewConfidenceTracker(
		v.Config.PriorHonest,
		0.05, 0.05, // alpha, beta
		float64(delayedCount)/float64(len(records)),
		delayedCount,
		len(records),
	)

	v.Confidence.Bayesian.MinQueriesBeforeHonest = v.Config.MinQueries
}

func (v *Verifier) AskQuery(q Query, simTime float64) Response {
	q.ID = v.nextQueryID
	v.nextQueryID++

	resp := v.Oracle.Answer(q, simTime)
	v.ResponseCache[q.ID] = resp

	return resp
}

func (v *Verifier) GenerateQueries() []Query {
	queries := make([]Query, 0)

	sampledRecords := make([]TransmissionRecord, 0)
	for _, rec := range v.AllRecords {
		if v.SampledIDs[rec.PacketID] {
			sampledRecords = append(sampledRecords, rec)
		}
	}

	if len(sampledRecords) < 2 {
		return queries
	}

	switch v.Config.QueryStrategy {
	case StrategyRandom:
		queries = v.generateRandomQueries(sampledRecords)
	case StrategyTargetedQuery:
		queries = v.generateTargetedQueries(sampledRecords)
	case StrategyAdaptive:
		queries = v.generateAdaptiveQueries(sampledRecords)
	case StrategyExhaustive:
		queries = v.generateExhaustiveQueries(sampledRecords)
	}

	return queries
}

func (v *Verifier) generateRandomQueries(records []TransmissionRecord) []Query {
	queries := make([]Query, 0)

	for i := range len(records) {
		for j := i + 1; j < len(records); j++ {
			if rand.Float64() < 0.3 {
				interval := TimeInterval{
					Start: math.Min(records[i].SentTime, records[j].SentTime) - 0.1,
					End:   math.Max(records[i].SentTime, records[j].SentTime) + 0.1,
				}

				queries = append(queries, Query{
					Type:      QueryComparison,
					PacketID:  records[i].PacketID,
					PacketID2: records[j].PacketID,
					Interval:  interval,
				})
			}
		}
	}

	return queries
}

func (v *Verifier) generateTargetedQueries(records []TransmissionRecord) []Query {
	queries := make([]Query, 0)

	sorted := make([]TransmissionRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ActualDelay > sorted[j].ActualDelay
	})

	highDelayCount := len(sorted) / 3
	if highDelayCount < 10 {
		highDelayCount = min(10, len(sorted))
	}

	highDelay := sorted[:highDelayCount]
	lowDelay := sorted[highDelayCount:]

	for _, high := range highDelay {
		numComparisons := min(10, len(lowDelay)) // Increased from 5
		for i := 0; i < numComparisons; i++ {
			low := lowDelay[rand.Intn(len(lowDelay))]

			interval := TimeInterval{
				Start: math.Min(high.SentTime, low.SentTime) - 0.1,
				End:   math.Max(high.SentTime, low.SentTime) + 0.1,
			}

			queries = append(queries, Query{
				Type:      QueryComparison,
				PacketID:  high.PacketID,
				PacketID2: low.PacketID,
				Interval:  interval,
			})
		}
	}

	for i := range len(highDelay) {
		for j := i + 1; j < len(highDelay); j++ {
			interval := TimeInterval{
				Start: math.Min(highDelay[i].SentTime, highDelay[j].SentTime) - 0.1,
				End:   math.Max(highDelay[i].SentTime, highDelay[j].SentTime) + 0.1,
			}
			queries = append(queries, Query{
				Type:      QueryComparison,
				PacketID:  highDelay[i].PacketID,
				PacketID2: highDelay[j].PacketID,
				Interval:  interval,
			})
		}
	}

	return queries
}

func (v *Verifier) generateAdaptiveQueries(records []TransmissionRecord) []Query {
	queries := v.generateTargetedQueries(records)

	random := v.generateRandomQueries(records)
	numRandom := len(random) / 2
	for i := 0; i < numRandom && i < len(random); i++ {
		queries = append(queries, random[rand.Intn(len(random))])
	}

	return queries
}

func (v *Verifier) generateExhaustiveQueries(records []TransmissionRecord) []Query {
	queries := make([]Query, 0)

	for i := range len(records) {
		for j := i + 1; j < len(records); j++ {
			interval := TimeInterval{
				Start: math.Min(records[i].SentTime, records[j].SentTime) - 0.1,
				End:   math.Max(records[i].SentTime, records[j].SentTime) + 0.1,
			}

			queries = append(queries, Query{
				Type:      QueryComparison,
				PacketID:  records[i].PacketID,
				PacketID2: records[j].PacketID,
				Interval:  interval,
			})
		}
	}

	return queries
}

func (v *Verifier) findRecord(packetID int) *TransmissionRecord {
	for i := range v.AllRecords {
		if v.AllRecords[i].PacketID == packetID {
			return &v.AllRecords[i]
		}
	}
	return nil
}

func (v *Verifier) RunVerification(simTime float64) VerificationResult {
	queries := v.GenerateQueries()

	rand.Shuffle(len(queries), func(i, j int) {
		queries[i], queries[j] = queries[j], queries[i]
	})

	for i, q := range queries {
		if i >= v.Config.MaxQueries {
			break
		}

		resp := v.AskQuery(q, simTime)
		rec1 := v.findRecord(q.PacketID)
		rec2 := v.findRecord(q.PacketID2)

		timeOverlap := false
		if rec1 != nil && rec2 != nil {
			timeOverlap = math.Abs(rec1.SentTime-rec2.SentTime) < 5.0
		}

		suspicion, contradiction := v.Detector.ProcessResponse(q, resp, rec1, rec2, timeOverlap)
		v.QueryLog = append(v.QueryLog, QueryLogEntry{
			Query:     q,
			Response:  resp,
			Suspicion: suspicion,
			Timestamp: simTime,
		})

		involvesSuspicious := false
		if rec1 != nil && rec1.WasDelayed {
			involvesSuspicious = true
		}
		if rec2 != nil && rec2.WasDelayed {
			involvesSuspicious = true
		}

		v.Confidence.ProcessResult(q.ID, suspicion, contradiction, involvesSuspicious)

		if contradiction {
			break
		}

		if len(v.QueryLog) >= v.Config.MinQueries {
			shouldContinue, reason := v.Confidence.Bayesian.ShouldContinue(v.Config.TargetConfidence, v.Config.MaxQueries)
			if !shouldContinue {
				if reason == "DISHONEST_DETECTED" || reason == "HONEST_CONFIRMED" {
					break
				}
			}
		}
	}

	return v.buildResult()
}

func (v *Verifier) buildResult() VerificationResult {
	verdict, confidence := v.Confidence.GetVerdict()
	definitiveProofs := v.Detector.GetDefinitiveContradictions()
	trustworthy := verdict == "HONEST" || verdict == "HONEST_LIKELY"

	return VerificationResult{
		Verdict:              verdict,
		Confidence:           confidence,
		Trustworthy:          trustworthy,
		TotalQueries:         len(v.QueryLog),
		TotalSampled:         len(v.SampledIDs),
		TotalPackets:         len(v.AllRecords),
		ContradictionsFound:  len(v.Detector.Contradictions),
		DefinitiveProofs:     len(definitiveProofs),
		Contradictions:       v.Detector.Contradictions,
		OracleStats:          v.Oracle.GetStats(),
		ConfidenceHistory:    v.extractConfidenceHistory(),
		TopSuspiciousPackets: v.Detector.Temporal.GetTopSuspicious(10),
	}
}

func (v *Verifier) extractConfidenceHistory() []float64 {
	history := make([]float64, len(v.Confidence.Bayesian.QueryHistory))
	for i, qr := range v.Confidence.Bayesian.QueryHistory {
		history[i] = qr.PHonestAfter
	}
	return history
}

type VerificationResult struct {
	Verdict     string
	Confidence  float64
	Trustworthy bool

	TotalQueries int
	TotalSampled int
	TotalPackets int

	ContradictionsFound int
	DefinitiveProofs    int
	Contradictions      []Contradiction

	OracleStats          string
	ConfidenceHistory    []float64
	TopSuspiciousPackets []int
}

func (vr VerificationResult) String() string {
	status := "TRUSTWORTHY"
	if !vr.Trustworthy {
		status = "UNTRUSTWORTHY"
	}

	result := fmt.Sprintf(`
================================================================================
                        VERIFICATION RESULT
================================================================================
Status:              %s
Verdict:             %s
Confidence:          %.2f%%

Packets:             %d total, %d sampled (%.1f%%)
Queries:             %d executed
Contradictions:      %d found (%d definitive proofs)

Oracle Stats:        %s
Top Suspicious:      %v
================================================================================
`, status, vr.Verdict, vr.Confidence*100,
		vr.TotalPackets, vr.TotalSampled, float64(vr.TotalSampled)/float64(vr.TotalPackets)*100,
		vr.TotalQueries,
		vr.ContradictionsFound, vr.DefinitiveProofs,
		vr.OracleStats,
		vr.TopSuspiciousPackets)

	if len(vr.Contradictions) > 0 {
		result += "\n=== CONTRADICTIONS FOUND ===\n"
		for i, c := range vr.Contradictions {
			if i >= 10 {
				result += fmt.Sprintf("\n... and %d more\n", len(vr.Contradictions)-10)
				break
			}
			result += fmt.Sprintf("\n[%d] %s\n", i+1, c)
		}
	}

	return result
}

func NewVerifier(oracle *NetworkOracle, config VerificationConfig) *Verifier {
	v := &Verifier{
		Oracle:        oracle,
		Config:        config,
		Detector:      NewContradictionDetector(config.MinPhysicalDelay, config.MaxJitter, config.TemporalTolerance),
		AllRecords:    make([]TransmissionRecord, 0),
		SampledIDs:    make(map[int]bool),
		PathInfos:     make(map[string]PathInfo),
		QueryLog:      make([]QueryLogEntry, 0),
		ResponseCache: make(map[int]Response),
		nextQueryID:   1,
	}

	return v
}
