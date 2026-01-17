package verification

import (
	"fmt"
	"math"
)

type ContradictionType string

const (
	ContradictionTransitivity        ContradictionType = "TRANSITIVITY_VIOLATION"
	ContradictionTemporalMismatch    ContradictionType = "TEMPORAL_MISMATCH"
	ContradictionPhysicalImpossible  ContradictionType = "PHYSICAL_IMPOSSIBLE"
	ContradictionCommitmentViolation ContradictionType = "COMMITMENT_VIOLATION"
	ContradictionPathMismatch        ContradictionType = "PATH_MISMATCH"
	ContradictionDelayMismatch       ContradictionType = "DELAY_MISMATCH"
	ContradictionCrossInterval       ContradictionType = "CROSS_INTERVAL"
	ContradictionHashMismatch        ContradictionType = "HASH_MISMATCH"
)

type Contradiction struct {
	Type        ContradictionType
	Description string
	Severity    float64

	Query1      Query
	Response1   Response
	Query2      Query
	Response2   Response
	GroundTruth *TransmissionRecord

	Cycle []int
}

func (c Contradiction) String() string {
	result := fmt.Sprintf("CONTRADICTION [%s] (severity=%.2f): %s", c.Type, c.Severity, c.Description)

	if c.Query1.ID != 0 {
		result += fmt.Sprintf("\n  Query1: %s -> %s", c.Query1, c.Response1)
	}
	if c.Query2.ID != 0 {
		result += fmt.Sprintf("\n  Query2: %s -> %s", c.Query2, c.Response2)
	}
	if len(c.Cycle) > 0 {
		result += fmt.Sprintf("\n  Cycle: %v", c.Cycle)
	}
	if c.GroundTruth != nil {
		result += fmt.Sprintf("\n  [DEBUG Ground Truth]: %s", c.GroundTruth)
	}
	return result
}

type TransitivityChecker struct {
	// edge (i,j) means "i was claimed to have lower min delay than j"
	graph       map[int]map[int]bool
	queryRecord map[string]int // "i-j" -> queryID that established this
}

func NewTransitivityChecker() *TransitivityChecker {
	return &TransitivityChecker{
		graph:       make(map[int]map[int]bool),
		queryRecord: make(map[string]int),
	}
}

func (tc *TransitivityChecker) AddComparison(fasterPacket, slowerPacket, queryID int) *Contradiction {
	if tc.graph[fasterPacket] == nil {
		tc.graph[fasterPacket] = make(map[int]bool)
	}

	tc.graph[fasterPacket][slowerPacket] = true
	tc.queryRecord[fmt.Sprintf("%d-%d", fasterPacket, slowerPacket)] = queryID

	cycle := tc.findCycle(fasterPacket)
	if cycle != nil {
		return &Contradiction{
			Type:        ContradictionTransitivity,
			Description: fmt.Sprintf("Transitivity violation: cycle detected involving packets %v", cycle),
			Severity:    1.0,
			Cycle:       cycle,
		}
	}

	return nil
}

func (tc *TransitivityChecker) findCycle(start int) []int {
	visited := make(map[int]bool)
	parent := make(map[int]int)

	var dfs func(node int) bool
	dfs = func(node int) bool {
		if visited[node] {
			return false
		}
		visited[node] = true

		for neighbor := range tc.graph[node] {
			if neighbor == start {
				return true
			}
			parent[neighbor] = node
			if dfs(neighbor) {
				return true
			}
		}
		return false
	}

	for neighbor := range tc.graph[start] {
		if neighbor == start {
			return []int{start}
		}
		parent[neighbor] = start
		visited = make(map[int]bool)
		visited[start] = true
		if dfs(neighbor) {
			return tc.reconstructCycle(start, parent)
		}
	}

	return nil
}

func (tc *TransitivityChecker) reconstructCycle(start int, parent map[int]int) []int {
	cycle := []int{start}
	current := start

	for {
		found := false
		for neighbor := range tc.graph[current] {
			if neighbor == start {
				return cycle
			}
			if _, inParent := parent[neighbor]; inParent || neighbor == start {
				cycle = append(cycle, neighbor)
				current = neighbor
				found = true
				break
			}
		}
		if !found || len(cycle) > 100 {
			break
		}
	}

	return cycle
}

func (tc *TransitivityChecker) Reset() {
	tc.graph = make(map[int]map[int]bool)
	tc.queryRecord = make(map[string]int)
}

type TemporalConsistencyChecker struct {
	Tolerance       float64
	SuspicionScores map[int]float64
}

func NewTemporalConsistencyChecker(tolerance float64) *TemporalConsistencyChecker {
	return &TemporalConsistencyChecker{
		Tolerance:       tolerance,
		SuspicionScores: make(map[int]float64),
	}
}

func (tcc *TemporalConsistencyChecker) CheckComparison(
	packet1, packet2 *TransmissionRecord,
	comparisonResult ComparisonResult,
	timeWindowOverlap bool,
) (float64, *Contradiction) {

	if packet1 == nil || packet2 == nil {
		return 0, nil
	}

	obs1 := packet1.ActualDelay
	obs2 := packet2.ActualDelay

	suspicion := 0.0

	switch comparisonResult {
	case Packet1Faster:
		if timeWindowOverlap && obs1 > obs2*(1+tcc.Tolerance) {
			suspicion = (obs1 / obs2) - 1
			tcc.SuspicionScores[packet1.PacketID] += suspicion

			if suspicion > 1.0 {
				return suspicion, &Contradiction{
					Type: ContradictionTemporalMismatch,
					Description: fmt.Sprintf("Packet %d claimed faster but observed %.4fs vs %.4fs (%.1fx slower)",
						packet1.PacketID, obs1, obs2, obs1/obs2),
					Severity: math.Min(suspicion/2, 0.9),
				}
			}
		}

	case Packet2Faster:
		if timeWindowOverlap && obs2 > obs1*(1+tcc.Tolerance) {
			suspicion = (obs2 / obs1) - 1
			tcc.SuspicionScores[packet2.PacketID] += suspicion

			if suspicion > 1.0 {
				return suspicion, &Contradiction{
					Type: ContradictionTemporalMismatch,
					Description: fmt.Sprintf("Packet %d claimed faster but observed %.4fs vs %.4fs (%.1fx slower)",
						packet2.PacketID, obs2, obs1, obs2/obs1),
					Severity: math.Min(suspicion/2, 0.9),
				}
			}
		}
	}

	return suspicion, nil
}

func (tcc *TemporalConsistencyChecker) GetTopSuspicious(n int) []int {
	type kv struct {
		id    int
		score float64
	}

	var sorted []kv
	for id, score := range tcc.SuspicionScores {
		sorted = append(sorted, kv{id, score})
	}

	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].score > sorted[i].score {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	result := make([]int, 0, n)
	for i := 0; i < n && i < len(sorted); i++ {
		result = append(result, sorted[i].id)
	}
	return result
}

func (tcc *TemporalConsistencyChecker) Reset() {
	tcc.SuspicionScores = make(map[int]float64)
}

type PhysicalConstraintChecker struct {
	MinPhysicalDelay float64
	MaxJitter        float64
	PathDelays       map[string]float64
}

func NewPhysicalConstraintChecker(minDelay, maxJitter float64) *PhysicalConstraintChecker {
	return &PhysicalConstraintChecker{
		MinPhysicalDelay: minDelay,
		MaxJitter:        maxJitter,
		PathDelays:       make(map[string]float64),
	}
}

func (pcc *PhysicalConstraintChecker) AddPath(pathName string, baseDelay float64) {
	pcc.PathDelays[pathName] = baseDelay
}

func (pcc *PhysicalConstraintChecker) CheckClaim(claimedMinDelay, observedDelay float64, pathName string) *Contradiction {
	if claimedMinDelay < pcc.MinPhysicalDelay {
		return &Contradiction{
			Type: ContradictionPhysicalImpossible,
			Description: fmt.Sprintf("Claimed min delay %.4fs < physical minimum %.4fs (speed of light)",
				claimedMinDelay, pcc.MinPhysicalDelay),
			Severity: 1.0,
		}
	}

	if observedDelay < claimedMinDelay-0.001 {
		return &Contradiction{
			Type: ContradictionPhysicalImpossible,
			Description: fmt.Sprintf("Observed delay %.4fs < claimed minimum %.4fs",
				observedDelay, claimedMinDelay),
			Severity: 1.0,
		}
	}

	if pathDelay, exists := pcc.PathDelays[pathName]; exists {
		if claimedMinDelay < pathDelay-0.001 {
			return &Contradiction{
				Type: ContradictionPhysicalImpossible,
				Description: fmt.Sprintf("Claimed min delay %.4fs < path base delay %.4fs for %s",
					claimedMinDelay, pathDelay, pathName),
				Severity: 1.0,
			}
		}
	}

	return nil
}

func (pcc *PhysicalConstraintChecker) CheckDelayBounds(pathName string, observedDelay float64) *Contradiction {
	if pathDelay, exists := pcc.PathDelays[pathName]; exists {
		// Too fast
		if observedDelay < pathDelay-0.001 {
			return &Contradiction{
				Type: ContradictionPhysicalImpossible,
				Description: fmt.Sprintf("Observed delay %.4fs faster than path minimum %.4fs for %s",
					observedDelay, pathDelay, pathName),
				Severity: 1.0,
			}
		}

		maxExpected := pathDelay + pcc.MaxJitter + 5.0
		if observedDelay > maxExpected {
			return &Contradiction{
				Type: ContradictionDelayMismatch,
				Description: fmt.Sprintf("Observed delay %.4fs >> expected max %.4fs for %s",
					observedDelay, maxExpected, pathName),
				Severity: 0.5,
			}
		}
	}

	return nil
}

type CommitmentChecker struct {
	ResponseHistory map[string]Response
}

func NewCommitmentChecker() *CommitmentChecker {
	return &CommitmentChecker{
		ResponseHistory: make(map[string]Response),
	}
}

func (cc *CommitmentChecker) queryHash(q Query) string {
	return fmt.Sprintf("%d-%d-%d-%s-%.2f-%.2f",
		q.Type, q.PacketID, q.PacketID2, q.PathName,
		q.Interval.Start, q.Interval.End)
}

func (cc *CommitmentChecker) CheckAndRecord(q Query, r Response) *Contradiction {
	hash := cc.queryHash(q)

	if prev, exists := cc.ResponseHistory[hash]; exists {
		inconsistent := false

		switch q.Type {
		case QueryComparison:
			inconsistent = r.ComparisonAnswer != prev.ComparisonAnswer
		case QueryPathHash:
			inconsistent = r.StringAnswer != prev.StringAnswer
		case QueryDelayBound:
			inconsistent = r.BoolAnswer != prev.BoolAnswer
		case QueryShortestPath:
			inconsistent = r.BoolAnswer != prev.BoolAnswer
		case QueryDelay:
			inconsistent = math.Abs(r.FloatAnswer-prev.FloatAnswer) > 0.01
		case QueryPathUsed:
			inconsistent = r.StringAnswer != prev.StringAnswer
		}

		if inconsistent {
			return &Contradiction{
				Type: ContradictionCommitmentViolation,
				Description: fmt.Sprintf("Inconsistent answers to same query: %s vs %s",
					prev.String(), r.String()),
				Severity:  1.0, // Definitive
				Query1:    prev.Query,
				Response1: prev,
				Query2:    q,
				Response2: r,
			}
		}
	}

	cc.ResponseHistory[hash] = r
	return nil
}

func (cc *CommitmentChecker) Reset() {
	cc.ResponseHistory = make(map[string]Response)
}

type ContradictionDetector struct {
	Transitivity *TransitivityChecker
	Temporal     *TemporalConsistencyChecker
	Physical     *PhysicalConstraintChecker
	Commitment   *CommitmentChecker

	Contradictions []Contradiction
}

func NewContradictionDetector(minDelay, maxJitter, tolerance float64) *ContradictionDetector {
	return &ContradictionDetector{
		Transitivity:   NewTransitivityChecker(),
		Temporal:       NewTemporalConsistencyChecker(tolerance),
		Physical:       NewPhysicalConstraintChecker(minDelay, maxJitter),
		Commitment:     NewCommitmentChecker(),
		Contradictions: make([]Contradiction, 0),
	}
}

func (cd *ContradictionDetector) ProcessResponse(q Query, r Response,
	rec1, rec2 *TransmissionRecord, timeOverlap bool) (float64, bool) {

	suspicion := 0.0
	foundContradiction := false

	if c := cd.Commitment.CheckAndRecord(q, r); c != nil {
		cd.Contradictions = append(cd.Contradictions, *c)
		foundContradiction = true
	}

	switch q.Type {
	case QueryComparison:
		switch r.ComparisonAnswer {
		case Packet1Faster:
			if c := cd.Transitivity.AddComparison(q.PacketID, q.PacketID2, q.ID); c != nil {
				cd.Contradictions = append(cd.Contradictions, *c)
				foundContradiction = true
			}
		case Packet2Faster:
			if c := cd.Transitivity.AddComparison(q.PacketID2, q.PacketID, q.ID); c != nil {
				cd.Contradictions = append(cd.Contradictions, *c)
				foundContradiction = true
			}
		}

		if rec1 != nil && rec2 != nil {
			s, c := cd.Temporal.CheckComparison(rec1, rec2, r.ComparisonAnswer, timeOverlap)
			suspicion = s
			if c != nil {
				cd.Contradictions = append(cd.Contradictions, *c)
				if c.Severity >= 0.9 {
					foundContradiction = true
				}
			}
		}

	case QueryDelayBound:

	case QueryDelay:
		if rec1 != nil {
			if c := cd.Physical.CheckDelayBounds(rec1.PathUsed, r.FloatAnswer); c != nil {
				cd.Contradictions = append(cd.Contradictions, *c)
				if c.Severity >= 0.9 {
					foundContradiction = true
				}
			}
		}
	}

	return suspicion, foundContradiction
}

func (cd *ContradictionDetector) GetDefinitiveContradictions() []Contradiction {
	definitive := make([]Contradiction, 0)
	for _, c := range cd.Contradictions {
		if c.Severity >= 0.99 {
			definitive = append(definitive, c)
		}
	}
	return definitive
}

func (cd *ContradictionDetector) Reset() {
	cd.Transitivity.Reset()
	cd.Temporal.Reset()
	cd.Commitment.Reset()
	cd.Contradictions = make([]Contradiction, 0)
}

func (cd *ContradictionDetector) Summary() string {
	definitive := len(cd.GetDefinitiveContradictions())
	suspicious := cd.Temporal.GetTopSuspicious(5)

	return fmt.Sprintf("Contradictions: %d total, %d definitive. Top suspicious packets: %v",
		len(cd.Contradictions), definitive, suspicious)
}
