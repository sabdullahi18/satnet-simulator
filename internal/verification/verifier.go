package verification

import (
	"fmt"
	"math"
)

// Contradiction represents a detected inconsistency in the network's responses
type Contradiction struct {
	Type        string
	Description string
	Query1      Query
	Response1   Response
	Query2      Query
	Response2   Response
}

func (c Contradiction) String() string {
	return fmt.Sprintf("CONTRADICTION [%s]: %s\n  Query1: %s -> %s\n  Query2: %s -> %s",
		c.Type, c.Description, c.Query1, c.Response1, c.Query2, c.Response2)
}

// Verifier interrogates the network oracle and detects contradictions
type Verifier struct {
	Oracle         *NetworkOracle
	Responses      []Response
	Contradictions []Contradiction
	Paths          []PathInfo
	nextQueryID    int

	// Ground truth - the verifier knows what actually happened
	// because it controls the path selection
	GroundTruth    []TransmissionRecord

	// Physical constraints
	MinPossibleDelay float64 // Speed of light constraint
	MaxJitter        float64 // Maximum expected jitter
}

// PathInfo contains information about available paths
type PathInfo struct {
	Name      string
	BaseDelay float64
	IsShortest bool
}

// NewVerifier creates a new verifier
func NewVerifier(oracle *NetworkOracle, paths []PathInfo, minDelay, maxJitter float64) *Verifier {
	return &Verifier{
		Oracle:           oracle,
		Responses:        make([]Response, 0),
		Contradictions:   make([]Contradiction, 0),
		Paths:            paths,
		GroundTruth:      make([]TransmissionRecord, 0),
		nextQueryID:      1,
		MinPossibleDelay: minDelay,
		MaxJitter:        maxJitter,
	}
}

// RecordGroundTruth records what actually happened (verifier controls path selection)
func (v *Verifier) RecordGroundTruth(record TransmissionRecord) {
	v.GroundTruth = append(v.GroundTruth, record)
}

// FindGroundTruth finds the actual transmission record for a packet
func (v *Verifier) FindGroundTruth(packetID int, interval TimeInterval) *TransmissionRecord {
	for i := range v.GroundTruth {
		rec := &v.GroundTruth[i]
		if rec.PacketID == packetID && interval.Contains(rec.SentTime) {
			return rec
		}
	}
	return nil
}

// AskQuestion poses a query to the oracle and records the response
func (v *Verifier) AskQuestion(q Query, simTime float64) Response {
	q.ID = v.nextQueryID
	v.nextQueryID++

	resp := v.Oracle.Answer(q, simTime)
	v.Responses = append(v.Responses, resp)

	return resp
}

// InterrogatePacket asks multiple questions about a specific packet
func (v *Verifier) InterrogatePacket(packetID int, interval TimeInterval, simTime float64) []Response {
	responses := make([]Response, 0, 3)

	// Ask about shortest path
	q1 := Query{
		Type:     QueryShortestPath,
		Interval: interval,
		PacketID: packetID,
	}
	responses = append(responses, v.AskQuestion(q1, simTime))

	// Ask about delay
	q2 := Query{
		Type:     QueryDelay,
		Interval: interval,
		PacketID: packetID,
	}
	responses = append(responses, v.AskQuestion(q2, simTime))

	// Ask about which path was used
	q3 := Query{
		Type:     QueryPathUsed,
		Interval: interval,
		PacketID: packetID,
	}
	responses = append(responses, v.AskQuestion(q3, simTime))

	return responses
}

// CheckContradictions analyzes all responses for inconsistencies
func (v *Verifier) CheckContradictions() []Contradiction {
	v.Contradictions = make([]Contradiction, 0)

	// Group responses by packet ID and interval
	type key struct {
		packetID int
		interval TimeInterval
	}
	byPacketInterval := make(map[key][]Response)
	for _, resp := range v.Responses {
		k := key{resp.Query.PacketID, resp.Query.Interval}
		byPacketInterval[k] = append(byPacketInterval[k], resp)
	}

	// Check each packet's responses for contradictions AND against ground truth
	for k, responses := range byPacketInterval {
		v.checkPacketContradictions(k.packetID, responses)
		v.checkAgainstGroundTruth(k.packetID, k.interval, responses)
	}

	// Check aggregate contradictions (packet counts vs individual claims)
	v.checkAggregateContradictions()

	return v.Contradictions
}

// checkAgainstGroundTruth compares oracle responses to what actually happened
func (v *Verifier) checkAgainstGroundTruth(packetID int, interval TimeInterval, responses []Response) {
	truth := v.FindGroundTruth(packetID, interval)
	if truth == nil {
		return // No ground truth for this packet in this interval
	}

	for _, resp := range responses {
		switch resp.Query.Type {
		case QueryShortestPath:
			if resp.BoolAnswer != truth.IsShortestPath {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "GROUND_TRUTH_SHORTEST_PATH",
					Description: fmt.Sprintf("Packet %d: network claims shortest_path=%v but actual=%v", packetID, resp.BoolAnswer, truth.IsShortestPath),
					Query1:      resp.Query,
					Response1:   resp,
					Query2:      Query{},
					Response2:   Response{},
				})
			}

		case QueryPathUsed:
			if resp.StringAnswer != "UNKNOWN" && resp.StringAnswer != truth.PathUsed {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "GROUND_TRUTH_PATH_USED",
					Description: fmt.Sprintf("Packet %d: network claims path='%s' but actual='%s'", packetID, resp.StringAnswer, truth.PathUsed),
					Query1:      resp.Query,
					Response1:   resp,
					Query2:      Query{},
					Response2:   Response{},
				})
			}

		case QueryDelay:
			// Allow some tolerance for delay (jitter makes exact matching impossible)
			// But a large discrepancy indicates lying
			delayDiff := math.Abs(resp.FloatAnswer - truth.ActualDelay)
			tolerance := 0.5 // 500ms tolerance
			if resp.FloatAnswer >= 0 && delayDiff > tolerance {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "GROUND_TRUTH_DELAY",
					Description: fmt.Sprintf("Packet %d: network claims delay=%.4fs but actual=%.4fs (diff=%.4fs)", packetID, resp.FloatAnswer, truth.ActualDelay, delayDiff),
					Query1:      resp.Query,
					Response1:   resp,
					Query2:      Query{},
					Response2:   Response{},
				})
			}
		}
	}
}

func (v *Verifier) checkPacketContradictions(packetID int, responses []Response) {
	var shortestPathResp, delayResp, pathUsedResp *Response

	for i := range responses {
		resp := &responses[i]
		switch resp.Query.Type {
		case QueryShortestPath:
			shortestPathResp = resp
		case QueryDelay:
			delayResp = resp
		case QueryPathUsed:
			pathUsedResp = resp
		}
	}

	// Check: If claims shortest path, but path name doesn't match shortest
	if shortestPathResp != nil && pathUsedResp != nil {
		claimedShortest := shortestPathResp.BoolAnswer
		claimedPath := pathUsedResp.StringAnswer

		// Find which path is actually the shortest
		var shortestPathName string
		for _, p := range v.Paths {
			if p.IsShortest {
				shortestPathName = p.Name
				break
			}
		}

		if claimedShortest && claimedPath != shortestPathName && claimedPath != "UNKNOWN" {
			v.Contradictions = append(v.Contradictions, Contradiction{
				Type:        "PATH_MISMATCH",
				Description: fmt.Sprintf("Packet %d: claimed shortest path but path '%s' is not the shortest ('%s')", packetID, claimedPath, shortestPathName),
				Query1:      shortestPathResp.Query,
				Response1:   *shortestPathResp,
				Query2:      pathUsedResp.Query,
				Response2:   *pathUsedResp,
			})
		}
	}

	// Check: Delay should be consistent with claimed path
	if delayResp != nil && pathUsedResp != nil {
		claimedDelay := delayResp.FloatAnswer
		claimedPath := pathUsedResp.StringAnswer

		// Find the path info
		var pathInfo *PathInfo
		for i := range v.Paths {
			if v.Paths[i].Name == claimedPath {
				pathInfo = &v.Paths[i]
				break
			}
		}

		if pathInfo != nil {
			// Delay should be at least base delay
			if claimedDelay < pathInfo.BaseDelay-0.001 { // small tolerance
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "DELAY_TOO_LOW",
					Description: fmt.Sprintf("Packet %d: claimed delay %.4fs is less than path '%s' base delay %.4fs", packetID, claimedDelay, claimedPath, pathInfo.BaseDelay),
					Query1:      delayResp.Query,
					Response1:   *delayResp,
					Query2:      pathUsedResp.Query,
					Response2:   *pathUsedResp,
				})
			}

			// Delay shouldn't be impossibly high for the claimed path (base + max jitter + max spike)
			maxExpectedDelay := pathInfo.BaseDelay + v.MaxJitter + 3.0 // 3.0 is generous spike allowance
			if claimedDelay > maxExpectedDelay {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "DELAY_TOO_HIGH",
					Description: fmt.Sprintf("Packet %d: claimed delay %.4fs exceeds max expected %.4fs for path '%s'", packetID, claimedDelay, maxExpectedDelay, claimedPath),
					Query1:      delayResp.Query,
					Response1:   *delayResp,
					Query2:      pathUsedResp.Query,
					Response2:   *pathUsedResp,
				})
			}
		}
	}

	// Check: If claims shortest path, delay should be in reasonable range
	if shortestPathResp != nil && delayResp != nil {
		if shortestPathResp.BoolAnswer {
			claimedDelay := delayResp.FloatAnswer

			// Find shortest path info
			var shortestPathInfo *PathInfo
			for i := range v.Paths {
				if v.Paths[i].IsShortest {
					shortestPathInfo = &v.Paths[i]
					break
				}
			}

			if shortestPathInfo != nil {
				// If claiming shortest path, delay should be consistent with that path
				minExpected := shortestPathInfo.BaseDelay
				maxExpected := shortestPathInfo.BaseDelay + v.MaxJitter + 3.0

				if claimedDelay < minExpected-0.001 {
					v.Contradictions = append(v.Contradictions, Contradiction{
						Type:        "SHORTEST_PATH_DELAY_INCONSISTENT",
						Description: fmt.Sprintf("Packet %d: claims shortest path but delay %.4fs < min expected %.4fs", packetID, claimedDelay, minExpected),
						Query1:      shortestPathResp.Query,
						Response1:   *shortestPathResp,
						Query2:      delayResp.Query,
						Response2:   *delayResp,
					})
				} else if claimedDelay > maxExpected {
					v.Contradictions = append(v.Contradictions, Contradiction{
						Type:        "SHORTEST_PATH_DELAY_INCONSISTENT",
						Description: fmt.Sprintf("Packet %d: claims shortest path but delay %.4fs > max expected %.4fs", packetID, claimedDelay, maxExpected),
						Query1:      shortestPathResp.Query,
						Response1:   *shortestPathResp,
						Query2:      delayResp.Query,
						Response2:   *delayResp,
					})
				}
			}
		}
	}

	// Check: Physical constraint - delay can't be less than speed of light minimum
	if delayResp != nil {
		if delayResp.FloatAnswer < v.MinPossibleDelay && delayResp.FloatAnswer >= 0 {
			v.Contradictions = append(v.Contradictions, Contradiction{
				Type:        "PHYSICAL_VIOLATION",
				Description: fmt.Sprintf("Packet %d: claimed delay %.4fs violates minimum possible delay %.4fs (speed of light)", packetID, delayResp.FloatAnswer, v.MinPossibleDelay),
				Query1:      delayResp.Query,
				Response1:   *delayResp,
				Query2:      Query{}, // No second query needed
				Response2:   Response{},
			})
		}
	}
}

func (v *Verifier) checkAggregateContradictions() {
	// Group QueryPacketCount responses by interval
	// Then count individual path claims for the SAME interval

	// First, find all QueryPacketCount queries and their intervals
	for _, countResp := range v.Responses {
		if countResp.Query.Type != QueryPacketCount {
			continue
		}

		interval := countResp.Query.Interval
		pathName := countResp.Query.PathName
		claimedCount := int(countResp.FloatAnswer)

		// Count individual path claims for this SPECIFIC interval
		individualClaims := 0
		for _, pathResp := range v.Responses {
			if pathResp.Query.Type == QueryPathUsed &&
			   pathResp.StringAnswer == pathName &&
			   pathResp.Query.Interval == interval {
				individualClaims++
			}
		}

		// If we have individual claims and they significantly differ from the count
		if individualClaims > 0 && math.Abs(float64(claimedCount-individualClaims)) > float64(individualClaims)/2 {
			v.Contradictions = append(v.Contradictions, Contradiction{
				Type:        "COUNT_MISMATCH",
				Description: fmt.Sprintf("Path '%s' in %s: claimed count %d but individual responses indicate %d", pathName, interval, claimedCount, individualClaims),
				Query1:      countResp.Query,
				Response1:   countResp,
				Query2:      Query{}, // Aggregate from multiple queries
				Response2:   Response{},
			})
		}
	}
}

// RunVerification performs a full verification run
func (v *Verifier) RunVerification(intervals []TimeInterval, packetsPerInterval int, simTime float64) VerificationResult {
	totalQueries := 0

	for _, interval := range intervals {
		// Interrogate packets in this interval
		for pid := 0; pid < packetsPerInterval; pid++ {
			v.InterrogatePacket(pid, interval, simTime)
			totalQueries += 3 // 3 questions per packet
		}

		// Also ask aggregate questions
		for _, path := range v.Paths {
			q := Query{
				Type:     QueryPacketCount,
				Interval: interval,
				PathName: path.Name,
			}
			v.AskQuestion(q, simTime)
			totalQueries++
		}
	}

	// Check for contradictions
	contradictions := v.CheckContradictions()

	return VerificationResult{
		TotalQueries:       totalQueries,
		TotalResponses:     len(v.Responses),
		ContradictionsFound: len(contradictions),
		Contradictions:     contradictions,
		Trustworthy:        len(contradictions) == 0,
		OracleStats:        v.Oracle.GetStats(),
	}
}

// VerificationResult contains the results of a verification run
type VerificationResult struct {
	TotalQueries        int
	TotalResponses      int
	ContradictionsFound int
	Contradictions      []Contradiction
	Trustworthy         bool
	OracleStats         string
}

func (vr VerificationResult) String() string {
	status := "TRUSTWORTHY"
	if !vr.Trustworthy {
		status = "UNTRUSTWORTHY - LIES DETECTED"
	}

	result := fmt.Sprintf(`
=== VERIFICATION RESULT ===
Status: %s
Total Queries: %d
Contradictions Found: %d
Oracle Stats: %s
`, status, vr.TotalQueries, vr.ContradictionsFound, vr.OracleStats)

	if len(vr.Contradictions) > 0 {
		result += "\n=== CONTRADICTIONS ===\n"
		for i, c := range vr.Contradictions {
			result += fmt.Sprintf("\n[%d] %s\n", i+1, c)
		}
	}

	return result
}
