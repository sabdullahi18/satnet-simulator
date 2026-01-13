package verification

import (
	"crypto/sha256"
	"fmt"
	"math"
)

// Contradiction represents a detected inconsistency in the network's responses
type Contradiction struct {
	Type        string
	Description string
	Query1      Query
	Response1   Response
	Query2      Query    // Optional: empty for single-query contradictions
	Response2   Response // Optional: empty for single-query contradictions
}

func (c Contradiction) String() string {
	if c.Query2.ID == 0 && c.Response2.QueryID == 0 {
		// Single query contradiction (e.g., physical violation, hash mismatch)
		return fmt.Sprintf("CONTRADICTION [%s]: %s\n  Query: %s -> %s",
			c.Type, c.Description, c.Query1, c.Response1)
	}
	// Two-query contradiction
	return fmt.Sprintf("CONTRADICTION [%s]: %s\n  Query1: %s -> %s\n  Query2: %s -> %s",
		c.Type, c.Description, c.Query1, c.Response1, c.Query2, c.Response2)
}

// PathCommitment represents a hash commitment to a path choice
// The network provides this when transmitting, and must be consistent later
type PathCommitment struct {
	PacketID  int
	PathHash  string // SHA256 hash of the path name
	Timestamp float64
}

// Verifier interrogates the network oracle and detects contradictions
// IMPORTANT: The verifier does NOT have access to ground truth for verification.
// It can only detect lies through internal contradictions in the network's responses.
type Verifier struct {
	Oracle         *NetworkOracle
	Responses      []Response
	Contradictions []Contradiction
	Paths          []PathInfo
	nextQueryID    int

	// Path commitments - hashes the network provided at transmission time
	PathCommitments map[int]PathCommitment // packetID -> commitment

	// Physical constraints (publicly known)
	MinPossibleDelay float64 // Speed of light constraint
	MaxJitter        float64 // Maximum expected jitter

	// DEBUG ONLY: Ground truth for analysis (not used in verification!)
	DebugGroundTruth []TransmissionRecord
}

// PathInfo contains information about available paths (publicly known)
type PathInfo struct {
	Name       string
	BaseDelay  float64
	IsShortest bool
}

// NewVerifier creates a new verifier
func NewVerifier(oracle *NetworkOracle, paths []PathInfo, minDelay, maxJitter float64) *Verifier {
	return &Verifier{
		Oracle:           oracle,
		Responses:        make([]Response, 0),
		Contradictions:   make([]Contradiction, 0),
		Paths:            paths,
		PathCommitments:  make(map[int]PathCommitment),
		nextQueryID:      1,
		MinPossibleDelay: minDelay,
		MaxJitter:        maxJitter,
		DebugGroundTruth: make([]TransmissionRecord, 0),
	}
}

// RecordPathCommitment records a hash commitment from the network
// This is what the network provides at transmission time (we can't see the actual path)
func (v *Verifier) RecordPathCommitment(packetID int, pathHash string, timestamp float64) {
	v.PathCommitments[packetID] = PathCommitment{
		PacketID:  packetID,
		PathHash:  pathHash,
		Timestamp: timestamp,
	}
}

// HashPath creates a hash of a path name (used to verify commitments)
func HashPath(pathName string) string {
	h := sha256.Sum256([]byte(pathName))
	return fmt.Sprintf("%x", h[:8]) // First 8 bytes for readability
}

// RecordDebugGroundTruth records actual behavior for debugging (NOT used in verification)
func (v *Verifier) RecordDebugGroundTruth(record TransmissionRecord) {
	v.DebugGroundTruth = append(v.DebugGroundTruth, record)
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

// CheckContradictions analyzes all responses for internal inconsistencies
// This does NOT use ground truth - only the network's own responses
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

	// Check each packet's responses for internal contradictions
	for k, responses := range byPacketInterval {
		v.checkPacketContradictions(k.packetID, responses)
		v.checkHashCommitment(k.packetID, responses)
	}

	// Check aggregate contradictions (packet counts vs individual claims)
	v.checkAggregateContradictions()

	return v.Contradictions
}

// checkHashCommitment verifies that claimed path matches the hash commitment
func (v *Verifier) checkHashCommitment(packetID int, responses []Response) {
	commitment, exists := v.PathCommitments[packetID]
	if !exists {
		return // No commitment for this packet
	}

	// Find the path claim for this packet
	for _, resp := range responses {
		if resp.Query.Type == QueryPathUsed && resp.StringAnswer != "UNKNOWN" {
			claimedPath := resp.StringAnswer
			claimedHash := HashPath(claimedPath)

			if claimedHash != commitment.PathHash {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "HASH_MISMATCH",
					Description: fmt.Sprintf("Packet %d: claimed path '%s' (hash=%s) doesn't match commitment hash=%s", packetID, claimedPath, claimedHash, commitment.PathHash),
					Query1:      resp.Query,
					Response1:   resp,
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

		// Find which path is the shortest (this is public knowledge)
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

		// Also check the reverse: claims NOT shortest path but claims shortest path name
		if !claimedShortest && claimedPath == shortestPathName && claimedPath != "UNKNOWN" {
			v.Contradictions = append(v.Contradictions, Contradiction{
				Type:        "PATH_MISMATCH",
				Description: fmt.Sprintf("Packet %d: claimed NOT shortest path but path '%s' IS the shortest", packetID, claimedPath),
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

		// Find the path info (publicly known)
		var pathInfo *PathInfo
		for i := range v.Paths {
			if v.Paths[i].Name == claimedPath {
				pathInfo = &v.Paths[i]
				break
			}
		}

		if pathInfo != nil {
			// Delay should be at least base delay of the claimed path
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

			// Delay shouldn't be impossibly high for the claimed path
			maxExpectedDelay := pathInfo.BaseDelay + v.MaxJitter + 3.0 // generous spike allowance
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

	// Check: If claims shortest path, delay should be consistent with shortest path's constraints
	if shortestPathResp != nil && delayResp != nil {
		if shortestPathResp.BoolAnswer {
			claimedDelay := delayResp.FloatAnswer

			// Find shortest path info (publicly known)
			var shortestPathInfo *PathInfo
			for i := range v.Paths {
				if v.Paths[i].IsShortest {
					shortestPathInfo = &v.Paths[i]
					break
				}
			}

			if shortestPathInfo != nil {
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
			})
		}
	}
}

func (v *Verifier) checkAggregateContradictions() {
	// Check that aggregate counts match individual claims
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

	// Check for contradictions (internal only - no ground truth!)
	contradictions := v.CheckContradictions()

	return VerificationResult{
		TotalQueries:        totalQueries,
		TotalResponses:      len(v.Responses),
		ContradictionsFound: len(contradictions),
		Contradictions:      contradictions,
		Trustworthy:         len(contradictions) == 0,
		OracleStats:         v.Oracle.GetStats(),
	}
}

// GetDebugReport generates a report comparing network claims to ground truth
// This is for debugging/analysis only - NOT part of the verification!
func (v *Verifier) GetDebugReport() string {
	report := "\n=== DEBUG: Ground Truth Analysis ===\n"
	report += "(This information is NOT available to the verifier in production)\n\n"

	liesDetected := 0
	liesUndetected := 0

	for _, truth := range v.DebugGroundTruth {
		// Find responses for this packet
		for _, resp := range v.Responses {
			if resp.Query.PacketID != truth.PacketID {
				continue
			}
			if !resp.Query.Interval.Contains(truth.SentTime) {
				continue
			}

			switch resp.Query.Type {
			case QueryShortestPath:
				if resp.BoolAnswer != truth.IsShortestPath {
					// This was a lie - was it detected?
					detected := false
					for _, c := range v.Contradictions {
						if c.Query1.PacketID == truth.PacketID {
							detected = true
							break
						}
					}
					if detected {
						liesDetected++
					} else {
						liesUndetected++
						report += fmt.Sprintf("UNDETECTED LIE: Packet %d - claimed shortest=%v, actual=%v\n",
							truth.PacketID, resp.BoolAnswer, truth.IsShortestPath)
					}
				}
			case QueryPathUsed:
				if resp.StringAnswer != "UNKNOWN" && resp.StringAnswer != truth.PathUsed {
					detected := false
					for _, c := range v.Contradictions {
						if c.Query1.PacketID == truth.PacketID {
							detected = true
							break
						}
					}
					if detected {
						liesDetected++
					} else {
						liesUndetected++
						report += fmt.Sprintf("UNDETECTED LIE: Packet %d - claimed path=%s, actual=%s\n",
							truth.PacketID, resp.StringAnswer, truth.PathUsed)
					}
				}
			}
		}
	}

	report += fmt.Sprintf("\nSummary: %d lies detected through contradictions, %d lies went undetected\n",
		liesDetected, liesUndetected)

	return report
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
		status = "UNTRUSTWORTHY - CONTRADICTIONS DETECTED"
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
