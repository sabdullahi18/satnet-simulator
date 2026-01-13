package verification

import (
	"crypto/sha256"
	"fmt"
	"math"
)

type Contradiction struct {
	Type        string
	Description string
	Query1      Query
	Response1   Response
	Query2      Query
	Response2   Response
	GroundTruth *TransmissionRecord
}

func (c Contradiction) String() string {
	if c.Query2.ID == 0 && c.Response2.QueryID == 0 {
		return fmt.Sprintf("CONTRADICTION [%s]: %s\n  Query: %s -> %s", c.Type, c.Description, c.Query1, c.Response1)
	}
	return fmt.Sprintf("CONTRADICTION [%s]: %s\n  Query1: %s -> %s\n  Query2: %s -> %s",
		c.Type, c.Description, c.Query1, c.Response1, c.Query2, c.Response2)
}

type PathCommitment struct {
	PacketID  int
	PathHash  string
	Timestamp float64
}

type Verifier struct {
	Oracle           *NetworkOracle
	Responses        []Response
	Contradictions   []Contradiction
	Paths            []PathInfo
	nextQueryID      int
	PathCommitments  map[int]PathCommitment
	GroundTruth      []TransmissionRecord
	MinPossibleDelay float64
	MaxJitter        float64
}

type PathInfo struct {
	Name       string
	BaseDelay  float64
	IsShortest bool
}

func NewVerifier(oracle *NetworkOracle, paths []PathInfo, minDelay, maxJitter float64) *Verifier {
	return &Verifier{
		Oracle:           oracle,
		Responses:        make([]Response, 0),
		Contradictions:   make([]Contradiction, 0),
		Paths:            paths,
		PathCommitments:  make(map[int]PathCommitment),
		GroundTruth:      make([]TransmissionRecord, 0),
		nextQueryID:      1,
		MinPossibleDelay: minDelay,
		MaxJitter:        maxJitter,
	}
}

func (v *Verifier) RecordPathCommitment(packetID int, pathHash string, timestamp float64) {
	v.PathCommitments[packetID] = PathCommitment{
		PacketID:  packetID,
		PathHash:  pathHash,
		Timestamp: timestamp,
	}
}

func HashPath(pathName string) string {
	h := sha256.Sum256([]byte(pathName))
	return fmt.Sprintf("%x", h[:8])
}

func (v *Verifier) RecordGroundTruth(record TransmissionRecord) {
	v.GroundTruth = append(v.GroundTruth, record)
}

func (v *Verifier) FindGroundTruth(packetID int, interval TimeInterval) *TransmissionRecord {
	for i := range v.GroundTruth {
		rec := &v.GroundTruth[i]
		if rec.PacketID == packetID && interval.Contains(rec.SentTime) {
			return rec
		}
	}
	return nil
}

func (v *Verifier) AskQuestion(q Query, simTime float64) Response {
	q.ID = v.nextQueryID
	v.nextQueryID++

	resp := v.Oracle.Answer(q, simTime)
	v.Responses = append(v.Responses, resp)

	return resp
}

func (v *Verifier) InterrogatePacket(packetID int, interval TimeInterval, simTime float64) []Response {
	responses := make([]Response, 0, 3)

	q1 := Query{
		Type:     QueryShortestPath,
		Interval: interval,
		PacketID: packetID,
	}
	responses = append(responses, v.AskQuestion(q1, simTime))

	q2 := Query{
		Type:     QueryDelay,
		Interval: interval,
		PacketID: packetID,
	}
	responses = append(responses, v.AskQuestion(q2, simTime))

	q3 := Query{
		Type:     QueryPathUsed,
		Interval: interval,
		PacketID: packetID,
	}
	responses = append(responses, v.AskQuestion(q3, simTime))

	return responses
}

func (v *Verifier) CheckContradictions() []Contradiction {
	v.Contradictions = make([]Contradiction, 0)

	type key struct {
		packetID int
		interval TimeInterval
	}

	byPacket := make(map[key][]Response)
	for _, resp := range v.Responses {
		k := key{resp.Query.PacketID, resp.Query.Interval}
		byPacket[k] = append(byPacket[k], resp)
	}

	for k, responses := range byPacket {
		v.checkPacketContradictions(k.packetID, responses)
		v.checkAgainstGroundTruth(k.packetID, k.interval, responses)
	}

	v.checkAggregateContradictions()
	return v.Contradictions
}

func (v *Verifier) checkHashCommitment(packetID int, responses []Response) {
	commitment, exists := v.PathCommitments[packetID]
	if !exists {
		return
	}

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

func (v *Verifier) checkAgainstGroundTruth(packetID int, interval TimeInterval, responses []Response) {
	truth := v.FindGroundTruth(packetID, interval)
	if truth == nil {
		return
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
					GroundTruth: truth,
				})
			}

		case QueryPathUsed:
			if resp.StringAnswer != "UNKNOWN" && resp.StringAnswer != truth.PathUsed {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "GROUND_TRUTH_PATH_USED",
					Description: fmt.Sprintf("Packet %d: network claims path='%s' but actual='%s'", packetID, resp.StringAnswer, truth.PathUsed),
					Query1:      resp.Query,
					Response1:   resp,
					GroundTruth: truth,
				})
			}

		case QueryDelay:
			delayDiff := math.Abs(resp.FloatAnswer - truth.ActualDelay)
			tolerance := 0.01
			if resp.FloatAnswer >= 0 && delayDiff > tolerance {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "GROUND_TRUTH_DELAY",
					Description: fmt.Sprintf("Packet %d: network claims delay=%.4fs but actual=%.4fs (diff=%.4fs)", packetID, resp.FloatAnswer, truth.ActualDelay, delayDiff),
					Query1:      resp.Query,
					Response1:   resp,
					GroundTruth: truth,
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

	if shortestPathResp != nil && pathUsedResp != nil {
		claimedShortest := shortestPathResp.BoolAnswer
		claimedPath := pathUsedResp.StringAnswer

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

	if delayResp != nil && pathUsedResp != nil {
		claimedDelay := delayResp.FloatAnswer
		claimedPath := pathUsedResp.StringAnswer

		var pathInfo *PathInfo
		for i := range v.Paths {
			if v.Paths[i].Name == claimedPath {
				pathInfo = &v.Paths[i]
				break
			}
		}

		if pathInfo != nil {
			if claimedDelay < pathInfo.BaseDelay-0.001 {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "DELAY_TOO_LOW",
					Description: fmt.Sprintf("Packet %d: claimed delay %.4fs is less than path '%s' base delay %.4fs", packetID, claimedDelay, claimedPath, pathInfo.BaseDelay),
					Query1:      delayResp.Query,
					Response1:   *delayResp,
					Query2:      pathUsedResp.Query,
					Response2:   *pathUsedResp,
				})
			}

			maxExpectedDelay := pathInfo.BaseDelay + v.MaxJitter + 3.0
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

	if shortestPathResp != nil && delayResp != nil {
		if shortestPathResp.BoolAnswer {
			claimedDelay := delayResp.FloatAnswer

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

	if delayResp != nil {
		if delayResp.FloatAnswer < v.MinPossibleDelay && delayResp.FloatAnswer >= 0 {
			v.Contradictions = append(v.Contradictions, Contradiction{
				Type:        "PHYSICAL_VIOLATION",
				Description: fmt.Sprintf("Packet %d: claimed delay %.4fs violates minimum possible delay %.4fs (speed of light)", packetID, delayResp.FloatAnswer, v.MinPossibleDelay),
				Query1:      delayResp.Query,
				Response1:   *delayResp,
				Query2:      Query{},
				Response2:   Response{},
			})
		}
	}
}

func (v *Verifier) checkAggregateContradictions() {
	for _, countResp := range v.Responses {
		if countResp.Query.Type == QueryPacketCount {
			continue
		}
		pathName := countResp.Query.PathName
		interval := countResp.Query.Interval
		claimedCount := int(countResp.FloatAnswer)
		individualClaims := 0

		for _, pathResp := range v.Responses {
			if pathResp.Query.Type == QueryPathUsed && pathResp.StringAnswer == pathName && pathResp.Query.Interval == interval {
				individualClaims++
			}
		}

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

func (v *Verifier) RunVerification(intervals []TimeInterval, packetsPerInterval int, simTime float64) VerificationResult {
	totalQueries := 0

	for _, interval := range intervals {
		for pid := range packetsPerInterval {
			v.InterrogatePacket(pid, interval, simTime)
			totalQueries += 3
		}

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

func (v *Verifier) GetDebugReport() string {
	report := "\n=== DEBUG: Ground Truth Analysis ===\n"
	report += "(This information is NOT available to the verifier in production)\n\n"

	liesDetected := 0
	liesUndetected := 0

	for _, truth := range v.GroundTruth {
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
