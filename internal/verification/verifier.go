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
	result := fmt.Sprintf("CONTRADICTION [%s]: %s", c.Type, c.Description)
	result += fmt.Sprintf("\n Current answer: %s -> %s", c.Query1, c.Response1)

	if c.Query2.ID != 0 || c.Response2.QueryID != 0 {
		result += fmt.Sprintf("\n Contradicts with: %s -> %s", c.Query2, c.Response2)
	}

	if c.GroundTruth != nil {
		result += fmt.Sprintf("\n [DEBUG - ground truth]: %s", c.GroundTruth)
	}
	return result
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
	ResponseHistory  map[int][]Response
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
		ResponseHistory:  make(map[int][]Response),
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

	if q.PacketID >= 0 {
		v.ResponseHistory[q.PacketID] = append(v.ResponseHistory[q.PacketID], resp)
	}

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
		truth := v.FindGroundTruth(k.packetID, k.interval)
		v.checkPacketContradictions(k.packetID, responses, truth)
		v.checkHashCommitment(k.packetID, responses, truth)
		v.checkCrossIntervalContradictions(k.packetID, k.interval, responses, truth)
	}

	v.checkAggregateContradictions()
	return v.Contradictions
}

func (v *Verifier) checkHashCommitment(packetID int, responses []Response, truth *TransmissionRecord) {
	if truth == nil {
		return
	}

	commitment, exists := v.PathCommitments[packetID]
	if !exists {
		return
	}

	for _, resp := range responses {
		if resp.Query.Type == QueryPathUsed && resp.StringAnswer != "UNKNOWN" {
			claimedPath := resp.StringAnswer
			claimedHash := HashPath(claimedPath)

			if claimedHash != commitment.PathHash {
				commitmentQuery := Query{
					ID:       -1,
					Type:     QueryPathUsed,
					PacketID: packetID,
				}

				commitmentResp := Response{
					QueryID:      -1,
					Query:        commitmentQuery,
					StringAnswer: fmt.Sprintf("committed_hash=%s (actual: %s)", commitment.PathHash, truth.PathUsed),
				}

				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "HASH_MISMATCH",
					Description: fmt.Sprintf("Packet %d: network claimed path '%s' but committed to different path at routing time", packetID, claimedPath),
					Query1:      resp.Query,
					Response1:   resp,
					Query2:      commitmentQuery,
					Response2:   commitmentResp,
					GroundTruth: truth,
				})
			}
		}
	}
}

func (v *Verifier) checkCrossIntervalContradictions(packetID int, interval TimeInterval, responses []Response, truth *TransmissionRecord) {
	if truth == nil {
		return
	}

	allResponses := v.ResponseHistory[packetID]
	if len(allResponses) == 0 {
		return
	}

	var currentPath, currentShortest, currentDelay *Response
	for i := range responses {
		resp := &responses[i]
		switch resp.Query.Type {
		case QueryPathUsed:
			currentPath = resp
		case QueryShortestPath:
			currentShortest = resp
		case QueryDelay:
			currentDelay = resp
		}
	}

	for _, prevResp := range allResponses {
		if prevResp.Query.Interval == interval {
			continue
		}

		prevTruth := v.FindGroundTruth(packetID, prevResp.Query.Interval)
		if prevTruth == nil {
			continue
		}

		if currentPath != nil && prevResp.Query.Type == QueryPathUsed {
			if currentPath.StringAnswer != "UNKNOWN" && prevResp.StringAnswer != "UNKNOWN" {
				if currentPath.StringAnswer != prevResp.StringAnswer {
					v.Contradictions = append(v.Contradictions, Contradiction{
						Type:        "CROSS_INTERVAL_PATH_MISMATCH",
						Description: fmt.Sprintf("Packet %d: network gives different paths in different queries", packetID),
						Query1:      currentPath.Query,
						Response1:   *currentPath,
						Query2:      prevResp.Query,
						Response2:   prevResp,
						GroundTruth: truth,
					})
				}
			}
		}

		if currentShortest != nil && prevResp.Query.Type == QueryShortestPath {
			if currentShortest.BoolAnswer != prevResp.BoolAnswer {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "CROSS_INTERVAL_SHORTEST_MISMATCH",
					Description: fmt.Sprintf("Packet %d: network gives different shortest_path answers", packetID),
					Query1:      currentShortest.Query,
					Response1:   *currentShortest,
					Query2:      prevResp.Query,
					Response2:   prevResp,
					GroundTruth: truth,
				})
			}
		}

		if currentDelay != nil && prevResp.Query.Type == QueryDelay {
			if currentDelay.FloatAnswer >= 0 && prevResp.FloatAnswer >= 0 {
				delayDiff := math.Abs(currentDelay.FloatAnswer - prevResp.FloatAnswer)
				if delayDiff >= 0.01 {
					v.Contradictions = append(v.Contradictions, Contradiction{
						Type:        "CROSS_INTERVAL_DELAY_MISMATCH",
						Description: fmt.Sprintf("Packet %d: network reports significantly different delays (%.4fs vs %.4fs)", packetID, currentDelay.FloatAnswer, prevResp.FloatAnswer),
						Query1:      currentDelay.Query,
						Response1:   *currentDelay,
						Query2:      prevResp.Query,
						Response2:   prevResp,
						GroundTruth: truth,
					})
				}
			}
		}
	}
}

func (v *Verifier) checkPacketContradictions(packetID int, responses []Response, truth *TransmissionRecord) {
	if truth == nil {
		return
	}

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
				GroundTruth: truth,
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
				GroundTruth: truth,
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
					Description: fmt.Sprintf("Packet %d: claimed delay %.4fs but path '%s' has base delay %.4fs", packetID, claimedDelay, claimedPath, pathInfo.BaseDelay),
					Query1:      delayResp.Query,
					Response1:   *delayResp,
					Query2:      pathUsedResp.Query,
					Response2:   *pathUsedResp,
					GroundTruth: truth,
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
					GroundTruth: truth,
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
						GroundTruth: truth,
					})
				} else if claimedDelay > maxExpected {
					v.Contradictions = append(v.Contradictions, Contradiction{
						Type:        "SHORTEST_PATH_DELAY_INCONSISTENT",
						Description: fmt.Sprintf("Packet %d: claims shortest path but delay %.4fs > max expected %.4fs", packetID, claimedDelay, maxExpected),
						Query1:      shortestPathResp.Query,
						Response1:   *shortestPathResp,
						Query2:      delayResp.Query,
						Response2:   *delayResp,
						GroundTruth: truth,
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
				GroundTruth: truth,
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
