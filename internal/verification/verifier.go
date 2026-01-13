package verification

import (
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
}

func (c Contradiction) String() string {
	return fmt.Sprintf("CONTRADICTION [%s]: %s\n  Query1: %s -> %s\n  Query2: %s -> %s",
		c.Type, c.Description, c.Query1, c.Response1, c.Query2, c.Response2)
}

type Verifier struct {
	Oracle         *NetworkOracle
	Responses      []Response
	Contradictions []Contradiction
	Paths          []PathInfo
	nextQueryID    int

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
		nextQueryID:      1,
		MinPossibleDelay: minDelay,
		MaxJitter:        maxJitter,
	}
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

	byPacket := make(map[int][]Response)
	for _, resp := range v.Responses {
		pid := resp.Query.PacketID
		byPacket[pid] = append(byPacket[pid], resp)
	}

	for packetID, responses := range byPacket {
		v.checkPacketContradictions(packetID, responses)
	}

	v.checkAggregateContradictions()

	return v.Contradictions
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
	claimedPathCounts := make(map[string]int)
	for _, resp := range v.Responses {
		if resp.Query.Type == QueryPathUsed && resp.StringAnswer != "UNKNOWN" {
			claimedPathCounts[resp.StringAnswer]++
		}
	}

	for _, resp := range v.Responses {
		if resp.Query.Type == QueryPacketCount {
			pathName := resp.Query.PathName
			claimedCount := int(resp.FloatAnswer)
			actualClaims := claimedPathCounts[pathName]

			if actualClaims > 0 && math.Abs(float64(claimedCount-actualClaims)) > float64(actualClaims)/2 {
				v.Contradictions = append(v.Contradictions, Contradiction{
					Type:        "COUNT_MISMATCH",
					Description: fmt.Sprintf("Path '%s': claimed count %d but individual responses indicate %d", pathName, claimedCount, actualClaims),
					Query1:      resp.Query,
					Response1:   resp,
					Query2:      Query{},
					Response2:   Response{},
				})
			}
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
