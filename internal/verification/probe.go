package verification

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"satnet-simulator/internal/network"
)

type ProbeType int

const (
	ProbeStandard ProbeType = iota
	ProbeForced
	ProbeChallengeResponse
	ProbeSubPathVerification
)

func (pt ProbeType) String() string {
	switch pt {
	case ProbeStandard:
		return "STANDARD"
	case ProbeForced:
		return "FORCED"
	case ProbeChallengeResponse:
		return "CHALLENGE_RESPONSE"
	case ProbeSubPathVerification:
		return "SUBPATH_VERIFICATION"
	default:
		return "UNKNOWN"
	}
}

type ProbePacket struct {
	ID                 int
	Type               ProbeType
	SentTime           float64
	ForcedPath         string
	ForcedSubPaths     []string
	Challenge          []byte
	SecretKey          []byte
	ExpectedProof      []byte
	TargetSubPath      int
	ExpectedMerkleRoot string
	ExpectedMinDelay   float64
	ExpectedMaxDelay   float64
}

func GenerateChallenge() (challenge []byte, secretKey []byte, err error) {
	challenge = make([]byte, 32)
	secretKey = make([]byte, 32)

	if _, err := rand.Read(challenge); err != nil {
		return nil, nil, err
	}
	if _, err = rand.Read(secretKey); err != nil {
		return nil, nil, err
	}
	return challenge, secretKey, nil
}

func ComputeExpectedProof(secretKey, challenge []byte, pathData string) []byte {
	data := append(challenge, []byte(pathData)...)
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(data)
	return mac.Sum(nil)
}

func VerifyProof(networkProof, expectedProof []byte) bool {
	return hmac.Equal(networkProof, expectedProof)
}

type ProbeResult struct {
	Probe             *ProbePacket
	ReceivedTime      float64
	ActualDelay       float64
	ReportedPath      string
	ReportedSubPaths  []string
	ReportedDelay     float64
	NetworkProof      []byte
	ProofValid        bool
	MerkleProofValid  bool
	TimingValid       bool
	PathMatchesForced bool
	Issues            []string
}

func (pr *ProbeResult) AddIssue(issue string) {
	pr.Issues = append(pr.Issues, issue)
}

func (pr *ProbeResult) HasIssues() bool {
	return len(pr.Issues) > 0
}

type ProbeManager struct {
	probes      map[int]*ProbePacket
	results     map[int]*ProbeResult
	nextProbeID int
	topology    *network.PathTopology
}

func NewProbeManager(topology *network.PathTopology) *ProbeManager {
	return &ProbeManager{
		probes:      make(map[int]*ProbePacket),
		results:     make(map[int]*ProbeResult),
		nextProbeID: 10000,
		topology:    topology,
	}
}

func (pm *ProbeManager) CreateStandardProbe(sentTime float64) *ProbePacket {
	probe := &ProbePacket{
		ID:       pm.nextProbeID,
		Type:     ProbeStandard,
		SentTime: sentTime,
	}
	pm.nextProbeID++
	pm.probes[probe.ID] = probe
	return probe
}

func (pm *ProbeManager) CreateForcedProbe(sentTime float64, forcedPath string) *ProbePacket {
	probe := &ProbePacket{
		ID:         pm.nextProbeID,
		Type:       ProbeForced,
		SentTime:   sentTime,
		ForcedPath: forcedPath,
	}
	if pm.topology != nil {
		if path := pm.topology.GetPath(forcedPath); path != nil {
			probe.ExpectedMinDelay = path.TotalDelay
			probe.ExpectedMaxDelay = path.TotalDelay + 3
		}
	}
	pm.nextProbeID++
	pm.probes[probe.ID] = probe
	return probe
}

func (pm *ProbeManager) CreateSubPathProbe(sentTime float64, pathName string, subPathIndex int) *ProbePacket {
	probe := &ProbePacket{
		ID:            pm.nextProbeID,
		Type:          ProbeSubPathVerification,
		SentTime:      sentTime,
		ForcedPath:    pathName,
		TargetSubPath: subPathIndex,
	}
	if pm.topology != nil {
		if path := pm.topology.GetPath(pathName); path != nil {
			probe.ExpectedMerkleRoot = path.ComputeMerkleRoot()
		}
	}
	pm.nextProbeID++
	pm.probes[probe.ID] = probe
	return probe
}

func (pm *ProbeManager) CreateChallengeProbe(sentTime float64, forcedPath string) (*ProbePacket, error) {
	challenge, secretKey, err := GenerateChallenge()
	if err != nil {
		return nil, err
	}

	expectedProof := ComputeExpectedProof(secretKey, challenge, forcedPath)
	probe := &ProbePacket{
		ID:            pm.nextProbeID,
		Type:          ProbeChallengeResponse,
		SentTime:      sentTime,
		ForcedPath:    forcedPath,
		Challenge:     challenge,
		SecretKey:     secretKey,
		ExpectedProof: expectedProof,
	}
	pm.nextProbeID++
	pm.probes[probe.ID] = probe
	return probe, nil
}

func (pm *ProbeManager) GetProbe(probeID int) *ProbePacket {
	return pm.probes[probeID]
}

func (pm *ProbeManager) RecordResult(probeID int, result *ProbeResult) {
	pm.results[probeID] = result
}

func (pm *ProbeManager) GetResult(probeID int) *ProbeResult {
	return pm.results[probeID]
}

func (pm *ProbeManager) GetAllProbes() map[int]*ProbePacket {
	return pm.probes
}

type ProbeContradiction struct {
	Type        string
	ProbeID     int
	Description string
	Probe       *ProbePacket
	Result      *ProbeResult
}

func (pc ProbeContradiction) String() string {
	return fmt.Sprintf("PROBE CONTRADICTION [%s]: %s", pc.Type, pc.Description)
}

func (p *ProbePacket) ChallengeHex() string {
	return hex.EncodeToString(p.Challenge)
}

func (p *ProbePacket) ExpectedProofHex() string {
	return hex.EncodeToString(p.ExpectedProof)
}

func (pm *ProbeManager) AnalyseResults() []ProbeContradiction {
	var contradictions []ProbeContradiction

	for probeID, result := range pm.results {
		probe := pm.probes[probeID]
		if probe == nil {
			continue
		}
		if probe.ExpectedMinDelay > 0 {
			if result.ActualDelay < probe.ExpectedMinDelay {
				contradictions = append(contradictions, ProbeContradiction{
					Type:        "TIMING_IMPOSSIBLY_FAST",
					ProbeID:     probeID,
					Description: fmt.Sprintf("Probe %d: actual delay %.4fs < minimum possible %.4fs for path %s", probeID, result.ActualDelay, probe.ExpectedMinDelay, probe.ForcedPath),
					Probe:       probe,
					Result:      result,
				})
			}
		}
		if probe.Type == ProbeForced && probe.ForcedPath != "" {
			if result.ReportedPath != probe.ForcedPath {
				contradictions = append(contradictions, ProbeContradiction{
					Type:        "FORCED_PATH_VIOLATION",
					ProbeID:     probeID,
					Description: fmt.Sprintf("Probe %d: forced path '%s' but network reported '%s'", probeID, probe.ForcedPath, result.ReportedPath),
					Probe:       probe,
					Result:      result,
				})
			}
		}
		if probe.Type == ProbeChallengeResponse {
			if !result.ProofValid {
				contradictions = append(contradictions, ProbeContradiction{
					Type:        "CHALLENGE_PROOF_INVALID",
					ProbeID:     probeID,
					Description: fmt.Sprintf("Probe %d: network failed to provide valid cryptographic proof", probeID),
					Probe:       probe,
					Result:      result,
				})
			}
		}
		if probe.Type == ProbeSubPathVerification {
			if !result.MerkleProofValid {
				contradictions = append(contradictions, ProbeContradiction{
					Type:        "MERKLE_PROOF_INVALID",
					ProbeID:     probeID,
					Description: fmt.Sprintf("Probe %d: subpath Merkle proof verification failed", probeID),
					Probe:       probe,
					Result:      result,
				})
			}
		}
	}
	return contradictions
}

type SubPathForcingInstruction struct {
	PathName       string
	SubPathIndices []int
	SubPathHashes  []string
	MerkleRoot     string
}

func CreateSubPathForcing(path *network.PathWithSubPaths, indices []int) *SubPathForcingInstruction {
	if path == nil {
		return nil
	}

	instruction := &SubPathForcingInstruction{
		PathName:       path.Name,
		SubPathIndices: indices,
		SubPathHashes:  make([]string, len(indices)),
		MerkleRoot:     path.ComputeMerkleRoot(),
	}

	hashes := path.ComputeSubPathHashes()
	for i, idx := range indices {
		if idx >= 0 && idx < len(hashes) {
			instruction.SubPathHashes[i] = hashes[idx]
		}
	}

	return instruction
}

type ProbeSchedule struct {
	Probes    []*ProbePacket
	StartTime float64
	EndTime   float64
	Interval  float64
}

func (pm *ProbeManager) CreateProbeSchedule(startTime, endTime, interval float64, pathNames []string) *ProbeSchedule {
	schedule := &ProbeSchedule{
		Probes:    make([]*ProbePacket, 0),
		StartTime: startTime,
		EndTime:   endTime,
		Interval:  interval,
	}

	t := startTime
	pathIndex := 0
	for t < endTime {
		pathName := pathNames[pathIndex%len(pathNames)]
		probe := pm.CreateForcedProbe(t, pathName)
		schedule.Probes = append(schedule.Probes, probe)
		t += interval
		pathIndex++
	}
	return schedule
}

func (pm *ProbeManager) Summary() string {
	total := len(pm.results)
	issues := 0
	for _, result := range pm.results {
		if result.HasIssues() {
			issues++
		}
	}
	return fmt.Sprintf("Probes: %d total, %d with issues (%.1f%%)", total, issues, float64(issues)/float64(total)*100)
}
