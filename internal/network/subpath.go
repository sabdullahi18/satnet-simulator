package network

import (
	"crypto/sha256"
	"fmt"
)

type Satellite struct {
	ID       string
	Name     string
	Altitude float64
	Position string
}

type SubPath struct {
	ID        string
	FromNode  string
	ToNode    string
	LinkDelay float64
	Jitter    float64
	DropRate  float64
}

func (sp SubPath) ComputeHash() string {
	data := fmt.Sprintf("%s:%s->%s:%.6f", sp.ID, sp.FromNode, sp.ToNode, sp.LinkDelay)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:8])
}

type PathWithSubPaths struct {
	Name       string
	SubPaths   []SubPath
	TotalDelay float64
	IsShortest bool
}

func (p PathWithSubPaths) ComputeSubPathHashes() []string {
	hashes := make([]string, len(p.SubPaths))
	for i, sp := range p.SubPaths {
		hashes[i] = sp.ComputeHash()
	}
	return hashes
}

func (p PathWithSubPaths) ComputeMerkleRoot() string {
	if len(p.SubPaths) == 0 {
		return ""
	}

	hashes := p.ComputeSubPathHashes()
	for len(hashes) > 1 {
		var newLevel []string
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := hashes[i] + hashes[i+1]
				h := sha256.Sum256([]byte(combined))
				newLevel = append(newLevel, fmt.Sprintf("%x", h[:8]))
			} else {
				newLevel = append(newLevel, hashes[i])
			}
		}
		hashes = newLevel
	}
	return hashes[0]
}

type MerkleProof struct {
	SubPathIndex int
	SubPathHash  string
	Siblings     []string
	Positions    []int
}

func (p PathWithSubPaths) GenerateMerkleProof(subPathIndex int) *MerkleProof {
	if subPathIndex < 0 || subPathIndex >= len(p.SubPaths) {
		return nil
	}

	hashes := p.ComputeSubPathHashes()
	proof := &MerkleProof{
		SubPathIndex: subPathIndex,
		SubPathHash:  hashes[subPathIndex],
		Siblings:     make([]string, 0),
		Positions:    make([]int, 0),
	}

	index := subPathIndex
	for len(hashes) > 1 {
		var siblingIndex int
		var position int
		if index%2 == 0 {
			siblingIndex = index + 1
			position = 1
		} else {
			siblingIndex = index - 1
			position = 0
		}

		if siblingIndex < len(hashes) {
			proof.Siblings = append(proof.Siblings, hashes[siblingIndex])
			proof.Positions = append(proof.Positions, position)
		}

		var newLevel []string
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := hashes[i] + hashes[i+1]
				h := sha256.Sum256([]byte(combined))
				newLevel = append(newLevel, fmt.Sprintf("%x", h[:8]))
			} else {
				newLevel = append(newLevel, hashes[i])
			}
		}
		hashes = newLevel
		index = index / 2
	}
	return proof
}

func VerifyMerkleProof(proof *MerkleProof, expectedRoot string) bool {
	if proof == nil {
		return false
	}

	current := proof.SubPathHash
	for i, sibling := range proof.Siblings {
		var combined string
		if proof.Positions[i] == 0 {
			combined = sibling + current
		} else {
			combined = current + sibling
		}
		h := sha256.Sum256([]byte(combined))
		current = fmt.Sprintf("%x", h[:8])
	}
	return current == expectedRoot
}

type SubPathCommitment struct {
	PacketID     int
	SubPathIndex int
	SubPathHash  string
	MerkleRoot   string
	Proof        *MerkleProof
	EntryTime    float64
	ExitTime     float64
}

type PathTopology struct {
	Satellites map[string]Satellite
	Paths      map[string]*PathWithSubPaths
}

func NewPathTopology() *PathTopology {
	return &PathTopology{
		Satellites: make(map[string]Satellite),
		Paths:      make(map[string]*PathWithSubPaths),
	}
}

func (pt *PathTopology) AddSatellite(sat Satellite) {
	pt.Satellites[sat.ID] = sat
}

func (pt *PathTopology) CreatePath(name string, nodeIDs []string, hopDelays []float64, IsShortest bool) *PathWithSubPaths {
	if len(nodeIDs) < 2 || len(hopDelays) != len(nodeIDs)-1 {
		return nil
	}

	path := &PathWithSubPaths{
		Name:       name,
		SubPaths:   make([]SubPath, len(hopDelays)),
		IsShortest: IsShortest,
	}

	var totalDelay float64
	for i := range len(hopDelays) {
		path.SubPaths[i] = SubPath{
			ID:        fmt.Sprintf("%s_hop_%d", name, i),
			FromNode:  nodeIDs[i],
			ToNode:    nodeIDs[i+1],
			LinkDelay: hopDelays[i],
			Jitter:    0.02,
			DropRate:  0.001,
		}
		totalDelay += hopDelays[i]
	}
	path.TotalDelay = totalDelay
	pt.Paths[name] = path
	return path
}

func (pt *PathTopology) CreateDetailedLEOPath(name string) *PathWithSubPaths {
	pt.AddSatellite(Satellite{ID: "ground_a", Name: "Ground Station A", Altitude: 0})
	pt.AddSatellite(Satellite{ID: "leo_1", Name: "LEO 1", Altitude: 550})
	pt.AddSatellite(Satellite{ID: "leo_2", Name: "LEO 2", Altitude: 550})
	pt.AddSatellite(Satellite{ID: "leo_3", Name: "LEO 3", Altitude: 550})
	pt.AddSatellite(Satellite{ID: "ground_b", Name: "Ground Station B", Altitude: 0})

	nodeIDs := []string{"ground_a", "leo_1", "leo_2", "leo_3", "ground_b"}
	hopDelays := []float64{0.004, 0.01, 0.01, 0.004}
	return pt.CreatePath(name, nodeIDs, hopDelays, true)
}

func (pt *PathTopology) CreateDetailedGEOPath(name string) *PathWithSubPaths {
	pt.AddSatellite(Satellite{ID: "ground_a", Name: "Ground Station A", Altitude: 0})
	pt.AddSatellite(Satellite{ID: "geo_1", Name: "GEO 1", Altitude: 35786})
	pt.AddSatellite(Satellite{ID: "ground_b", Name: "Ground Station B", Altitude: 0})

	nodeIDs := []string{"ground_a", "geo_1", "ground_b"}
	hopDelays := []float64{0.12, 0.12}
	return pt.CreatePath(name, nodeIDs, hopDelays, false)
}

func (pt *PathTopology) GetPath(name string) *PathWithSubPaths {
	return pt.Paths[name]
}

type SubPathTraversalRecord struct {
	PacketID     int
	SubPathID    string
	SubPathIndex int
	EntryTime    float64
	ExitTime     float64
	ActualDelay  float64
	Dropped      bool
}

type PathTraversalRecord struct {
	PacketID       int
	PathName       string
	MerkleRoot     string
	SubPathRecords []SubPathTraversalRecord
	TotalDelay     float64
	StartTime      float64
	EndTiem        float64
}
