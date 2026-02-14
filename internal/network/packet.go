package network

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

type Packet struct {
	ID           int
	Src          string
	Dest         string
	CreationTime float64
	SequenceNum  int
	ReceivedTime float64
	ObservedPath string
	// Hidden ground truth (for simulation only)
	ActualPath     []string
	MinDelay       float64
	ActualDelay    float64
	MaliciousDelay float64
	IsDelayed      bool
}

func (p *Packet) ObservedDelay() float64 {
	return p.ReceivedTime - p.CreationTime
}

func (p *Packet) ComputePathHash() string {
	if len(p.ActualPath) == 0 {
		return ""
	}

	hasher := sha256.New()

	for _, node := range p.ActualPath {
		hasher.Write([]byte(node))
		hasher.Write([]byte("|"))
	}

	sum := hasher.Sum(nil)
	return fmt.Sprintf("%x", sum[:8])
}

func NewPacket(id int, src string, time float64) Packet {
	return Packet{
		ID:           id,
		Src:          src,
		CreationTime: time,
		SequenceNum:  id,
	}
}

// ShouldSample determines if this packet should be sampled using hash-based selection
// The key insight: SNP cannot know which packets will be sampled until after transmission
func (p *Packet) ShouldSample(secretKey string, sampleRate float64) bool {
	data := fmt.Sprintf("%d|%f|%s", p.ID, p.CreationTime, secretKey)
	h := sha256.Sum256([]byte(data))

	val := binary.BigEndian.Uint32(h[:4])
	normalised := float64(val) / float64(^uint32(0))
	return normalised < sampleRate
}

type PacketBatch struct {
	Packets   []*Packet
	StartTime float64
	EndTime   float64
}

func NewPacketBatch() *PacketBatch {
	return &PacketBatch{
		Packets: make([]*Packet, 0),
	}
}

func (b *PacketBatch) Add(p *Packet) {
	b.Packets = append(b.Packets, p)
	if b.StartTime == 0 || p.CreationTime < b.StartTime {
		b.StartTime = p.CreationTime
	}
	if p.CreationTime > b.EndTime {
		b.EndTime = p.CreationTime
	}
}

func (b *PacketBatch) Sample(secretKey string, rate float64) []*Packet {
	sampled := make([]*Packet, 0)
	for _, p := range b.Packets {
		if p.ShouldSample(secretKey, rate) {
			sampled = append(sampled, p)
		}
	}
	return sampled
}

func (b *PacketBatch) FilterByTimeInterval(start, end float64) []*Packet {
	filtered := make([]*Packet, 0)
	for _, p := range b.Packets {
		if p.CreationTime >= start && p.CreationTime <= end {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
