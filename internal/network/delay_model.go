package network

import (
	"math"
	"math/rand"
	"sort"
)

type DelayModel struct {
	BaseDelayMin   float64
	BaseDelayMax   float64
	TransitionRate float64
	LegitMu        float64
	LegitSigma     float64
	MaliciousMin   float64
	MaliciousMax   float64
	transitions    []PathTransition
	initialised    bool
}

type PathTransition struct {
	Time      float64
	BaseDelay float64
}

type DelayComponents struct {
	BaseDelay      float64
	LegitDelay     float64
	MaliciousDelay float64
	TotalDelay     float64
	MinPossible    float64
}

func DefaultDelayModel() *DelayModel {
	return &DelayModel{
		BaseDelayMin:   0.020,
		BaseDelayMax:   0.080,
		TransitionRate: 0.05,
		// LogNormal parameters for legit delay (occasional spikes)
		// mu=-4.6, sigma=0.8 gives median ~10ms, mean ~14ms, 99th %ile ~64ms
		LegitMu:      -4.6,
		LegitSigma:   0.8,
		MaliciousMin: 0.100, // 100ms
		MaliciousMax: 0.200, // 200ms
		transitions:  make([]PathTransition, 0),
		initialised:  false,
	}
}

func NewDelayModelConfig(cfg DelayModelConfig) *DelayModel {
	return &DelayModel{
		BaseDelayMin:   cfg.BaseDelayMin,
		BaseDelayMax:   cfg.BaseDelayMax,
		TransitionRate: cfg.TransitionRate,
		LegitMu:        cfg.LegitMu,
		LegitSigma:     cfg.LegitSigma,
		MaliciousMin:   cfg.MaliciousMin,
		MaliciousMax:   cfg.MaliciousMax,
		transitions:    make([]PathTransition, 0),
		initialised:    false,
	}
}

type DelayModelConfig struct {
	BaseDelayMin   float64
	BaseDelayMax   float64
	TransitionRate float64
	LegitMu        float64
	LegitSigma     float64
	MaliciousMin   float64
	MaliciousMax   float64
}

func (dm *DelayModel) Initialise(duration float64) {
	dm.transitions = make([]PathTransition, 0)

	// Piecewise constant function for base delay
	// Initial segment
	currentTime := 0.0
	dm.transitions = append(dm.transitions, PathTransition{
		Time:      0,
		BaseDelay: dm.sampleBaseDelay(),
	})

	// Generate transitions using Poisson process
	for currentTime < duration {
		// Inter-arrival time for Poisson process is Exponential(lambda)
		interArrival := -math.Log(1.0-rand.Float64()) / dm.TransitionRate
		currentTime += interArrival

		if currentTime < duration {
			dm.transitions = append(dm.transitions, PathTransition{
				Time:      currentTime,
				BaseDelay: dm.sampleBaseDelay(),
			})
		}
	}

	dm.initialised = true
}

func (dm *DelayModel) sampleBaseDelay() float64 {
	return dm.BaseDelayMin + rand.Float64()*(dm.BaseDelayMax-dm.BaseDelayMin)
}

func (dm *DelayModel) GetBaseDelay(t float64) float64 {
	if !dm.initialised || len(dm.transitions) == 0 {
		return dm.sampleBaseDelay()
	}

	// Find the segment that contains t
	idx := sort.Search(len(dm.transitions), func(i int) bool {
		return dm.transitions[i].Time > t
	})

	// transitions[idx] is the first one AFTER t (or len if none)
	// So the active one is idx-1
	if idx == 0 {
		return dm.transitions[0].BaseDelay
	}
	return dm.transitions[idx-1].BaseDelay
}

func (dm *DelayModel) GetLegitDelay() float64 {
	// LogNormal distribution
	z := rand.NormFloat64()
	return math.Exp(dm.LegitMu + dm.LegitSigma*z)
}

func (dm *DelayModel) GetMaliciousDelay() float64 {
	// Uniform distribution for malicious delay
	return dm.MaliciousMin + rand.Float64()*(dm.MaliciousMax-dm.MaliciousMin)
}

func (dm *DelayModel) ComputeTotalDelay(sendTime float64, isMalicious bool) DelayComponents {
	baseDelay := dm.GetBaseDelay(sendTime)
	legitDelay := dm.GetLegitDelay()

	maliciousDelay := 0.0
	if isMalicious {
		maliciousDelay = dm.GetMaliciousDelay()
	}

	return DelayComponents{
		BaseDelay:      baseDelay,
		LegitDelay:     legitDelay,
		MaliciousDelay: maliciousDelay,
		TotalDelay:     baseDelay + legitDelay + maliciousDelay,
		MinPossible:    baseDelay,
	}
}

func (dm *DelayModel) GetTransitionCount() int {
	return len(dm.transitions)
}

func (dm *DelayModel) GetTransitions() []PathTransition {
	result := make([]PathTransition, len(dm.transitions))
	copy(result, dm.transitions)
	return result
}

func (dm *DelayModel) Reset() {
	dm.transitions = make([]PathTransition, 0)
	dm.initialised = false
}

func (dm *DelayModel) IsInitialised() bool {
	return dm.initialised
}
